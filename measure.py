"""
measure.py — resource + power measurement primitives (RAM, VRAM, CPU, GPU watts).
─────────────────────────────────────────────────────────────────
Measurement utilities for the NSC architecture-overhead evaluation.

Deliberately does NOT use torch / transformers introspection, because the
on-device agent is now llama-cpp (GGUF). The old computation_cost.py broke
on three things, all avoided here:
  - model.named_parameters()      -> llama_cpp.Llama has no such method
  - torch.cuda.memory_allocated() -> blind to ggml's own CUDA allocations
  - tokenizer.encode()            -> llama-cpp exposes .tokenize(), not HF API

What we measure for Part A (architecture / orchestration overhead):
  - wall-clock latency  (time.perf_counter)
  - CPU %               (psutil, sampled across the call window)
  - process RAM         (psutil RSS)
  - GPU VRAM            (nvidia-smi process query; works for llama-cpp)

GFLOPs and token counts are intentionally NOT here — those are inference/cost
properties (Part C), not orchestration overhead (Part A).
─────────────────────────────────────────────────────────────────
"""

import os
import time
import threading
import subprocess

import psutil

_PROC = psutil.Process(os.getpid())


# ─── RAM ──────────────────────────────────────────────────────────────────────

def get_ram_mb() -> float:
    """Resident RAM of this process in MB."""
    return _PROC.memory_info().rss / 1024 / 1024


# ─── VRAM (GGUF-safe, via nvidia-smi) ─────────────────────────────────────────

def get_vram_mb(pid: int | None = None) -> float | None:
    """
    GPU memory used by a process (default: this process) in MB.

    Uses nvidia-smi's per-process accounting, which captures llama-cpp / ggml
    CUDA allocations that torch.cuda.memory_allocated() cannot see.

    Returns None if no GPU / nvidia-smi unavailable. If the model runs in a
    *separate* process (e.g. a llama.cpp server), pass that server's pid.
    """
    target = pid if pid is not None else os.getpid()
    try:
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-compute-apps=pid,used_memory",
             "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode()
    except (FileNotFoundError, subprocess.SubprocessError):
        return None

    total = 0.0
    found = False
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 2:
            continue
        try:
            p_pid = int(parts[0])
            p_mem = float(parts[1])
        except ValueError:
            continue
        if p_pid == target:
            total += p_mem
            found = True
    return total if found else 0.0


def get_vram_total_mb() -> float | None:
    """
    Total VRAM in use on GPU 0 (all processes), MB. Fallback signal when the
    model lives in another process and per-process matching misses it.
    """
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used",
             "--format=csv,noheader,nounits", "-i", "0"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode()
        return float(out.strip().splitlines()[0])
    except (FileNotFoundError, subprocess.SubprocessError, ValueError, IndexError):
        return None


# ─── CPU sampler (background thread across a call window) ──────────────────────

class CPUSampler:
    """
    Samples process CPU% in a background thread while a call runs.

    psutil's cpu_percent() needs an interval to mean anything; a single
    instantaneous reading around a short call is noise. This polls repeatedly
    and reports the mean over the window.

        sampler = CPUSampler().start()
        ... do work ...
        cpu_pct = sampler.stop()    # mean process CPU% over the window
    """

    def __init__(self, interval: float = 0.05):
        self.interval = interval
        self._samples: list[float] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "CPUSampler":
        _PROC.cpu_percent(None)  # prime; first call always returns 0.0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            self._samples.append(_PROC.cpu_percent(None))
            time.sleep(self.interval)

    def stop(self) -> float | None:
        if self._thread is None:
            return None
        self._stop.set()
        self._thread.join()
        vals = [s for s in self._samples if s is not None]
        return round(sum(vals) / len(vals), 2) if vals else None


# ─── GPU power sampler (background thread, same shape as CPUSampler) ────────

def _get_gpu_power_limit_w() -> float | None:
    """Rated max power draw for GPU 0, from nvidia-smi (works even when
    power.draw itself reports N/A — power.limit is a static board spec,
    not a live sensor reading)."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=power.limit", "--format=csv,noheader,nounits", "-i", "0"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode()
        return float(out.strip().splitlines()[0])
    except (FileNotFoundError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def _get_gpu_sample() -> tuple[float | None, float | None]:
    """One (power_draw_w, utilization_pct) reading. power_draw_w is None on
    hardware/drivers that don't expose it (confirmed: this project's RTX 4060
    reports power.draw as literal 'N/A' via nvidia-smi even at 100% load —
    a real board/vBIOS limitation, not a permission or query-syntax issue)."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=power.draw,utilization.gpu",
             "--format=csv,noheader,nounits", "-i", "0"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip()
        parts = [p.strip() for p in out.split(",")]
        power = float(parts[0]) if parts[0] not in ("N/A", "[N/A]") else None
        util = float(parts[1]) if len(parts) > 1 and parts[1] not in ("N/A", "[N/A]") else None
        return power, util
    except (FileNotFoundError, subprocess.SubprocessError, ValueError, IndexError):
        return None, None


class GPUPowerSampler:
    """
    Samples GPU power draw in a background thread while a call runs — same
    polling-thread shape as CPUSampler above.

    Two data sources, tried in this order per sample:
      1. Real power.draw from nvidia-smi, when the hardware/driver actually
         reports it (works out of the box on GPUs that expose this sensor).
      2. Fallback: utilization.gpu (%) * power.limit (W) — a utilization-
         scaled estimate. Needed on hardware like this project's RTX 4060,
         where power.draw is permanently 'N/A' even under 100% load (a real
         board-level limitation, not a bug) — utilization.gpu and power.limit
         both DO report correctly there, so this is the best available proxy.

    stop() returns (avg_watt_draw, estimation_method), where estimation_method
    is "measured" if ANY sample came from real power.draw, else "utilization_scaled".
    None avg_watt_draw if nvidia-smi was unavailable for the whole window.
    """

    def __init__(self, interval: float = 0.2):
        self.interval = interval
        self._samples: list[float] = []
        self._used_real_power = False
        self._power_limit = _get_gpu_power_limit_w()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "GPUPowerSampler":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            power, util = _get_gpu_sample()
            if power is not None:
                self._samples.append(power)
                self._used_real_power = True
            elif util is not None and self._power_limit is not None:
                self._samples.append(util / 100.0 * self._power_limit)
            time.sleep(self.interval)

    def stop(self) -> tuple[float | None, str]:
        if self._thread is None:
            return None, "unavailable"
        self._stop.set()
        self._thread.join()
        if not self._samples:
            return None, "unavailable"
        avg_watt = round(sum(self._samples) / len(self._samples), 2)
        method = "measured" if self._used_real_power else "utilization_scaled"
        return avg_watt, method


# ─── Timed call with full resource snapshot ───────────────────────────────────

def timed_call(fn, *args, **kwargs) -> tuple:
    """
    Run fn, returning (result, metrics_dict).

    metrics_dict = {
        latency_ms, cpu_pct,
        ram_before_mb, ram_after_mb, ram_delta_mb,
        vram_before_mb, vram_after_mb, vram_delta_mb,
    }
    """
    ram_before  = round(get_ram_mb(), 2)
    vram_before = get_vram_mb()
    sampler = CPUSampler().start()

    start  = time.perf_counter()
    result = fn(*args, **kwargs)
    latency_ms = round((time.perf_counter() - start) * 1000, 2)

    cpu_pct    = sampler.stop()
    ram_after  = round(get_ram_mb(), 2)
    vram_after = get_vram_mb()

    metrics = {
        "latency_ms":     latency_ms,
        "cpu_pct":        cpu_pct,
        "ram_before_mb":  ram_before,
        "ram_after_mb":   ram_after,
        "ram_delta_mb":   round(ram_after - ram_before, 2),
        "vram_before_mb": vram_before,
        "vram_after_mb":  vram_after,
        "vram_delta_mb":  (round(vram_after - vram_before, 2)
                           if (vram_before is not None and vram_after is not None)
                           else None),
    }
    return result, metrics


# ─── Percentile / summary helpers ─────────────────────────────────────────────

def percentile(values: list[float], p: float) -> float | None:
    """
    p-th percentile (0..100), linear interpolation. No numpy dependency.
    """
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return round(vals[0], 2)
    k = (len(vals) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(vals) - 1)
    frac = k - lo
    return round(vals[lo] * (1 - frac) + vals[hi] * frac, 2)


def summarize_latency(values: list[float]) -> dict:
    """Standard latency summary for a group of measurements."""
    vals = [v for v in values if v is not None]
    if not vals:
        return {"n": 0}
    return {
        "n":      len(vals),
        "p50":    percentile(vals, 50),
        "p95":    percentile(vals, 95),
        "p99":    percentile(vals, 99),
        "min":    round(min(vals), 2),
        "max":    round(max(vals), 2),
        "mean":   round(sum(vals) / len(vals), 2),  # reported but not headline
    }