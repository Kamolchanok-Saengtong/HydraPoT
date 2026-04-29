"""
Measures:
  - GFLOPs  (via calflops)
  - RAM     (via psutil)
  - VRAM    (via torch.cuda)
  - Latency (via time.perf_counter)
─────────────────────────────────────────────────────────────────
"""

import os
import time
import psutil
import torch

try:
    from calflops import calculate_flops
    CALFLOPS_AVAILABLE = True
except ImportError:
    CALFLOPS_AVAILABLE = False
    print("[metrics] calflops not found — GFLOPs will not be measured")
    print("[metrics] install with: pip install calflops==0.3.2")

# ─── RAM ──────────────────────────────────────────────────────────────────────

def get_ram_mb() -> float:
    """Current process RAM usage in MB."""
    return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024

# ─── VRAM ─────────────────────────────────────────────────────────────────────

def get_vram_mb() -> float | None:
    """Current GPU VRAM usage in MB. Returns None if no GPU available."""
    if torch.cuda.is_available():
        return torch.cuda.memory_allocated() / 1024 / 1024
    return None

# ─── GFLOPs ───────────────────────────────────────────────────────────────────

"""
agent_manager/metrics.py
─────────────────────────────────────────────────────────────────
Shared measurement utilities for on-device LLM evaluation.
Used by:
  - evaluation/eval_ondevice.py  (standalone eval)
  - main.py                      (hybrid system, when ready)

Measures:
  - GFLOPs  (via calflops)
  - RAM     (via psutil)
  - VRAM    (via torch.cuda)
  - Latency (via time.perf_counter)
─────────────────────────────────────────────────────────────────
"""

import os
import time
import psutil
import torch

# ── calflops is optional — gracefully skip if not installed ───────────────────
try:
    from calflops import calculate_flops
    CALFLOPS_AVAILABLE = True
except ImportError:
    CALFLOPS_AVAILABLE = False
    print("[metrics] calflops not found — GFLOPs will not be measured")
    print("[metrics] install with: pip install calflops==0.3.2")

# ─── RAM ──────────────────────────────────────────────────────────────────────

def get_ram_mb() -> float:
    """Current process RAM usage in MB."""
    return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024

# ─── VRAM ─────────────────────────────────────────────────────────────────────

def get_vram_mb() -> float | None:
    """Current GPU VRAM usage in MB. Returns None if no GPU available."""
    if torch.cuda.is_available():
        return torch.cuda.memory_allocated() / 1024 / 1024
    return None

# ─── GFLOPs ───────────────────────────────────────────────────────────────────

def measure_gflops(model, tokenizer, prompt: str) -> float | None:
    """
    Estimate GFLOPs using standard transformer formula.
    Formula: FLOPs = 2 × N × T
      N = non-embedding parameters (excludes embedding layers)
      T = input sequence length (tokens)

    Reference: Kaplan et al. (2020) Scaling Laws for Neural Language Models
    """
    try:
        inputs  = tokenizer(prompt, return_tensors="pt")
        seq_len = inputs["input_ids"].shape[1]

        # exclude embedding layers — they don't contribute to compute FLOPs
        param_count = sum(
            p.numel() for name, p in model.named_parameters()
            if "embed" not in name
        )

        flops = 2 * param_count * seq_len
        return round(flops / 1e9, 4)

    except Exception as e:
        print(f"[metrics] GFLOPs measurement failed: {e}")
        return None

# ─── Full Snapshot ────────────────────────────────────────────────────────────

def snapshot_before() -> dict:
    """Take RAM/VRAM snapshot before LLM call."""
    return {
        "ram_mb":  round(get_ram_mb(), 2),
        "vram_mb": round(get_vram_mb(), 2) if get_vram_mb() is not None else None,
    }

def snapshot_after(before: dict) -> dict:
    """Take RAM/VRAM snapshot after LLM call and compute deltas."""
    ram_after  = round(get_ram_mb(), 2)
    vram_after = round(get_vram_mb(), 2) if get_vram_mb() is not None else None
    return {
        "ram_before_mb":  before["ram_mb"],
        "ram_after_mb":   ram_after,
        "ram_delta_mb":   round(ram_after - before["ram_mb"], 2),
        "vram_before_mb": before["vram_mb"],
        "vram_after_mb":  vram_after,
        "vram_delta_mb":  round(vram_after - before["vram_mb"], 2) if vram_after is not None else None,
    }

# ─── Latency ──────────────────────────────────────────────────────────────────

def measure_latency(fn, *args, **kwargs) -> tuple:
    """
    Wrap any function call and measure its latency.
    Returns (result, latency_ms).

    Usage:
        response, latency_ms = measure_latency(agent.send, prompt)
    """
    start  = time.perf_counter()
    result = fn(*args, **kwargs)
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    return result, latency_ms