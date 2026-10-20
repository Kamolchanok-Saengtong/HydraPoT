"""
experiment_data/PartA/module_overhead.py — FAIR per-module overhead of the on-device path.

Professor's correction: the old baseline was unfair — it compared HydraPoT's
STATEFUL prompt (SRi OS-state injected, ~4700 tok) against a NAIVE short prompt
(~120 tok). That made "prompt size" look like HydraPoT overhead, but ANY decent
on-device honeypot needs state injection — so a fair pure baseline keeps the
SAME prompt + SAME state tracking, and removes ONLY the HydraPoT-specific
machinery (multi-agent sync to Cowrie, routing, etc.).

So here both sides use the SAME big prompt (inference time is identical and
cancels out). The overhead is only the HydraPoT-ONLY modules:

  SHARED (in both fair-pure and HydraPoT):
    • prompt-build (SRi state injection) + state-update + logging
    • inference on the big stateful prompt
  HydraPoT-ONLY (removed for a fair pure baseline):
    • routing (classify)
    • history-sync — multi-agent Cowrie round-trip (save cmd to ~/.bash_history)

    cd /mnt/data-partition/honeypot && source honeypot_new/bin/activate
    python experiment_data/PartA/module_overhead.py                 # default 3 trials
    python experiment_data/PartA/module_overhead.py --trials 5

Loads the on-device model from config.yaml. Uses live Cowrie for history-sync
(skips cleanly if unreachable). Saves results/module_overhead_<timestamp>.txt/.json
─────────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import types
import time
import argparse
import statistics as st
from datetime import datetime

# PartA/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_NSC = os.path.abspath(os.path.join(_HERE, ".."))
for p in (_ROOT, _NSC, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
os.chdir(_ROOT)

import main as hp                                     # noqa: E402
from core.config_loader import load_config                 # noqa: E402
from core import router                               # noqa: E402
from agent_manager.ondevice_agent import OnDeviceAgent  # noqa: E402
from agent_manager.cowrie_agent import CowrieAgent      # noqa: E402
from workloads import load_mrheinen_instruction, load_mrheinen_raw  # noqa: E402

# Route each arm's log to its own Part folder (see _paths.py).
from _paths import session_dir_for



# Smoke-test workload only (--quick). The real run uses the same 481-row
# mrheinen dataset every other Part A number is measured on: these five are all
# long-output commands, so inference on them (~6,000 ms) is more than twice the
# dataset's mean (~2,773 ms). That inflated the denominator and halved the
# reported overhead percentage, since routing+history-sync is a FIXED per-command
# cost — it does not scale with how long the answer is.
QUICK_CMDS = ["cat /etc/passwd", "ls -la /tmp", "uname -a", "ps aux", "cat /proc/cpuinfo"]


# ── stubs to capture the real HydraPoT prompt without running the model ────────
class _CaptureStub:
    def __init__(self): self.last = None
    def send(self, s, u): self.last = (s, u); return ""
    def send_with_usage(self, s, u): self.last = (s, u); return "", None

class _CowStub:
    def __init__(self): self.shell = types.SimpleNamespace(send=lambda *a, **k: None)
    def _connect(self): return None
    def _collect_until_prompt(self, *a, **k): return ("", "")
    def disconnect(self): return None
    def send(self, cmd): return ("", None)


def mean_ms(xs): return st.mean(xs) if xs else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=3, help="repeats per command (default 3)")
    ap.add_argument("--quick", action="store_true",
                    help="5-command smoke test instead of the real 481-row workload")
    args = ap.parse_args()
    cfg = load_config()
    cmds = QUICK_CMDS if args.quick else load_mrheinen_raw()

    print("=" * 68)
    print("  MODULE OVERHEAD PROFILER — on-device path")
    print(f"  model: {cfg.agents.on_device.model}")
    print(f"  commands: {len(cmds)}   trials each: {args.trials}")
    print("=" * 68, flush=True)

    # ── 1) capture the real big HydraPoT prompt + time routing & glue ──────────
    stub = _CaptureStub()
    hp.config = load_config(); hp.ondevice = stub; hp.cloud = None
    # ONE handler for the whole workload, like main.py gives one per attacker
    # session and like Part A's local_hydrapot arm. A fresh handler per command
    # would reset SYSTEM_STATE every time, so the SRi block could never grow and
    # the shared prompt would be smaller than the one HydraPoT actually pays for.
    handle = hp.make_command_handler(_CowStub(), src_ip="p", public_ip="p",
                                     plugins=None, capture_cost=True,
                                     store="json", store_dir=session_dir_for("p", __file__))
    big_prompts, glue_ms = [], []
    for cmd in cmds:
        t = time.perf_counter()
        handle(cmd, lambda s: None, lambda: "", force_agent="on_device")
        glue_ms.append((time.perf_counter() - t) * 1000)
        if stub.last:
            big_prompts.append(stub.last)

    # Averaged over the whole workload, not one command: classify() short-circuits
    # on COWRIE_UNIMPLEMENTED/COWRIE_AUTHORITATIVE before ever scoring FI, so its
    # cost depends on which command it is given.
    _reps = max(1, 3000 // len(cmds))
    t = time.perf_counter()
    for _ in range(_reps):
        for c in cmds:
            router.classify(c, [])
    route_ms = (time.perf_counter() - t) / (_reps * len(cmds)) * 1000

    # ── 2) load the REAL model, time inference on the SHARED big stateful prompt
    # Both the fair-pure baseline AND HydraPoT use this SAME prompt (state
    # injection is kept in both), so inference time is identical and cancels out.
    print("[profile] loading on-device model (once)...", flush=True)
    od = OnDeviceAgent(
        model=cfg.agents.on_device.model, quantization=cfg.agents.on_device.quantization,
        gguf_file=cfg.agents.on_device.gguf_file, temperature=cfg.agents.on_device.temperature,
        max_tokens=cfg.agents.on_device.max_tokens, do_sample=cfg.agents.on_device.do_sample,
    )
    print("[profile] warming up...", flush=True)
    _bs0, _bu0 = big_prompts[0]
    od.send(_bs0, _bu0)

    # Iterate the captured prompts, not cmds: a command the pipeline answers
    # without reaching the model contributes no prompt, so indexing by position
    # in cmds would mispair them (or run off the end).
    inf_ms = []
    for tr in range(args.trials):
        for n, (bs, bu) in enumerate(big_prompts, 1):
            t = time.perf_counter(); od.send(bs, bu); inf_ms.append((time.perf_counter() - t) * 1000)
            if n % 100 == 0:
                print(f"[profile] trial {tr+1}/{args.trials}  {n}/{len(big_prompts)}  "
                      f"inference≈{mean_ms(inf_ms):.0f}ms", flush=True)
        print(f"[profile] trial {tr+1} done — inference≈{mean_ms(inf_ms):.0f}ms", flush=True)

    # ── 3) history-sync (live Cowrie round-trip) ───────────────────────────────
    hist_ms, hist_note = None, ""
    try:
        cw = CowrieAgent(host=cfg.agents.cowrie.host, port=cfg.agents.cowrie.port,
                         username=cfg.agents.cowrie.username, password=cfg.agents.cowrie.password)
        cw._connect(); cw.send("echo warm")
        hs = []
        for _ in range(args.trials):
            for cmd in cmds:
                safe = cmd.replace("'", "'\\''")
                hk = f"HISTFILE=~/.bash_history; history -s '{safe}'; history -w"
                t = time.perf_counter(); cw.shell.send(hk + "\n"); cw._collect_until_prompt(hk)
                hs.append((time.perf_counter() - t) * 1000)
        hist_ms = mean_ms(hs); cw.client.close()
    except Exception as e:
        hist_note = f"(Cowrie unavailable: {type(e).__name__}) — skipped"

    # ── report (FAIR: same prompt + state in both; overhead = HydraPoT-only) ───
    big_tok = (len(big_prompts[0][0]) + len(big_prompts[0][1])) // 4
    glue = mean_ms(glue_ms)                 # prompt-build + state + log (SHARED)
    inf  = mean_ms(inf_ms)                  # inference on big prompt   (SHARED)
    h_hist = hist_ms if isinstance(hist_ms, float) else 0.0
    shared      = glue + inf                # fair pure on-device baseline
    hydra_only  = route_ms + h_hist         # routing + multi-agent Cowrie sync
    fair_pure   = shared
    hydra_total = shared + hydra_only
    overhead    = hydra_only

    lines = []
    def out(s): lines.append(s); print(s, flush=True)

    out("\n" + "=" * 68)
    out("  FAIR PER-MODULE OVERHEAD — on-device (same prompt + state in both)")
    out("=" * 68)
    out(f"  stateful prompt (SHARED by both): ~{big_tok} tok")
    out("-" * 68)
    out("  SHARED modules (present in fair-pure AND HydraPoT):")
    out(f"    {'prompt-build + state + log':<38}{glue:>11.2f} ms")
    out(f"    {'inference (big stateful prompt)':<38}{inf:>11.0f} ms")
    out(f"    {'= fair pure on-device total':<38}{fair_pure:>11.0f} ms")
    out("-" * 68)
    out("  HydraPoT-ONLY modules (removed for a fair baseline):")
    out(f"    {'routing (classify)':<38}{route_ms:>11.3f} ms")
    out(f"    {'history-sync (multi-agent Cowrie)':<38}" +
        (f"{h_hist:>11.0f} ms" if isinstance(hist_ms, float) else f"{hist_note:>14}"))
    out("-" * 68)
    out(f"  {'TOTAL — fair pure on-device':<40}{fair_pure:>11.0f} ms")
    out(f"  {'TOTAL — on-device in HydraPoT':<40}{hydra_total:>11.0f} ms")
    pct = overhead / hydra_total * 100 if hydra_total else 0
    out(f"  {'>>> FAIR HydraPoT overhead':<40}{overhead:>11.0f} ms  ({pct:.1f}%)")
    out("-" * 68)
    out("  (the big prompt / inference is NOT overhead — it's in BOTH baselines,")
    out("   since any stateful on-device honeypot needs state injection)")
    out("=" * 68)

    # ── save ─────────────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(_HERE, "..", "results", "partA"); os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, f"module_overhead_{ts}.txt"), "w") as f:
        f.write("\n".join(lines))
    json.dump({
        "model": cfg.agents.on_device.model, "trials": args.trials,
        "stateful_tokens": big_tok, "fair_baseline": True,
        "shared_glue_ms": glue, "shared_inference_ms": inf,
        "hydra_only_routing_ms": route_ms,
        "hydra_only_history_sync_ms": hist_ms if isinstance(hist_ms, float) else None,
        "total_fair_pure_ms": fair_pure, "total_hydra_ms": hydra_total,
        "fair_overhead_ms": overhead, "fair_overhead_pct": round(pct, 2),
    }, open(os.path.join(outdir, f"module_overhead_{ts}.json"), "w"), indent=2)
    print(f"\nsaved -> results/module_overhead_{ts}.txt / .json")

    os._exit(0)   # avoid the noisy llama.cpp __del__ cleanup traceback on exit


if __name__ == "__main__":
    main()
