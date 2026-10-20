"""
experiment_data/PartA/score/summarize_partA.py — architecture-overhead table.

Reads the Part A run under results/partA/<arm>/<arm>.jsonl and reports, per
agent, the ABSOLUTE overhead in milliseconds that HydraPoT's machinery adds on
top of the bare agent:

    overhead_ms = mean(latency of <agent>_hydrapot) - mean(latency of standalone_<agent>)

standalone_* is the bare agent OUTSIDE the HydraPoT pipeline (zero HydraPoT);
<agent>_hydrapot is the SAME agent forced THROUGH the real pipeline (SSH proxy,
router/classify, PromptManager, SYSTEM_STATE mutation, FI scoring, history-sync).
The delta is the overhead reviewers asked for — in ms, not just a percentage.

Usage:
    python experiment_data/PartA/score/summarize_partA.py
"""
import glob
import json
import os
import statistics

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartA/
_ROOT = os.path.dirname(os.path.dirname(_HERE))                               # repo root
RESULTS_DIR = os.path.join(_ROOT, "experiment_data", "results", "partA")

# (display, standalone arm, hydrapot arm) — on_device is labelled "local".
ARMS = [
    ("Cowrie",           "standalone_cowrie", "cowrie_hydrapot"),
    ("Local (on-device)", "standalone_local",  "local_hydrapot"),
    ("Cloud",            "standalone_cloud",  "cloud_hydrapot"),
]


def _read_blocks(path):
    """Parse a file of blank-line-separated pretty-printed JSON objects."""
    recs = []
    try:
        txt = open(path, encoding="utf-8").read()
    except OSError:
        return recs
    dec, i, n = json.JSONDecoder(), 0, len(txt)
    while i < n:
        while i < n and txt[i] in " \n\r\t":
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(txt, i)
        except json.JSONDecodeError:
            break
        recs.append(obj)
    return recs


def _latencies(arm):
    recs = _read_blocks(os.path.join(RESULTS_DIR, arm, f"{arm}.jsonl"))
    return [r["latency_ms"] for r in recs
            if r.get("ok") and isinstance(r.get("latency_ms"), (int, float))]


def _pct(xs, q):
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * q
    lo = int(k)
    return s[lo] if lo + 1 >= len(s) else s[lo] + (s[lo + 1] - s[lo]) * (k - lo)


def main():
    if not glob.glob(os.path.join(RESULTS_DIR, "*", "*.jsonl")):
        print(f"[summarize_partA] no data under {os.path.relpath(RESULTS_DIR, _ROOT)}/")
        print("  run first: python experiment_data/PartA/run/run_partA.py --trials 1")
        raise SystemExit(1)

    W = 80
    print("═" * W)
    print("  PART A  ARCHITECTURE OVERHEAD — ABSOLUTE (ms), per agent")
    print(f"  standalone (outside pipeline)  vs  *_hydrapot (through pipeline)")
    print("═" * W)
    print(f"  {'agent':<18} {'standalone':>11} {'hydrapot':>10} "
          f"{'overhead':>10} {'overhead %':>11} {'n':>5}")
    print("  " + "─" * (W - 2))

    for disp, pure_arm, hyd_arm in ARMS:
        pure = _latencies(pure_arm)
        hyd  = _latencies(hyd_arm)
        if not pure and not hyd:
            print(f"  {disp:<18} (no data)")
            continue
        pm, hm = statistics.mean(pure), statistics.mean(hyd)
        over = hm - pm
        pct  = (over / pm * 100) if pm else float("nan")
        n = min(len(pure), len(hyd))
        print(f"  {disp:<18} {pm:>10.1f}m {hm:>9.1f}m "
              f"{over:>+9.1f}m {pct:>+10.1f}% {n:>5}")
        print(f"  {'  (median)':<18} {statistics.median(pure):>10.1f}m "
              f"{statistics.median(hyd):>9.1f}m "
              f"{statistics.median(hyd) - statistics.median(pure):>+9.1f}m")
        print(f"  {'  (p95)':<18} {_pct(pure, 0.95):>10.1f}m {_pct(hyd, 0.95):>9.1f}m")

    hr = _latencies("honeyrouter")
    if hr:
        print("  " + "─" * (W - 2))
        print(f"  {'HoneyRouter':<18} {'—':>11} {statistics.mean(hr):>9.1f}m "
              f"   (natural routing — no standalone pair)")
    print("═" * W)
    print("  'm' = milliseconds.  overhead = hydrapot − standalone (HydraPoT's own cost).")


if __name__ == "__main__":
    main()
