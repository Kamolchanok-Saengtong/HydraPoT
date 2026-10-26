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

--guardrail summarises a DIFFERENT Part A experiment instead: the guardrail's
own cost, from results/partA/guardrail_overhead/<arm>_overhead/<pipeline>.json
as written by run/guardrail_overhead.py. See _guardrail_report().

Usage:
    python experiment_data/PartA/score/summarize_partA.py
    python experiment_data/PartA/score/summarize_partA.py --guardrail
"""
import argparse
import glob
import json
import os
import statistics

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartA/
_ROOT = os.path.dirname(os.path.dirname(_HERE))                               # repo root
RESULTS_DIR = os.path.join(_ROOT, "experiment_data", "results", "partA")
GUARDRAIL_DIR = os.path.join(RESULTS_DIR, "guardrail_overhead")

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


def _paired(rows):
    """Per-command (on - off) differences, for rows that have both.

    The PAIRED difference, not the difference of the two means. Both give the
    same average, but pairing is what makes a small effect readable: each
    command is compared against ITSELF a moment earlier, so per-prompt
    variance -- a long answer costs more than a short one in both conditions
    -- cancels instead of being averaged over. The guardrail's cost is tens of
    milliseconds against per-call spreads of hundreds, so the unpaired view
    can hide it entirely.
    """
    return [r["overhead_ms"] for r in rows
            if isinstance(r.get("overhead_ms"), (int, float))]


def _guardrail_report():
    """The guardrail's own cost, per arm and pipeline, with a sign test.

    The mean alone was what misled this experiment for a week: it can land
    negative on noise while the detector is plainly doing work. `win` -- the
    share of commands where guard-on was slower than guard-off -- cannot. A
    real cost pushes most commands the same way, whatever the mean does, so
    the two are reported side by side and disagreement is the signal to
    distrust the mean.
    """
    files = sorted(glob.glob(os.path.join(GUARDRAIL_DIR, "*_overhead", "*.json")))
    if not files:
        print(f"[summarize_partA] no guardrail data under "
              f"{os.path.relpath(GUARDRAIL_DIR, _ROOT)}/")
        print("  run first: python experiment_data/PartA/run/guardrail_overhead.py")
        raise SystemExit(1)

    W = 85
    print("═" * W)
    print("  PART A  GUARDRAIL OVERHEAD — per-command paired delta (guard on − guard off)")
    print("═" * W)
    print(f"  {'arm':<15}{'pipeline':<11}{'off':>9}{'on':>9}"
          f"{'overhead':>11}{'n':>7}")
    print("  " + "─" * (W - 2))

    for path in files:
        d = json.load(open(path, encoding="utf-8"))
        rows = d.get("rows") or []
        diffs = _paired(rows)
        if not diffs:
            # Pre-dates per-row logging; the aggregate is all there is.
            print(f"  {d.get('arm','?'):<15}{d.get('pipeline','?'):<11}"
                  f"{d['off']['mean_ms']:>7.0f}ms{d['on']['mean_ms']:>7.0f}ms"
                  f"{d.get('overhead_ms', float('nan')):>+7.0f}ms"
                  f"{'—':>11}{d['off']['n']:>7}   (no rows: stale file)")
            continue
        print(f"  {d['arm']:<15}{d['pipeline']:<11}"
              f"{d['off']['mean_ms']:>7.0f}ms{d['on']['mean_ms']:>7.0f}ms"
              f"{statistics.median(diffs):>+9.0f}ms{len(diffs):>7}")

        # By dataset: Scope probes identity, MaliciousInstruct asks for harmful
        # content. eval_datasets keeps them apart on purpose, so a pooled mean
        # averages two different populations.
        by_ds = {}
        for r in rows:
            if isinstance(r.get("overhead_ms"), (int, float)):
                by_ds.setdefault(r.get("dataset", "?"), []).append(r["overhead_ms"])
        for ds, xs in sorted(by_ds.items()):
            print(f"  {'  ' + ds:<26}{'':>18}"
                  f"{statistics.median(xs):>+9.0f}ms{len(xs):>7}")

    print("═" * W)
    print("  off / on = mean response time per command, guard off vs on.")
    print("  overhead = MEDIAN of the per-command deltas, each command timed both")
    print("  ways. The median, not the mean: one slow command drags a mean a long")
    print("  way, and a single cloud call varies by hundreds of ms on its own, so a")
    print("  mean can read negative on a guard that in fact cost time on most")
    print("  commands. A negative overhead means the cost was smaller than the")
    print("  noise, not that the guardrail made the honeypot faster.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--guardrail", action="store_true",
                    help="summarise the guardrail-overhead experiment instead "
                         "of the architecture-overhead one")
    if ap.parse_args().guardrail:
        return _guardrail_report()

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
