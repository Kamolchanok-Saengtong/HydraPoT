"""
experiment_data/PartC/oscar/summarize.py — old vs new, the way OSCAR reports it.

    Table I    create-then-revisit, N sessions: contradictions mean +- sd, and
               detection % (sessions with >= 1 contradiction) with a 95%
               Wilson interval, as in Gil et al. TDSC 2026 Tables I and VII
    Table XIV  mean contradictions per session length L
    signatures which contradiction types each system produced

    python summarize.py --dir experiment_data/results/oscar_probe
"""
import argparse
import collections
import json
import math
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import SIGNATURES     # noqa: E402


def wilson(k: int, n: int, z: float = 1.96):
    """95% Wilson score interval for k successes out of n, in percent."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return 100 * max(0.0, centre - half), 100 * min(1.0, centre + half)


def load(path):
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def table1(runs, label):
    counts = [len(r["contradictions"]) for r in runs]
    n, detected = len(counts), sum(c > 0 for c in counts)
    lo, hi = wilson(detected, n)
    sd = statistics.stdev(counts) if n > 1 else 0.0
    gates = [r["gate"] for r in runs if r.get("gate")]
    fallback = (sum(g["fallbacks"] for g in gates) / sum(g["turns"] for g in gates)
                if gates else None)
    fb = f"{100 * fallback:5.1f}%" if fallback is not None else "    —"
    print(f"  {label:<6} {n:>3}  {statistics.mean(counts):5.2f} ± {sd:4.2f}   "
          f"{100 * detected / n:5.1f}% [{lo:4.1f}, {hi:5.1f}]   {fb}")


def table14(old, new):
    by, length_cmds = {}, {}
    for label, runs in (("old", old or []), ("new", new or [])):
        for r in runs:
            by.setdefault(r["fillers"], {}).setdefault(label, []).append(
                len(r["contradictions"]))
            length_cmds[r["fillers"]] = len(r["transcript"])
    print(f"  {'L':>4} {'commands':>9} {'old':>8} {'new':>8}")
    for length in sorted(by):
        cells = []
        for label in ("old", "new"):
            vals = by[length].get(label)
            cells.append(f"{statistics.mean(vals):8.1f}" if vals else f"{'—':>8}")
        print(f"  {length:>4} {length_cmds[length]:>9} {cells[0]} {cells[1]}")


def signatures(sets):
    print(f"  {'signature':<14}" + "".join(f"{label:>8}" for label, _ in sets))
    totals = {label: collections.Counter(
        c["signature"] for r in runs for c in r["contradictions"])
        for label, runs in sets}
    for sig in SIGNATURES:
        print(f"  {sig:<14}" + "".join(f"{totals[label][sig]:>8}" for label, _ in sets))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    d = ap.parse_args().dir
    t1_old, t1_new = load(f"{d}/table1_old.json"), load(f"{d}/table1_new.json")
    t14_old, t14_new = load(f"{d}/table14_old.json"), load(f"{d}/table14_new.json")
    real = load(f"{d}/real_shell_calibration.json")

    if real:
        print(f"Oracle calibration on a real Ubuntu shell: "
              f"{sum(len(r['contradictions']) for r in real)} contradictions "
              f"over {len(real)} sessions (must be 0)\n")
    if t1_old or t1_new:
        print("TABLE I — create-then-revisit probe")
        print(f"  {'system':<6} {'N':>3}  {'contra/session':>14}   "
              f"{'detected [95% Wilson]':>22}   fallback")
        for label, runs in (("old", t1_old), ("new", t1_new)):
            if runs:
                table1(runs, label)
        print()
    if t14_old or t14_new:
        print("TABLE XIV — mean contradictions vs session length L (fillers)")
        table14(t14_old, t14_new)
        print()
    sets = [(l, r) for l, r in (("old", (t1_old or []) + (t14_old or [])),
                                ("new", (t1_new or []) + (t14_new or []))) if r]
    if sets:
        print("Contradictions by signature (all sessions)")
        signatures(sets)


if __name__ == "__main__":
    main()
