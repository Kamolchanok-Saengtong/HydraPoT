"""
experiment_data/PartC/oscar/paper_summary.py -- tables for paper_suite.py results.

Rescores every session from its saved transcript and real-shell output with the
CURRENT metric definitions, so a definition change applies to all of them.

    python paper_summary.py --dir experiment_data/results/oscar_paper_suite
"""
import argparse
import glob
import json
import os
import statistics
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import paper_suite as ps                 # noqa: E402
from summarize import wilson             # noqa: E402
from probe import CREATE                 # noqa: E402


def load(pattern):
    rows = []
    for path in sorted(glob.glob(pattern)):
        rows += json.load(open(path, encoding="utf-8"))
    for r in rows:
        cmds = [c for c, _ in r["transcript"]]
        r.update(ps.score(cmds, [tuple(t) for t in r["transcript"]], r["real"]))
    return rows


def line(label, rows):
    n = len(rows)
    if not n:
        return f"  {label:<24} (no sessions)"
    cmds = sum(r["commands"] for r in rows)
    crr = sum(r["answered"] for r in rows) / cmds
    fsrr = sum(r["all_answered"] for r in rows) / n
    depth = statistics.mean(r["depth"] for r in rows)
    msl = statistics.mean(r["depth"] / r["commands"] for r in rows)
    stable = sum(r["stable"] for r in rows)
    exact = sum(r["exact"] for r in rows) / max(1, stable)
    con = [len(r["contradictions"]) for r in rows]
    det = sum(c > 0 for c in con)
    lo, hi = wilson(det, n)
    return (f"  {label:<24} {n:>4} {cmds:>6}  {crr:5.3f}  {fsrr:5.2f}  {depth:6.1f}  {msl:5.2f}  "
            f"{exact:5.3f}  {statistics.mean(con):5.2f}  {100*det/n:4.0f}% [{lo:3.0f},{hi:3.0f}]")


HEAD = (f"  {'':<24} {'N':>4} {'cmds':>6}  {'CRR':>5}  {'FSRR':>5}  {'depth':>6}  {'MSL%':>5}  "
        f"{'exact':>5}  {'contra':>5}  detected [95% Wilson]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    d = ap.parse_args().dir
    print("CRR = commands answered; FSRR = sessions fully answered; exact = identical to real "
          "Ubuntu on persona-independent commands\n")

    attack = load(f"{d}/attack*.json")
    print("ATT&CK suite (paper Table III)\n" + HEAD)
    for tactic in ps.TACTICS:
        print(line(tactic, [r for r in attack if r["label"] == tactic]))
    print(line("MEAN over all", attack), "\n")

    print("Held-out commands interleaved with create-revisit (paper Table V)\n" + HEAD)
    lo_i, hi_i = len(CREATE), len(CREATE) + len(ps.HELDOUT)
    for name, f in (("gate ON", "heldout_gate_on*.json"), ("gate OFF", "heldout_gate_off*.json")):
        rows = load(f"{d}/{f}")
        print(line(name, rows))
        if rows:
            held = [sum(1 for i in range(lo_i, hi_i) if ps.failed(r["transcript"][i][1], r["real"][i]))
                    for r in rows]
            print(f"  {'  held-out commands only':<24} answered "
                  f"{1 - sum(held) / (len(held) * len(ps.HELDOUT)):5.3f}")
    print()

    print("Wild replay of real captured sessions (paper Sec. VI-I)\n" + HEAD)
    print(line("ml4net", load(f"{d}/wild_ml4net_*.json")))
    print(line("cyberlab", load(f"{d}/wild_cyberlab.json")))


if __name__ == "__main__":
    main()
