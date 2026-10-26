"""
experiment_data/PartC/score/eval_irt_sweep.py — 6-metric semantic score + real
judge score + cost, per omega point, for the TRAINED honeyrouter PPO policy.

Nothing re-derived: routing comes from honeyrouter.cli's own _load_data/_picks
(the same functions --review uses), judge scores are the REAL ones already in
results/partC/fidelity/judge/ (no new judge call), and the 6-metric semantic
fidelity comes from train_ml_router.score_vs_partc -- the same function the
regex-router comparison already used. This file only wires them together and
writes the result under results/partC/, not honeyrouter/out/.
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _ROOT)
# score_vs_partc lives in the sibling run/ folder, not here: this file scores,
# train_ml_router.py trains. Imported rather than reimplemented so the
# HoneyRouter and the ML-router baseline are scored by the same function.
sys.path.insert(0, os.path.join(_HERE, "..", "run"))

from train_ml_router import (ARMS, arm_lookup, rows_in_build_order,  # noqa: E402
                             score_vs_partc)

OUT_DIR = os.path.join(_ROOT, "experiment_data", "results", "partC", "honeyrouter_irt")


# rows_in_build_order() and arm_lookup() used to be defined here. They now live
# beside score_vs_partc in run/train_ml_router.py and are imported above, so
# the two files cannot drift: both route through the same build order, and a
# mismatch there would silently serve the wrong command's response.


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--points", type=int, default=5)
    ap.add_argument("--policy", default="rl", choices=["rl", "policy"])
    ap.add_argument("--out-dir", default=OUT_DIR,
                    help="where to write sweep_semantic_and_judge.json; a "
                         "config sweep points this at its own config_N/ so "
                         "runs do not overwrite each other")
    args = ap.parse_args()
    out_dir = args.out_dir

    sys.path.insert(0, os.path.join(_ROOT, "honeyrouter", ".."))
    from honeyrouter import cli as HR

    build_rows = rows_in_build_order()
    lut = arm_lookup()

    pol = HR._policy(args.policy)
    if pol is None:
        raise SystemExit("no trained policy found -- run honeyrouter/cli.py --train first")

    results = []
    for omega in [round(i * 2.0 / (args.points - 1), 2) for i in range(args.points)]:
        pick = HR._picks(pol, omega)                     # arm-index per row, build order
        out = []
        for n, (sid, pos) in enumerate(build_rows):
            arm = ARMS[pick[n]]
            real = lut[arm].get((str(sid), pos))
            if real is None:
                continue
            row = dict(real)
            row["arm"], row["routed_to"] = "irt_router", arm
            out.append(row)

        import collections
        dist = collections.Counter(r["routed_to"] for r in out)
        print(f"\n[omega={omega}] routing: {dict(dist)}  (n={len(out)})")
        comparison = score_vs_partc(out)                 # 6-metric semantic + cost, imported
        results.append({"omega": omega, "n": len(out),
                        "routing_distribution": dict(dist), **comparison})

    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "sweep_semantic_and_judge.json")
    with open(path, "w") as fh:
        json.dump({"policy": args.policy, "sweep": results}, fh, indent=2)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
