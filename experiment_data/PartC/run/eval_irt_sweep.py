"""
experiment_data/PartC/run/eval_irt_sweep.py — 6-metric semantic score + real
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
sys.path.insert(0, _HERE)

from train_ml_router import ARMS, score_vs_partc  # noqa: E402

OUT_DIR = os.path.join(_ROOT, "experiment_data", "results", "partC", "honeyrouter_irt")


def rows_in_build_order():
    """(session_id, position_in_session) per row, in EXACTLY the order
    routing_policy.build_pairwise_dataset() iterates -- sessions.py's
    load_sessions() dict order, then each session's command order."""
    from honeyrouter.sessions import load_sessions
    sess = load_sessions()
    return [(sid, c["position"]) for sid, cmds in sess.items() for c in cmds]


def arm_lookup():
    """{(session_id, position_in_session): {arm: real_row}} from the SAME
    fidelity files score_vs_partc reads, so a picked row is the arm's REAL
    stored response -- a replay, not a new generation."""
    from train_ml_router import FIDELITY
    lut = {a: {} for a in ARMS}
    for a in ARMS:
        for r in (json.loads(l) for l in open(os.path.join(FIDELITY, f"{a}.jsonl"))):
            lut[a][(str(r["session_id"]), r["position_in_session"])] = r
    return lut


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--points", type=int, default=5)
    ap.add_argument("--policy", default="rl", choices=["rl", "policy"])
    args = ap.parse_args()

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

    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "sweep_semantic_and_judge.json")
    with open(path, "w") as fh:
        json.dump({"policy": args.policy, "sweep": results}, fh, indent=2)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
