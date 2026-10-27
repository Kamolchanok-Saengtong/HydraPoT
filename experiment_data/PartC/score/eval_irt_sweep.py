"""
experiment_data/PartC/score/eval_irt_sweep.py — sweep omega on an ALREADY
TRAINED router and score each point. Loads a model, never trains one.

train_ml_router.py trains the three phases into
results/partC_ml_router/config_<hash>/. This file picks that folder up, runs
the trained policy at each requested omega, replays the real recorded
responses for whichever arm it chose, and scores them. Nothing is retrained,
so trying another omega costs seconds instead of a full training run -- which
is the whole reason the two are separate files. The sweep used to live inside
train_ml_router.main(), where adding an omega meant retraining.

Routing is honeyrouter's own: cli._picks() via train_ml_router.route_and_replay.
Scoring is train_ml_router.score_vs_partc -- the same function the regex-router
comparison uses, imported rather than reimplemented so the two cannot drift.

Output, per config folder, matching the layout training already established:

    config_<hash>/omega_<value>/fidelity/ml_router.jsonl    one replay per omega
    config_<hash>/omega_sweep.json                          every point together

irt_model.json is left alone: that file records how the model was TRAINED, and
this script does not train.

    python experiment_data/PartC/score/eval_irt_sweep.py \\
        --config-dir experiment_data/results/partC_ml_router/config_a23a86b14ed9 \\
        --omega-sweep 0,0.5,1,1.5,2
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _ROOT)
# score_vs_partc and the routing helpers live in the sibling run/ folder:
# this file scores, train_ml_router.py trains.
sys.path.insert(0, os.path.join(_HERE, "..", "run"))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config-dir", required=True, metavar="DIR",
                    help="a results/partC_ml_router/config_<hash>/ folder that "
                         "train_ml_router.py already trained. Required: the "
                         "policy has to come from a named run, not from "
                         "whatever happens to sit in honeyrouter/out/.")
    ap.add_argument("--points", type=int, default=5, metavar="N",
                    help="how many omega values to try, spread evenly from 0 "
                         "to --w-max. Default 5 (0, 0.5, 1, 1.5, 2).")
    ap.add_argument("--w-max", type=float, default=2.0, metavar="W",
                    help="top of the omega range (default 2.0, matching "
                         "reinforcement.py's training omega ~ U(0,2)). Lower "
                         "it to look inside a narrow band: the policy only "
                         "prefers cloud while omega is under cloud's fidelity "
                         "edge, ~0.03 on this data, which a 0..2 grid steps "
                         "straight over. --points 11 --w-max 0.05 lands on it.")
    ap.add_argument("--omega-sweep", dest="omegas", default=None,
                    help="explicit omega values, comma-separated, instead of "
                         "an even spread. Overrides --points/--w-max.")
    ap.add_argument("--policy", default="rl", choices=["rl", "policy"],
                    help="rl = phase 3 (PPO), policy = phase 2 (supervised)")
    args = ap.parse_args()

    run_dir = os.path.abspath(args.config_dir)
    if not os.path.isdir(run_dir):
        raise SystemExit(f"no such config folder: {run_dir}")

    # Point honeyrouter at THIS run's folder before anything imports it:
    # predictor.py, routing_policy.py and reinforcement.py each resolve their
    # own OUT_DIR at import time, so the env var has to be set first and
    # cli's own paths patched after -- the same handshake train_ml_router uses.
    os.environ["HONEYROUTER_OUT"] = run_dir
    from honeyrouter import cli as HRCLI
    HRCLI.OUT_DIR = run_dir
    HRCLI.STATE_PATH = os.path.join(run_dir, "router_state.json")

    from train_ml_router import (ARMS, FIDELITY, arm_lookup, load_policy,
                                 per_arm_cost, route_and_replay,
                                 rows_in_build_order, score_vs_partc)

    if args.omegas:
        omegas = [float(x) for x in args.omegas.split(",") if x.strip()]
    elif args.points < 1:
        raise SystemExit("--points must be at least 1")
    elif args.points == 1:
        omegas = [0.0]
    else:
        # 4 decimals, not 2: at --w-max 0.05 the step is 0.005, which rounding
        # to 2 collapsed into duplicate omegas (0.0, 0.01, 0.01, 0.02 ...) and
        # made a narrow sweep impossible to express.
        step = args.w_max / (args.points - 1)
        omegas = [round(i * step, 4) for i in range(args.points)]
    print(f"config  {os.path.relpath(run_dir, _ROOT)}/")
    print(f"policy  {args.policy}   (loaded, not trained)")
    print(f"omega   {omegas}\n")

    pol = load_policy(args.policy)
    if pol is None:
        raise SystemExit(
            f"no '{args.policy}' policy in {run_dir}.\n"
            f"  Train it first:\n"
            f"    python experiment_data/PartC/run/train_ml_router.py")

    build_rows = rows_in_build_order()
    lut = arm_lookup()
    print(f"[rows] {len(build_rows)} commands aligned to the policy's build order")

    sweep = []
    for omega in omegas:
        picks, out = route_and_replay(pol, omega, build_rows, lut)
        dist = collections.Counter(picks)
        print(f"\n[omega={omega}] routing: {dict(dist)}  (n={len(out)})")

        # One folder per omega, inside this config's folder, so neither two
        # omegas nor two configs can overwrite each other's replay.
        out_dir = os.path.join(run_dir, f"omega_{omega}", "fidelity")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "ml_router.jsonl"), "w",
                  encoding="utf-8") as fh:
            for row in out:
                fh.write(json.dumps(row) + "\n")

        sweep.append({"omega": omega, "n": len(out),
                      "routing_distribution": dict(dist),
                      **score_vs_partc(out)})

    # Reported alongside the sweep, not used by it -- the policy weighs cost
    # itself through omega. per_arm_cost wants {arm: [rows]}, the same shape
    # load_matrix builds.
    arm_rows = {a: [json.loads(l) for l in
                    open(os.path.join(FIDELITY, f"{a}.jsonl"), encoding="utf-8")]
                for a in ARMS}
    cost_norm, cost_raw = per_arm_cost(arm_rows)

    print("\n" + "=" * 70)
    print("  OMEGA SWEEP -- fidelity (cosine) vs cost, trained policy")
    print("=" * 70)
    print(f"  {'omega':>7}{'cowrie':>9}{'on_device':>11}{'cloud':>8}"
          f"{'cosine':>9}{'total_usd':>11}")
    for s in sweep:
        d = s["routing_distribution"]
        f, c = s["fidelity"]["ml_router"], s["cost"]["ml_router"]
        print(f"  {s['omega']:>7.3f}{d.get('cowrie', 0):>9}"
              f"{d.get('on_device', 0):>11}{d.get('cloud', 0):>8}"
              f"{f['cosine_score']:>9.3f}{c['total_usd']:>11.4f}")

    path = os.path.join(run_dir, "omega_sweep.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"policy": args.policy,
                   "routing": "honeyrouter.cli._picks (trained policy)",
                   "mean_cost_usd_raw": cost_raw,
                   "mean_cost_normalized": cost_norm,
                   "omega_sweep": sweep}, fh, indent=2)
    print(f"\nwrote {os.path.relpath(path, _ROOT)}")
    print(f"per-omega replays under "
          f"{os.path.relpath(run_dir, _ROOT)}/omega_<value>/fidelity/")


if __name__ == "__main__":
    main()
