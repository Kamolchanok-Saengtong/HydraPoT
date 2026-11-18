"""
experiment_data/PartC/score/eval_irt_sweep.py — sweep omega on an ALREADY
TRAINED router and score each point in the TRUE ENVIRONMENT. Loads a model,
never trains one.

train_ml_router.py trains the three phases into
results/partC_ml_router/config_<hash>/. This file picks that folder up and, for
each requested omega, runs the trained policy and ACTUALLY CALLS the picked
agent through the real pipeline (run_partC.py --arms irt_router) -- fresh
SYSTEM_STATE per session, real on-device/cloud inference -- then scores the
responses. There is no replay: every omega is a live run, so the routing AND
the responses reflect the real agents at that cost preference. Slow, and every
cloud hop is billed per omega -- that is the cost of measuring the real system.

Routing is honeyrouter's own: cli._picks(), driven live by run_partC.py's
irt_router arm. Scoring is train_ml_router.score_vs_partc -- the same function
the regex-router comparison uses, imported rather than reimplemented so the two
cannot drift.

Output, per config folder, matching the layout training already established:

    config_<hash>/omega_<value>/fidelity/ml_router.jsonl    one live run per omega
    config_<hash>/omega_sweep.json                          every point together

irt_model.json is left alone: that file records how the model was TRAINED, and
this script does not train.

    python experiment_data/PartC/score/eval_irt_sweep.py \\
        --config-dir experiment_data/results/partC_ml_router/config_a23a86b14ed9 \\
        --sessions dataset/dataset_groundtruth_50000.json \\
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


def route_live(run_dir, omega, policy, sessions, trials):
    """(picks, rows) with the picked agent ACTUALLY CALLED, not replayed.

    Delegates to run_partC.py's existing `irt_router` arm rather than calling
    agents from here: that arm already gives each session a fresh handle and
    its own SYSTEM_STATE, the way ground truth was collected, and getting that
    wrong is exactly what makes a stateful replay meaningless. This only tells
    it which trained policy and which omega to route with, then reshapes its
    records into the same rows the replay path returns, so scoring downstream
    cannot tell the two apart.
    """
    import subprocess

    tag = f"live_omega_{omega}"
    cmd = [sys.executable, "-u",
           os.path.join(_ROOT, "experiment_data", "PartC", "run",
                        "run_partC.py"),
           "--sessions", sessions,
           "--arms", "irt_router",
           "--irt-config-dir", run_dir,
           "--irt-policy", policy,
           "--irt-omega", str(omega),
           "--trials", str(trials),
           "--tag", tag]
    print(f"\n[live omega={omega}] {' '.join(cmd[2:])}", flush=True)
    # The on-device GGUF model barely fits an 8GB GPU; a co-tenant briefly
    # taking VRAM makes `llama_context` creation fail and the live run exit 1.
    # That is transient, so retry a few times with a wait before giving up
    # rather than letting one GPU hiccup kill the whole 51-pass sweep.
    import time as _time
    _ATTEMPTS = 4
    for _attempt in range(1, _ATTEMPTS + 1):
        try:
            subprocess.run(cmd, cwd=_ROOT, check=True)
            break
        except subprocess.CalledProcessError:
            if _attempt == _ATTEMPTS:
                raise
            wait = 30 * _attempt
            print(f"[live omega={omega}] run failed "
                  f"(attempt {_attempt}/{_ATTEMPTS}) — waiting {wait}s, "
                  f"likely GPU VRAM contention", flush=True)
            _time.sleep(wait)

    produced = os.path.join(_ROOT, "experiment_data", "results", "partC",
                            f"fidelity_{tag}", "irt_router.jsonl")
    if not os.path.isfile(produced):
        raise SystemExit(f"live run wrote no {produced}")

    picks, out = [], []
    with open(produced, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            arm = row.get("routed_to", "unknown")
            picks.append(arm)
            row["arm"] = "ml_router"        # the key score_vs_partc reads
            row["omega"] = omega
            out.append(row)
    return picks, out


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
    ap.add_argument("--force", action="store_true",
                    help="recompute every requested omega even if it is already "
                         "in this config's omega_sweep.json. Default reuses "
                         "cached points (same policy) and only computes the new "
                         "ones, extending the curve -- which also avoids "
                         "re-billing an omega that was already run live.")
    ap.add_argument("--policy", default="rl", choices=["rl", "policy"],
                    help="rl = phase 3 (PPO), policy = phase 2 (supervised)")
    ap.add_argument("--sessions", metavar="PATH", required=True,
                    help="dataset the live pipeline runs through the agents, "
                         "e.g. dataset/dataset_groundtruth_50000.json.")
    ap.add_argument("--trials", type=int, default=1, metavar="N",
                    help="trials per session (default 1)")
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

    from train_ml_router import (ARMS, FIDELITY, load_policy,
                                 per_arm_cost, score_vs_partc)

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

    sweep_path = os.path.join(run_dir, "omega_sweep.json")

    # Incremental sweep: an omega already run live for THIS config (same policy)
    # is reused from the previous omega_sweep.json, so adding a few points in
    # between -- 0.25, 0.75, ... -- only pays for the new ones, and an omega is
    # never billed to the cloud twice. The output is the union of the old points
    # and the requested ones, so a sweep extends rather than replaces. --force
    # recomputes everything. Reuse is gated on policy: merging two different
    # policies into one curve would be wrong, so a mismatch recomputes all.
    cached = {}
    if os.path.exists(sweep_path) and not args.force:
        try:
            prev = json.load(open(sweep_path, encoding="utf-8"))
            if prev.get("policy") == args.policy:
                cached = {round(float(e["omega"]), 4): e
                          for e in prev.get("omega_sweep", [])}
            else:
                print("[note] existing omega_sweep.json is a different "
                      "policy -- recomputing every omega")
        except Exception:
            pass

    req = [(o, round(float(o), 4)) for o in omegas]
    reuse = [o for o, k in req if k in cached]
    compute = [o for o, k in req if k not in cached]
    if reuse:
        print(f"[reuse] {len(reuse)} omega(s) already on disk for this config: "
              f"{sorted(set(reuse))}")
    print(f"[compute] {len(compute)} new omega(s): {sorted(set(compute))}"
          if compute else "[compute] nothing new -- every requested omega is cached")

    if compute:
        print(f"[live] agents are called for real, per omega, from "
              f"{args.sessions}")

    # Start from every cached point so the sweep extends; requested omegas are
    # (re)filled below, keyed by the rounded value.
    merged = dict(cached)
    for omega, key in req:
        if key in cached:
            continue
        picks, out = route_live(run_dir, omega, args.policy,
                                args.sessions, args.trials)
        dist = collections.Counter(picks)
        print(f"\n[omega={omega}] routing: {dict(dist)}  (n={len(out)})")

        # One folder per omega, inside this config's folder, so neither two
        # omegas nor two configs can overwrite each other's live run.
        out_dir = os.path.join(run_dir, f"omega_{omega}", "fidelity")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "ml_router.jsonl"), "w",
                  encoding="utf-8") as fh:
            for row in out:
                fh.write(json.dumps(row) + "\n")

        merged[key] = {"omega": omega, "n": len(out),
                       "routing_distribution": dict(dist),
                       **score_vs_partc(out)}

    sweep = [merged[k] for k in sorted(merged)]

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

    with open(sweep_path, "w", encoding="utf-8") as fh:
        json.dump({"policy": args.policy,
                   "mode": "live",
                   "sessions": args.sessions,
                   "routing": "honeyrouter.cli._picks (trained policy), live agents",
                   "mean_cost_usd_raw": cost_raw,
                   "mean_cost_normalized": cost_norm,
                   "omega_sweep": sweep}, fh, indent=2)
    print(f"\nwrote {os.path.relpath(sweep_path, _ROOT)}  "
          f"({len(sweep)} omega points)")
    print(f"per-omega live output under "
          f"{os.path.relpath(run_dir, _ROOT)}/omega_<value>/fidelity/")


if __name__ == "__main__":
    main()
