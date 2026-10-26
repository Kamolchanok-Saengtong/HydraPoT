"""
experiment_data/PartC/run/train_ml_router.py — replay Part C through the
HoneyRouter's OWN trained policy, swept over the preference weight omega.

THE ROUTING LOGIC IS honeyrouter/'s, NOT THIS FILE'S. The arm for each command
comes from honeyrouter.cli._picks() -- the policy trained by
honeyrouter/cli.py --train through the paper's three stages (variational IRT ->
preference-conditioned SetTransformer policy -> multi-objective PPO):

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743

This file used to fit its OWN router instead -- a Rasch (1PL) IRT plus a
TF-IDF -> MLP difficulty net, routed by argmax(fidelity - lambda*cost). None of
that is in the paper: no variational IRT, no policy network, no PPO, no
preference vector. It was a second, simpler router standing in for the real
one, so its numbers did not describe the method being published. Removed.

Pipeline now:
  1. Score every arm's real response against ground truth (score_all_metrics.py's
     own _fast_metrics, so numbers line up with the rest of Part C) -> a
     2179 x 3 correctness matrix. REPORTED ONLY -- nothing is fitted on it here;
     the policy was trained in honeyrouter/.
  2. Real per-arm cost, same formula as cost_analysis.py: cloud $/call for
     cloud, GPU_AVG_WATT x latency for on_device, 0 for cowrie. Reported, and
     used by no routing decision -- the policy weighs cost itself through omega.
  3. For each omega in the sweep, honeyrouter's policy picks the arm per
     command (cli._picks, the same call cli.py --review uses).
  4. REPLAY: the response served is the stored real response from the picked
     arm -- same mechanism replay_honeyrouter.py uses, no new agent calls.
  5. Scored and costed by CALLING score_all_metrics.py's _fast_metrics and
     cost_analysis.py's own cost primitives (cost.cost_model.gpu_avg_watt,
     cost.power_cost.kwh_to_thb) -- nothing re-derived.

SHARED HELPERS LIVE HERE, imported by score/eval_irt_sweep.py and
score/summarize_irt_router.py: ARMS, FIDELITY, score_vs_partc(),
rows_in_build_order(), arm_lookup(). One direction only -- score/ imports from
run/, never the reverse -- so there is no cycle.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))                       # .../PartC/run
_PARTC = os.path.dirname(_HERE)                                          # .../PartC
_ROOT = os.path.abspath(os.path.join(_PARTC, "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "evaluation"))
sys.path.insert(0, os.path.join(_PARTC, "score"))

FIDELITY = os.path.join(_ROOT, "experiment_data", "results", "partC", "fidelity")
OUT_DIR = os.path.join(_ROOT, "experiment_data", "results", "partC_ml_router")
ARMS = ("cowrie", "on_device", "cloud")

# Training lengths come from cli.py, NOT from this file -- one source of truth,
# and they are the paper's own values (arXiv:2502.02743, appendix E.3-E.5). A
# bare run here therefore trains exactly what production trains, so any
# difference is a flag you passed and it shows up in config.json.
#
# Safe to import at module level: cli.py imports nothing from honeyrouter
# itself at import time (every one of its honeyrouter imports is inside a
# function), so the stage modules stay unimported until main() has set
# HONEYROUTER_OUT and they can resolve their paths to this run's folder.
from honeyrouter import cli as HRCLI                        # noqa: E402

DEFAULTS = HRCLI.DEFAULTS
STAGES = {
    "p1": os.path.join(_ROOT, "honeyrouter", "predictor.py"),
    "p2": os.path.join(_ROOT, "honeyrouter", "routing_policy.py"),
    "p3": os.path.join(_ROOT, "honeyrouter", "reinforcement.py"),
}


# ── 0. train the three phases from scratch, into THIS run's folder ──────────

def config_hash(cfg: dict) -> str:
    """Short digest of the hyperparameters alone, so a config maps to a folder.

    Sorted keys, and nothing but the hyperparameters: fold in a timestamp and
    every run looks new, so a repeat could never be recognised.
    """
    blob = json.dumps(cfg, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def train_phases(cfg: dict, out_dir: str) -> str:
    """Run the paper's three phases from scratch into out_dir.

    The same three scripts cli.py --train runs, with the same flags -- the
    training logic is honeyrouter's, this only chooses where it lands.
    HONEYROUTER_OUT is what redirects it: predictor.py, routing_policy.py and
    reinforcement.py all resolve their artifact paths through it, so the
    writes AND the cross-stage reads stay in out_dir and PRODUCTION in
    honeyrouter/out/ is never touched.

    Returns the policy to evaluate: "rl" when phase 3 ran, else "policy".
    """
    env = dict(os.environ, HONEYROUTER_OUT=out_dir)

    print(f"[phase 1/3] IRT predictor · {cfg['p1_epochs']} epochs", flush=True)
    subprocess.run([sys.executable, "-u", STAGES["p1"],
                    "--epochs", str(cfg["p1_epochs"])],
                   cwd=_ROOT, env=env, check=True)

    print(f"[phase 2/3] policy pretraining · {cfg['p2_steps']} steps, "
          f"batch {cfg['p2_batch']}", flush=True)
    subprocess.run([sys.executable, "-u", STAGES["p2"],
                    "--steps", str(cfg["p2_steps"]),
                    "--batch", str(cfg["p2_batch"])],
                   cwd=_ROOT, env=env, check=True)

    if not cfg["run_rl"]:
        print("[phase 3/3] skipped (--no-rl)", flush=True)
        return "policy"

    print(f"[phase 3/3] multi-objective PPO · {cfg['p3_steps']} steps", flush=True)
    cmd = [sys.executable, "-u", STAGES["p3"], "--steps", str(cfg["p3_steps"])]
    if not cfg["mixup"]:
        cmd.append("--no-mixup")
    subprocess.run(cmd, cwd=_ROOT, env=env, check=True)
    return "rl"


# ── 1. score every arm's real response against ground truth ────────────────

def load_matrix():
    from score_all_metrics import _fast_metrics  # noqa: E402

    rows = {a: [json.loads(l) for l in open(os.path.join(FIDELITY, f"{a}.jsonl"))]
            for a in ARMS}
    n = len(rows["cowrie"])
    for a in ARMS[1:]:
        assert len(rows[a]) == n

    cmds, scores, meta = [], np.zeros((n, 3)), []
    for i in range(n):
        base = rows["cowrie"][i]
        cmds.append(base["cmd"])
        meta.append({"session_id": base["session_id"],
                     "position_in_session": base["position_in_session"],
                     "trial": base["trial"], "cmd": base["cmd"],
                     "ground_truth": base["ground_truth"],
                     "fi_score": base["fi_score"]})
        for j, a in enumerate(ARMS):
            r = rows[a][i]
            fm = _fast_metrics(r.get("response"), r.get("ground_truth"))
            # one scalar "correctness" per (command, arm): mean of the
            # non-BERT metrics already used elsewhere in Part C -- avoids a
            # GPU dependency here, and avoids picking one metric over another.
            scores[i, j] = np.mean([fm["cosine_score"], fm["levenshtein_score"],
                                    fm["jaro_winkler_score"], fm["sequence_score"]])
    return cmds, scores, meta, rows


# ── 2. row alignment for honeyrouter's policy ───────────────────────────────
# These two live here, not in score/eval_irt_sweep.py, so the import runs one
# way only: score/ imports from run/, never the reverse. Putting them in the
# scorer and importing score_vs_partc back out of this file would be a cycle.

def rows_in_build_order():
    """(session_id, position_in_session) per row, in EXACTLY the order
    routing_policy.build_pairwise_dataset() iterates -- sessions.py's
    load_sessions() dict order, then each session's command order.

    The policy returns one arm index per row in that order and nothing else
    carries the mapping, so a mismatch here would silently serve the wrong
    command's response.
    """
    from honeyrouter.sessions import load_sessions
    sess = load_sessions()
    return [(sid, c["position"]) for sid, cmds in sess.items() for c in cmds]


def arm_lookup():
    """{arm: {(session_id, position_in_session): real_row}} from the SAME
    fidelity files score_vs_partc reads, so a picked row is the arm's REAL
    stored response -- a replay, not a new generation."""
    lut = {a: {} for a in ARMS}
    for a in ARMS:
        with open(os.path.join(FIDELITY, f"{a}.jsonl"), encoding="utf-8") as fh:
            for r in (json.loads(l) for l in fh):
                lut[a][(str(r["session_id"]), r["position_in_session"])] = r
    return lut


# ── 3. per-arm real cost basis, same formula as cost_analysis.py ───────────

def per_arm_cost(rows):
    from cost.cost_model import gpu_avg_watt
    from cost.power_cost import kwh_to_thb
    from core.config_loader import load_config

    tariff = load_config().power_tariff
    gpu_w = gpu_avg_watt()
    n = len(rows["cowrie"])

    cloud_usd_per_call = np.array([r.get("cost") or 0.0 for r in rows["cloud"]])
    od_ms_per_call = np.array([r.get("inference_ms") or 0.0 for r in rows["on_device"]])
    od_kwh_per_call = gpu_w * (od_ms_per_call / 1000 / 3600) / 1000.0
    od_thb_per_call = np.array([kwh_to_thb(k, tariff)["total_thb"] if k > 0 else 0.0
                                for k in od_kwh_per_call])
    usd_per_thb = 1 / 35.0
    od_usd_per_call = od_thb_per_call * usd_per_thb

    # mean per-call cost, one scalar per arm -- the routing decision for a
    # command we have not yet run can only use the arm's AVERAGE cost, not
    # that command's own (unknown ahead of time) latency/token count.
    raw = {"cowrie": 0.0, "on_device": float(od_usd_per_call.mean()),
          "cloud": float(cloud_usd_per_call.mean())}
    # normalized to [0,1] by the most expensive arm, so lambda is comparable
    # to fidelity (also [0,1]) instead of needing a guessed huge multiplier
    # to register against a $1e-4 cost.
    scale = max(raw.values()) or 1.0
    norm = {a: v / scale for a, v in raw.items()}
    return norm, raw


# ── 5. route + replay with the REAL stored response ─────────────────────────

def load_policy(which: str = "rl"):
    """honeyrouter's TRAINED policy, via its own loader.

    `which`: "rl" is the PPO-trained policy (stage 3), "policy" the
    supervised-pretrained one (stage 2). None when nothing is trained yet.
    """
    from honeyrouter import cli as HR
    return HR._policy(which)


def route_and_replay(pol, omega, build_rows, lut):
    """One arm per command from honeyrouter's policy, then the REAL response.

    The decision is entirely honeyrouter's: cli._picks() runs the trained
    preference-conditioned policy at this omega -- the same call cli.py
    --review makes. Nothing here scores, ranks or weighs anything; this only
    maps the policy's choice back to the stored response for that command, so
    the served answer is a replay rather than a new generation.

    omega weights -cost, so a higher omega is cheaper. Range matches
    reinforcement.py's training, omega ~ U(0, 2).
    """
    from honeyrouter import cli as HR
    pick = HR._picks(pol, omega)                 # arm index per row, build order
    picks, out = [], []
    for n, (sid, pos) in enumerate(build_rows):
        arm = ARMS[pick[n]]
        real = lut[arm].get((str(sid), pos))
        if real is None:                         # scored row the fidelity files lack
            continue
        picks.append(arm)
        row = dict(real)
        row["arm"] = "ml_router"                 # key score_vs_partc + the
        row["routed_to"] = arm                   # summariser already read
        row["omega"] = omega
        out.append(row)
    return picks, out


# ── 6. score against Part C, calling score_all_metrics.py / cost_analysis.py ──

def score_vs_partc(ml_rows):
    """Fidelity + cost for ml_router, next to cowrie/on_device/cloud/honeyrouter --
    calls the SAME functions those arms were scored with, not a re-derivation.
    """
    from collections import defaultdict
    from score_all_metrics import _fast_metrics, _load_valid, METRICS  # noqa: E402

    fast_metrics = [m for m in METRICS if m[0] != "bert_f1"]   # CPU-only here
    arm_files = {a: os.path.join(FIDELITY, f"{a}.jsonl")
                for a in ("cowrie", "on_device", "cloud", "honeyrouter")}
    overall = {}
    for arm, path in arm_files.items():
        vals = defaultdict(list)
        for _fi, resp, gt in _load_valid(path):
            fm = _fast_metrics(resp, gt)
            for k, _ in fast_metrics:
                vals[k].append(fm[k])
        overall[arm] = {k: round(sum(v) / len(v), 4) for k, v in vals.items()}

    vals = defaultdict(list)
    for r in ml_rows:
        fm = _fast_metrics(r.get("response"), r.get("ground_truth"))
        for k, _ in fast_metrics:
            vals[k].append(fm[k])
    overall["ml_router"] = {k: round(sum(v) / len(v), 4) for k, v in vals.items()}

    print("\n" + "=" * 70)
    # "ml_router" is the dict key both callers and summarize_irt_router.py
    # already read, so it stays; the label says what actually routed.
    print("  FIDELITY — honeyrouter (regex) vs ml_router (honeyrouter policy)")
    print("=" * 70)
    print("  " + f"{'arm':<12}" + "".join(f"{lbl.split(' (')[0]:>13}" for _, lbl in fast_metrics))
    for arm in ("cowrie", "on_device", "cloud", "honeyrouter", "ml_router"):
        row = "  " + f"{arm:<12}"
        for k, _ in fast_metrics:
            row += f"{overall[arm][k]:>13.3f}"
        print(row)

    # cost: same primitives cost_analysis.py uses, called directly
    from cost.cost_model import gpu_avg_watt
    from cost.power_cost import kwh_to_thb
    from core.config_loader import load_config

    tariff = load_config().power_tariff
    gpu_w = gpu_avg_watt()
    usd_per_thb = 1 / 35.0

    cloud_rows = [json.loads(l) for l in open(arm_files["cloud"])]
    ond_rows = [json.loads(l) for l in open(arm_files["on_device"])]
    hr_rows = [json.loads(l) for l in open(arm_files["honeyrouter"])]
    key = lambda r: (str(r["session_id"]), r["position_in_session"])
    cost_lut = {key(r): r.get("cost") for r in cloud_rows}
    lat_lut = {key(r): r.get("inference_ms") for r in ond_rows}

    def cost_of(routed_lut):
        cloud_keys = [k for k, v in routed_lut.items() if v == "cloud"]
        od_keys = [k for k, v in routed_lut.items() if v == "on_device"]
        cloud_usd = sum(cost_lut.get(k) or 0 for k in cloud_keys)
        ms = sum(lat_lut.get(k) or 0 for k in od_keys)
        kwh = gpu_w * (ms / 1000 / 3600) / 1000.0
        thb = kwh_to_thb(kwh, tariff)["total_thb"] if kwh > 0 else 0.0
        return {"cloud_usd": round(cloud_usd, 6), "elec_kwh": round(kwh, 6),
                "elec_thb": round(thb, 4),
                "total_usd": round(cloud_usd + thb * usd_per_thb, 6)}

    hr_routed = {key(r): r["routed_to"] for r in hr_rows}
    ml_routed = {key(r): r["routed_to"] for r in ml_rows}
    cost = {"honeyrouter": cost_of(hr_routed), "ml_router": cost_of(ml_routed)}

    print("\n" + "=" * 70)
    print("  COST — honeyrouter (regex) vs ml_router (honeyrouter policy)")
    print("=" * 70)
    for a in ("honeyrouter", "ml_router"):
        c = cost[a]
        print(f"  {a:<12} cloud $ {c['cloud_usd']:.4f}  elec kWh {c['elec_kwh']:.4f}  "
              f"total $ {c['total_usd']:.4f}")

    return {"fidelity": overall, "cost": cost}


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--omega-sweep", dest="omegas",
                    default="0,0.5,1,1.5,2",
                    help="omega values to try, comma-separated. omega weights "
                         "-cost, so higher is cheaper; the range matches "
                         "reinforcement.py's training, omega ~ U(0, 2). This "
                         "is the paper's preference parameter -- it replaces "
                         "the hand-rolled lambda this file used to sweep.")
    for k in ("p1_epochs", "p2_steps", "p2_batch", "p3_steps"):
        ap.add_argument("--" + k.replace("_", "-"), type=int,
                        default=DEFAULTS[k], dest=k,
                        help=f"paper default {DEFAULTS[k]}")
    ap.add_argument("--no-rl", dest="run_rl", action="store_false",
                    default=DEFAULTS["run_rl"], help="skip phase 3 (PPO)")
    ap.add_argument("--no-mixup", dest="mixup", action="store_false",
                    default=DEFAULTS["mixup"], help="phase 3 without mixup")
    ap.add_argument("--reuse", action="store_true",
                    help="if this exact config was already trained, score the "
                         "existing model instead of retraining it")
    args = ap.parse_args()
    omegas = [float(x) for x in args.omegas.split(",")]

    cfg = {k: getattr(args, k) for k in
           ("p1_epochs", "p2_steps", "p2_batch", "p3_steps", "run_rl", "mixup")}
    h = config_hash(cfg)
    paper = {k: DEFAULTS[k] for k in cfg}
    run_dir = os.path.join(OUT_DIR, f"config_{h}")
    trained = os.path.isfile(os.path.join(run_dir, "routing_policy.pt"))

    print(f"config {h} -> {os.path.relpath(run_dir, _ROOT)}/")
    print(f"  {cfg}")
    if cfg != paper:
        print("  DEPARTS FROM THE PAPER: "
              + str({k: f"{v} (paper {paper[k]})"
                     for k, v in cfg.items() if v != paper[k]}))
    print("  production in honeyrouter/out/ is NOT touched\n", flush=True)

    os.makedirs(run_dir, exist_ok=True)
    # Before ANY honeyrouter stage module is imported, so predictor/
    # routing_policy/reinforcement resolve to this run's folder. cli.py froze
    # its own OUT_DIR at import, when the folder was not yet known, so that one
    # is repointed by hand -- _policy() checks for the artifacts there.
    os.environ["HONEYROUTER_OUT"] = run_dir
    HRCLI.OUT_DIR = run_dir
    HRCLI.STATE_PATH = os.path.join(run_dir, "router_state.json")

    t0 = time.time()
    if trained and args.reuse:
        print("[phases] already trained, --reuse given: scoring as-is\n")
        which = "rl" if os.path.isfile(
            os.path.join(run_dir, "routing_policy_rl.pt")) else "policy"
    else:
        which = train_phases(cfg, run_dir)
    train_sec = round(time.time() - t0, 1)

    with open(os.path.join(run_dir, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"hash": h, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "config": cfg, "paper_defaults": paper,
                   "departs_from_paper": cfg != paper,
                   "train_sec": train_sec, "policy": which}, fh, indent=2)

    pol = load_policy(which)
    if pol is None:
        raise SystemExit(f"training finished but no {which} policy in {run_dir}")

    print("[1/4] scoring every arm's real response against ground truth ...")
    cmds, scores, meta, rows = load_matrix()
    print(f"      {scores.shape[0]} commands x {scores.shape[1]} arms  "
          f"mean correctness: " + "  ".join(
              f"{a}={scores[:, j].mean():.3f}" for j, a in enumerate(ARMS)))
    print("      (reported only -- the policy was trained in honeyrouter/, "
          "nothing is fitted here)")

    print("[2/4] real per-arm cost basis ...")
    cost_norm, cost_raw = per_arm_cost(rows)
    print(f"      raw $/call:  " + "  ".join(f"{a}={c:.6f}" for a, c in cost_raw.items()))
    print(f"      normalized:  " + "  ".join(f"{a}={c:.4f}" for a, c in cost_norm.items()))
    print("      (reported only -- the policy weighs cost itself, via omega)")

    print("[3/4] aligning rows to the policy's build order ...")
    build_rows = rows_in_build_order()
    lut = arm_lookup()
    print(f"      {len(build_rows)} rows")

    import collections
    sweep = []
    for omega in omegas:
        print(f"\n[4/4] omega={omega} -- honeyrouter policy routes, then replay ...")
        picks, out = route_and_replay(pol, omega, build_rows, lut)
        dist = collections.Counter(picks)
        print(f"      routing distribution: {dict(dist)}  (n={len(out)})")

        # Inside THIS config's folder, so two configs cannot overwrite each
        # other's replay -- that is the whole point of the config_<hash> dir.
        out_dir = os.path.join(run_dir, f"omega_{omega}")
        os.makedirs(os.path.join(out_dir, "fidelity"), exist_ok=True)
        path = os.path.join(out_dir, "fidelity", "ml_router.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for row in out:
                fh.write(json.dumps(row) + "\n")

        comparison = score_vs_partc(out)
        sweep.append({"omega": omega, "n": len(out),
                      "routing_distribution": dict(dist), **comparison})

    print("\n" + "=" * 70)
    print("  OMEGA SWEEP -- fidelity (cosine) vs cost, honeyrouter policy")
    print("=" * 70)
    print(f"  {'omega':>7}{'cowrie':>9}{'on_device':>11}{'cloud':>8}"
          f"{'cosine':>9}{'total_usd':>11}")
    for s in sweep:
        d, f, c = s["routing_distribution"], s["fidelity"]["ml_router"], s["cost"]["ml_router"]
        print(f"  {s['omega']:>7.2f}{d.get('cowrie', 0):>9}{d.get('on_device', 0):>11}"
              f"{d.get('cloud', 0):>8}{f['cosine_score']:>9.3f}{c['total_usd']:>11.4f}")

    path = os.path.join(run_dir, "irt_model.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"hash": h, "config": cfg, "policy": which,
                   "train_sec": train_sec,
                   "routing": "honeyrouter.cli._picks (trained policy)",
                   "mean_cost_usd_raw": cost_raw,
                   "mean_cost_normalized": cost_norm,
                   "omega_sweep": sweep}, fh, indent=2)
    print(f"\nwrote {os.path.relpath(path, _ROOT)}")
    print(f"per-omega replays under "
          f"{os.path.relpath(run_dir, _ROOT)}/omega_<value>/fidelity/")


if __name__ == "__main__":
    main()
