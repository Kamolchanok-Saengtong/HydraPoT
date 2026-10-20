"""
experiment_data/run_partA.py — thin CLI for the architecture-overhead measurement.

Runs the full mrheinen_linux_commands.json dataset (481 raw rows, compound
";"-joined lines kept intact) through 7 arms: cowrie/on_device/cloud each
run pure (zero HydraPoT involvement) and hydrapot (forced through main.py's
real pipeline), plus honeyrouter (natural routing via classify()). See
overhead.py's module docstring for the full arm breakdown.
"""

import os
import sys
import argparse
from datetime import datetime

# PartA/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
for p in (_ROOT, _NSC, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

# Donated keys (API_KEY_*) live in experiment_data/.env, separate from root .env.
from core.config_loader import load_dotenv
load_dotenv(os.path.join(_NSC, ".env"), override=True)

from agents import build_agents, pick_model
from overhead import run_overhead, ALL_MEASURES, make_arm_writers, ALL_ARMS
from workloads import load_mrheinen_raw


def _existing_max_trial(out_dir, arms=None):
    """Highest trial index already saved under out_dir (-1 if none).

    Scoped to `arms` when given: re-measuring one arm must continue ITS own
    trial numbering, not jump past trials only the other arms have.
    """
    import glob, json
    mx = -1
    globs = ([os.path.join(out_dir, a, f"{a}.jsonl") for a in arms] if arms
             else [os.path.join(out_dir, "*", "*.jsonl")])
    paths = [p for pat in globs for p in glob.glob(pat)]
    for p in paths:
        txt = open(p, encoding="utf-8").read()
        dec, i, n = json.JSONDecoder(), 0, len(txt)
        while i < n:
            while i < n and txt[i] in " \n\r\t":
                i += 1
            if i >= n:
                break
            try:
                o, i = dec.raw_decode(txt, i)
            except json.JSONDecodeError:
                break
            t = o.get("trial")
            if isinstance(t, int):
                mx = max(mx, t)
    return mx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms",         type=str,  default=None,
                    help="comma-separated subset of arms to measure "
                         "(default: all 7). e.g. --arms standalone_local")
    ap.add_argument("--trials",       type=int,  default=1)
    ap.add_argument("--warmup",       type=int,  default=3)
    ap.add_argument("--model",        type=str,  default=None,
                    help="on-device model id to use (overrides config)")
    ap.add_argument("--pick-model",   action="store_true",
                    help="interactively choose a cached on-device model")
    args = ap.parse_args()

    run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(_HERE, "..", "results", "partA")
    os.makedirs(out_dir, exist_ok=True)

    # ── agents (moved up — workload construction now needs ag.scorer) ───────
    model_override = args.model
    if args.pick_model and not model_override:
        model_override = pick_model()
    ag = build_agents(connect_cowrie=True, model_override=model_override)

    # ── workload: the raw dataset, exactly as it sits on disk ───────────────
    cmds   = load_mrheinen_raw()
    sample = [(ag.scorer.score(c)[0], c) for c in cmds]
    print(f"[NSC-A] mrheinen workload (raw, unsplit): {len(sample)} commands")

    n_arms = len(ALL_ARMS)
    print(f"[NSC-A] {len(sample)} total commands x {args.trials} trials "
          f"x {n_arms} arms -> {os.path.join(out_dir, 'architecture_overhead')}")

    # ── run ───────────────────────────────────────────────────────────────────
    # New trials extend the existing files — number them after what's on disk.
    sel_arms = ([a.strip() for a in args.arms.split(",") if a.strip()]
                if args.arms else None)
    if sel_arms:
        print(f"[NSC-A] measuring ONLY: {', '.join(sel_arms)}")
    trial_offset = _existing_max_trial(out_dir, sel_arms) + 1
    if trial_offset:
        print(f"[NSC-A] extending: {trial_offset} trial(s) already on disk, "
              f"new trials numbered {trial_offset}..{trial_offset + args.trials - 1}")

    writer_fn, close_writers = make_arm_writers(out_dir, run_id, sel_arms)
    def write_rec(rec):
        rec["run_id"] = run_id
        writer_fn(rec)

    run_overhead(
        ag, sample,
        trials=args.trials,
        measures=ALL_MEASURES,
        warmup=args.warmup,
        on_record=write_rec,
        trial_offset=trial_offset,
        arms=sel_arms,
    )
    close_writers()

    try:
        ag.cowrie.disconnect()
    except Exception:
        pass

    # ── summary ───────────────────────────────────────────────────────────────
    print(f"\n[NSC-A] done -> {out_dir}")
    for arm in ALL_ARMS:
        print(f"[NSC-A]   {arm}/{arm}.jsonl")
    print(f"\n[NSC-A] experiment summary:")
    print(f"[NSC-A]   run_id       {run_id}")
    print(f"[NSC-A]   commands     {len(sample)}")
    print(f"[NSC-A]   trials       {args.trials}")
    print(f"[NSC-A]   arms         {n_arms} ({', '.join(ALL_ARMS)})")
    print(f"[NSC-A]   measurements {len(sample) * args.trials * n_arms:,}")
    print(f"[NSC-A]   workload     mrheinen_linux_commands.json (raw, 481 rows)")
    print(f"[NSC-A] next: python experiment_data/PartA/score/summarize_partA.py")


if __name__ == "__main__":
    main()