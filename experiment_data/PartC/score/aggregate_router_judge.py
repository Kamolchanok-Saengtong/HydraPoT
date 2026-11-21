"""
experiment_data/PartC/score/aggregate_router_judge.py -- judge scores per omega for a trained router.

Writes <config-dir>/review.json, the file summarize_honeyrouter_v2.py reads to
show its judge column:

    {"mode": "lookup", "sweep": [{"omega": 0.4, "judge": 3.52, "n": 2179}, ...]}

Two ways to get the number, both over the router's own picks:

  lookup (default)  Each routed command takes the recorded judge score of the agent
                    it picked, from the per-arm judge files the Part C run already
                    has. No new judge call, no cost -- and the SAME method that
                    gives the regex baseline its judge score, so the two compare.
  live              Reads the judge's scores for the router's own live responses,
                    from `llm_judge_score.py score` run on each omega's
                    fidelity/ folder with --arms ml_router (a paid pass).

    python experiment_data/PartC/score/aggregate_router_judge.py \\
        --config-dir experiment_data/results/partC_ml_router/vector_learn_gpqa
    python experiment_data/PartC/score/summarize_honeyrouter_v2.py \\
        --runs bench-learn+net=vector_learn_gpqa          # no --metrics: judge column on
"""
import argparse
import glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "run"))

JUDGE_FILE = "judge_scored_openai_gpt-6-luna.jsonl"       # llm_judge_score.py's default model


def _rows(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _key(row):
    return (str(row["session_id"]), row["position_in_session"])


def lookup_scores(fidelity):
    """{arm: {(session, position): judge score}} from the Part C per-arm judge files."""
    scores = {}
    for arm in ("cowrie", "on_device", "cloud"):
        path = os.path.join(fidelity, "judge", arm, JUDGE_FILE)
        scores[arm] = {_key(r): r["judge_score"] for r in _rows(path)
                       if r.get("judge_score") is not None}
    return scores


def mean_lookup(routed, table):
    got = [table[r["routed_to"]].get(_key(r)) for r in routed if r["routed_to"] in table]
    got = [g for g in got if g is not None]
    return (sum(got) / len(got), len(got)) if got else (None, 0)


def mean_live(omega_dir):
    path = os.path.join(omega_dir, "fidelity", "judge", "ml_router", JUDGE_FILE)
    if not os.path.isfile(path):
        return None, 0
    got = [r["judge_score"] for r in _rows(path) if r.get("judge_score") is not None]
    return (sum(got) / len(got), len(got)) if got else (None, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config-dir", required=True)
    ap.add_argument("--mode", choices=("lookup", "live"), default="lookup")
    args = ap.parse_args()

    from train_ml_router import FIDELITY
    table = lookup_scores(FIDELITY) if args.mode == "lookup" else None
    sweep = []
    for omega_dir in glob.glob(os.path.join(args.config_dir, "omega_*")):
        if not os.path.isdir(omega_dir):
            continue
        omega = float(os.path.basename(omega_dir)[len("omega_"):])
        routed_file = os.path.join(omega_dir, "fidelity", "ml_router.jsonl")
        if args.mode == "lookup":
            if not os.path.isfile(routed_file):
                continue
            judge, n = mean_lookup(_rows(routed_file), table)
        else:
            judge, n = mean_live(omega_dir)
        if judge is not None:
            sweep.append({"omega": omega, "judge": round(judge, 4), "n": n})
    sweep.sort(key=lambda p: p["omega"])
    out = os.path.join(args.config_dir, "review.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"mode": args.mode, "sweep": sweep}, fh, indent=1)
    print(f"{args.mode}: {len(sweep)} omega points -> {out}")
    for p in sweep:
        print(f"  omega {p['omega']:<5} judge {p['judge']:.3f}  (n={p['n']})")


if __name__ == "__main__":
    main()
