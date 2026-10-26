"""
experiment_data/PartC/score/summarize_irt_router.py — regex HoneyRouter vs the
trained IRT/NN/PPO router, one table.

Reads only what train_honeyrouter_irt.sh already wrote under
results/partC/honeyrouter_irt/ (review.json from cli.py --review,
sweep_semantic_and_judge.json from eval_irt_sweep.py) -- nothing here is
recomputed, this just lays both runs' numbers next to each other.

    python experiment_data/PartC/score/summarize_irt_router.py
"""
import argparse
import json
import os

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # PartC/
IRT_DIR = os.path.join(_HERE, "..", "results", "partC", "honeyrouter_irt")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_sweep(d):
    """The omega sweep, from whichever file the run actually wrote.

    Two scripts produce the same sweep under different names:
      eval_irt_sweep.py    -> sweep_semantic_and_judge.json  {"sweep": [...]}
      train_ml_router.py   -> irt_model.json                 {"omega_sweep": [...]}
    The rows are the same shape either way (omega, routing_distribution,
    fidelity, cost), so this reads either rather than making the caller
    produce a particular filename.
    """
    a = os.path.join(d, "sweep_semantic_and_judge.json")
    if os.path.isfile(a):
        return _read(a)
    b = os.path.join(d, "irt_model.json")
    if os.path.isfile(b):
        m = _read(b)
        return {"policy": m.get("policy", "rl"), "sweep": m["omega_sweep"]}
    rel = os.path.relpath(d, os.path.join(_HERE, "..", ".."))
    raise SystemExit(
        f"no sweep in {rel}/ -- expected sweep_semantic_and_judge.json or "
        f"irt_model.json.\n  Produce one with:\n"
        f"    python experiment_data/PartC/run/train_ml_router.py")


def _load_review(d):
    """Judge scores per pure arm and per omega, from cli.py --review."""
    path = os.path.join(d, "review.json")
    if os.path.isfile(path):
        return _read(path)
    rel = os.path.relpath(d, os.path.join(_HERE, "..", ".."))
    raise SystemExit(
        f"missing {rel}/review.json -- it holds the judge scores.\n"
        f"  Produce it with:\n"
        f"    HONEYROUTER_OUT=$PWD/{rel} python -c \"import json,sys;"
        f"sys.path.insert(0,'.');from honeyrouter.cli import sweep,baselines;"
        f"json.dump({{'sweep':sweep('rl',points=5),'baselines':baselines()}},"
        f"open('{rel}/review.json','w'),indent=2)\"")

METRICS = [("cosine_score", "Cosine"), ("levenshtein_score", "Lev"),
           ("jaro_winkler_score", "JW"), ("sequence_score", "Seq"),
           ("bleu_score", "BLEU"), ("exact_match", "Exact")]


def regex_honeyrouter_judge():
    """Mean judge score for the regex router -- not in cli.py's baselines(),
    which only covers the 3 pure arms and the trained policy. Same lookup:
    fidelity/honeyrouter.jsonl's routed_to per row -> that arm's real judge
    score, no new judge call."""
    import sys
    sys.path.insert(0, os.path.join(_HERE, "run"))
    from train_ml_router import ARMS, FIDELITY

    judge = {a: {} for a in ARMS}
    for a in ARMS:
        path = os.path.join(FIDELITY, "judge", a, "judge_scored_openai_gpt-6-luna.jsonl")
        for r in (json.loads(l) for l in open(path)):
            if r.get("judge_score") is not None:
                judge[a][(str(r["session_id"]), r["position_in_session"])] = r["judge_score"]

    # one row routes to "unknown" (a bare "./" -- no arm handled it), skipped
    hr = [json.loads(l) for l in open(os.path.join(FIDELITY, "honeyrouter.jsonl"))]
    scores = [judge[r["routed_to"]].get((str(r["session_id"]), r["position_in_session"]))
             for r in hr if r["routed_to"] in judge]
    scores = [s for s in scores if s is not None]
    return sum(scores) / len(scores) if scores else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=IRT_DIR,
                    help="folder holding the run's output. Defaults to "
                         "results/partC/honeyrouter_irt (the production run); "
                         "point it at a results/partC_ml_router/config_<hash>/ "
                         "to summarise one config instead.")
    d = ap.parse_args().dir

    review = _load_review(d)
    semantic = _load_sweep(d)
    hr_judge = regex_honeyrouter_judge()

    print("=" * 96)
    print("  REGEX HoneyRouter vs trained IRT/NN/PPO router -- judge score (1-5) + cost")
    print("=" * 96)
    print(f"  {'policy':<20}{'judge':>8}{'cost $':>10}  mix")
    for b in review["baselines"]:
        print(f"  {b['name']:<20}{b['judge']:>8.3f}{b['cost']:>10.4f}")
    for r in review["sweep"]:
        mix = " ".join(f"{a}={n}" for a, n in r["mix"].items())
        print(f"  {'rl @ w=' + str(r['omega']):<20}{r['judge']:>8.3f}{r['cost']:>10.4f}  {mix}")

    # judge score per pure arm comes from baselines(); per-omega comes from
    # the rl sweep -- both already real judge_scored_openai_gpt-6-luna.jsonl
    # lookups, not recomputed here. The semantic file's cost dict only has
    # honeyrouter/ml_router (the two it actually routes), so a pure arm's
    # cost is read from review.json's baselines instead.
    judge_by_arm = {b["name"].replace("always ", ""): b["judge"] for b in review["baselines"]}
    cost_by_arm = {b["name"].replace("always ", ""): b["cost"] for b in review["baselines"]}
    judge_by_omega = {r["omega"]: r["judge"] for r in review["sweep"]}

    print("\n" + "=" * 96)
    print("  Same comparison + real LLM-judge score (1-5), 6-metric semantic fidelity")
    print("=" * 96)
    header = (f"  {'arm':<22}{'judge':>7}" + "".join(f"{lbl:>9}" for _, lbl in METRICS)
             + f"{'cost $':>10}")
    print(header)

    first = semantic["sweep"][0]
    for arm in ("cowrie", "on_device", "cloud"):
        f = first["fidelity"][arm]
        row = f"  {arm:<22}{judge_by_arm.get(arm, float('nan')):>7.3f}"
        row += "".join(f"{f[k]:>9.3f}" for k, _ in METRICS)
        print(row + f"{cost_by_arm.get(arm, 0.0):>10.4f}")

    f, c = first["fidelity"]["honeyrouter"], first["cost"]["honeyrouter"]
    hr_j_str = f"{hr_judge:>7.3f}" if hr_judge is not None else f"{'-':>7}"
    row = f"  {'honeyrouter (regex)':<22}{hr_j_str}" + "".join(f"{f[k]:>9.3f}" for k, _ in METRICS)
    print(row + f"{c['total_usd']:>10.4f}")

    for s in semantic["sweep"]:
        f, c = s["fidelity"]["ml_router"], s["cost"]["ml_router"]
        label = f"irt_router @ w={s['omega']}"
        row = f"  {label:<22}{judge_by_omega.get(s['omega'], float('nan')):>7.3f}"
        row += "".join(f"{f[k]:>9.3f}" for k, _ in METRICS)
        print(row + f"{c['total_usd']:>10.4f}")

    cheapest = min(semantic["sweep"], key=lambda s: s["cost"]["ml_router"]["total_usd"])
    hr_cost = first["cost"]["honeyrouter"]["total_usd"]
    saved = (1 - cheapest["cost"]["ml_router"]["total_usd"] / hr_cost) * 100 if hr_cost else 0
    print(f"\n  at w={cheapest['omega']}: {saved:.0f}% cheaper than regex HoneyRouter, "
          f"cosine {cheapest['fidelity']['ml_router']['cosine_score']:.3f} vs "
          f"regex's {first['fidelity']['honeyrouter']['cosine_score']:.3f}")


if __name__ == "__main__":
    main()
