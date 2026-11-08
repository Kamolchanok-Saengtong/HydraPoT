"""
experiment_data/PartC/score/summarize_honeyrouter_v2.py — HoneyRouter v2 runs,
one table each and a paper-vs-benchmark comparison.

v2 replaces the IRT ability model of the earlier router with a looked-up
published benchmark score as the Phase-1 axis (predictor.py). Two axes were
trained, and this lays them side by side:

    paper      vector_paper   Terminal-Bench 2.1 (the paper's own axis)
    benchmark  vector_gpqa    GPQA Diamond (general-intelligence axis)

Reads only what each run already wrote under results/partC_ml_router/<run>/:
  omega_sweep.json   routing mix + 6-metric semantic fidelity + cost, per omega
  review.json        LLM-judge scores (OPTIONAL) -- shown only if present

Nothing is recomputed or retrained; this reads the trained runs' output. The
judge table is optional on purpose: the sweep file alone carries the routing
mix and cost, which is what the axis comparison turns on, so the summary runs
without a judge pass.

    python experiment_data/PartC/score/summarize_honeyrouter_v2.py
    python experiment_data/PartC/score/summarize_honeyrouter_v2.py \
        --runs paper=vector_paper benchmark=vector_gpqa
"""
import argparse
import json
import os

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # PartC/
_REPO = os.path.join(_HERE, "..", "..")
ML_ROUTER = os.path.join(_HERE, "..", "results", "partC_ml_router")

# label -> run folder. Order is the display order. The two axes v2 was trained
# on; override with --runs to summarise others.
DEFAULT_RUNS = [("paper", "vector_paper"), ("benchmark", "vector_gpqa")]

ARMS = ("cowrie", "on_device", "cloud")
METRICS = [("cosine_score", "Cosine"), ("levenshtein_score", "Lev"),
           ("jaro_winkler_score", "JW"), ("sequence_score", "Seq"),
           ("bleu_score", "BLEU"), ("exact_match", "Exact")]


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _resolve(run: str) -> str:
    """A --runs value: an absolute/relative path if it points at a folder,
    otherwise a bare run name under results/partC_ml_router/."""
    if os.path.isdir(run):
        return run
    return os.path.join(ML_ROUTER, run)


def load_sweep(run_dir: str) -> list:
    """The omega sweep rows (omega, routing_distribution, fidelity, cost, n).

    v2 writes omega_sweep.json; the pre-split layout left the same rows in
    irt_model.json, so that is accepted as a fallback rather than failing a run
    trained before training and evaluation were separated.
    """
    for name in ("omega_sweep.json", "irt_model.json"):
        path = os.path.join(run_dir, name)
        if os.path.isfile(path):
            m = _read(path)
            if "omega_sweep" in m:
                return m["omega_sweep"]
    rel = os.path.relpath(run_dir, _REPO)
    raise SystemExit(
        f"no sweep in {rel}/ -- expected omega_sweep.json.\n"
        f"  Produce one from the trained model (no retraining):\n"
        f"    python experiment_data/PartC/score/eval_irt_sweep.py \\\n"
        f"        --config-dir {rel} --omega-sweep 0,0.5,1,1.5,2")


def load_review(run_dir: str):
    """Judge scores, or None. Optional: unlike the sweep, the judge is a
    separate paid pass, and the axis comparison does not need it."""
    path = os.path.join(run_dir, "review.json")
    return _read(path) if os.path.isfile(path) else None


def regex_judge():
    """Mean judge score for the regex HoneyRouter, by looking up each routed
    row's real judge score -- no new judge call. Shared by every run (the
    regex baseline does not depend on the trained axis), so computed once.
    Returns None if the judge files are not present."""
    import sys
    sys.path.insert(0, os.path.join(_HERE, "run"))
    try:
        from train_ml_router import ARMS as _ARMS, FIDELITY
    except Exception:
        return None

    judge = {a: {} for a in _ARMS}
    try:
        for a in _ARMS:
            path = os.path.join(FIDELITY, "judge", a,
                                "judge_scored_openai_gpt-6-luna.jsonl")
            for r in (json.loads(l) for l in open(path)):
                if r.get("judge_score") is not None:
                    judge[a][(str(r["session_id"]), r["position_in_session"])] = \
                        r["judge_score"]
        hr = [json.loads(l) for l in
              open(os.path.join(FIDELITY, "honeyrouter.jsonl"))]
    except FileNotFoundError:
        return None
    scores = [judge[r["routed_to"]].get((str(r["session_id"]),
                                         r["position_in_session"]))
              for r in hr if r["routed_to"] in judge]
    scores = [s for s in scores if s is not None]
    return sum(scores) / len(scores) if scores else None


def _savings(cost, baseline):
    return (1 - cost / baseline) * 100 if baseline else 0.0


def summarize_run(label: str, run_dir: str, hr_judge=None):
    """One run: per-omega arm mix, cost, savings vs the regex baseline, and
    ml_router cosine fidelity. Judge column appears only if review.json exists.
    Returns the sweep rows so the caller can compare runs."""
    sweep = load_sweep(run_dir)
    review = load_review(run_dir)
    judge_by_omega = ({r["omega"]: r["judge"] for r in review["sweep"]}
                      if review else {})

    n = sweep[0].get("n")
    baseline = sweep[0]["cost"]["honeyrouter"]["total_usd"]
    rel = os.path.relpath(run_dir, _REPO)

    print("=" * 84)
    print(f"  {label.upper()}   ({rel}, n={n} commands)")
    print(f"  regex HoneyRouter baseline: ${baseline:.4f}"
          + (f"   judge {hr_judge:.3f}" if hr_judge is not None else ""))
    print("=" * 84)
    judge_hdr = f"{'judge':>7}" if review else ""
    print(f"  {'omega':>5} | {'cowrie':>12} {'on_device':>12} {'cloud':>11} | "
          f"{'cost $':>8} {'save':>6} {'cosine':>7}{judge_hdr}")
    print("  " + "-" * 78)
    for r in sweep:
        rd = r["routing_distribution"]
        c, o, cl = rd.get("cowrie", 0), rd.get("on_device", 0), rd.get("cloud", 0)
        cost = r["cost"]["ml_router"]["total_usd"]
        cos = r["fidelity"]["ml_router"]["cosine_score"]
        line = (f"  {r['omega']:>5} | "
                f"{c:>5} ({100*c/n:>4.1f}%) {o:>5} ({100*o/n:>4.1f}%) "
                f"{cl:>4} ({100*cl/n:>4.1f}%) | "
                f"{cost:>8.4f} {_savings(cost, baseline):>5.0f}% {cos:>7.3f}")
        if review:
            jv = judge_by_omega.get(r["omega"])
            line += f"{jv:>7.3f}" if jv is not None else f"{'-':>7}"
        print(line)
    print()
    return sweep


def compare_runs(summaries: dict):
    """Paper vs benchmark at matched omegas: the point of v2's axis switch is
    whether on_device becomes a real choice, so that column leads."""
    if len(summaries) < 2:
        return
    labels = list(summaries)
    omegas = [r["omega"] for r in next(iter(summaries.values()))]

    print("=" * 84)
    print(f"  COMPARISON  ({'  vs  '.join(labels)})   on_device usage + cost")
    print("=" * 84)
    head = f"  {'omega':>5} |"
    for lab in labels:
        head += f" {lab + ' on_dev':>14} {lab + ' $':>10} |"
    print(head)
    print("  " + "-" * (len(head) - 2))
    by = {lab: {r["omega"]: r for r in sw} for lab, sw in summaries.items()}
    for om in omegas:
        line = f"  {om:>5} |"
        for lab in labels:
            r = by[lab].get(om)
            if r is None:
                line += f" {'-':>14} {'-':>10} |"
                continue
            o = r["routing_distribution"].get("on_device", 0)
            n = r["n"]
            cost = r["cost"]["ml_router"]["total_usd"]
            line += f" {o:>6} ({100*o/n:>4.1f}%) {cost:>10.4f} |"
        print(line)
    print()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", nargs="+", metavar="LABEL=RUN",
                    help="label=run pairs; run is a folder name under "
                         "results/partC_ml_router/ or a path. Default: "
                         "paper=vector_paper benchmark=vector_gpqa")
    args = ap.parse_args()

    if args.runs:
        runs = []
        for spec in args.runs:
            if "=" not in spec:
                raise SystemExit(f"--runs wants LABEL=RUN, got {spec!r}")
            lab, run = spec.split("=", 1)
            runs.append((lab, run))
    else:
        runs = DEFAULT_RUNS

    hr_judge = regex_judge()
    summaries = {}
    for label, run in runs:
        summaries[label] = summarize_run(label, _resolve(run), hr_judge)

    compare_runs(summaries)


if __name__ == "__main__":
    main()
