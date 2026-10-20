"""
experiment_data/PartC/score/summarize_semantic.py — print the semantic-analysis table.

Reloads results/partC/semantic_analysis/all_metrics_scores.json (produced by
score_all_metrics.py) and prints per-arm metric means — no re-scoring.

Usage:
    python experiment_data/PartC/score/summarize_semantic.py            # overall
    python experiment_data/PartC/score/summarize_semantic.py --by-fi    # per FI band
"""
import argparse
import json
import os

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartC/
_ROOT = os.path.dirname(os.path.dirname(_HERE))
SCORES = os.path.join(_HERE, "..", "results", "partC", "semantic_analysis",
                      "all_metrics_scores.json")

ARMS = [("cowrie", "Pure Cowrie"), ("on_device", "Pure On-device"),
        ("cloud", "Pure Cloud"), ("honeyrouter", "HydraPoT")]
METRICS = [("cosine_score", "Cosine"), ("bert_f1", "BERT"),
           ("levenshtein_score", "Leven"), ("jaro_winkler_score", "Jaro"),
           ("sequence_score", "Seq"), ("bleu_score", "BLEU"),
           ("exact_match", "Exact")]


def _cell(v):
    return f"{v:>8.3f}" if isinstance(v, (int, float)) else f"{'-':>8}"


def _header():
    print(f"  {'arm':<16}" + "".join(f"{lbl:>8}" for _, lbl in METRICS))
    print("  " + "─" * (16 + 8 * len(METRICS)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--by-fi", action="store_true", help="break down per FI band")
    args = ap.parse_args()

    if not os.path.exists(SCORES):
        print(f"[summarize_semantic] not found: {os.path.relpath(SCORES, _ROOT)}")
        print("  run first: python experiment_data/PartC/score/score_all_metrics.py")
        raise SystemExit(1)

    data = json.load(open(SCORES))
    overall, per_band = data.get("overall", {}), data.get("per_band", {})

    print(f"[summarize_semantic] {os.path.relpath(SCORES, _ROOT)}")
    print("═" * (16 + 8 * len(METRICS) + 2))
    print("  PART C — SEMANTIC / FIDELITY METRICS (mean, 0–1 higher = more realistic)")
    print("═" * (16 + 8 * len(METRICS) + 2))

    if not args.by_fi:
        _header()
        for key, lbl in ARMS:
            row = overall.get(key, {})
            print(f"  {lbl:<16}" + "".join(_cell(row.get(m)) for m, _ in METRICS))
        return

    for fi in ["0", "1", "2", "3", "4"]:
        print(f"\n  ── FI band {fi} ──")
        _header()
        for key, lbl in ARMS:
            row = per_band.get(key, {})
            print(f"  {lbl:<16}"
                  + "".join(_cell(row.get(m, {}).get(fi)) for m, _ in METRICS))


if __name__ == "__main__":
    main()
