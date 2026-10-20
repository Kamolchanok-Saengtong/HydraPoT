"""
experiment_data/PartC/plot/plot_judge_by_fi.py — judge realism score by FI band.

Reads results/partC/fidelity/judge/<arm>/judge_scored_*.jsonl for each arm and
plots mean judge score (1-5) per FI band, same house style as
score_all_metrics.py's all_metrics_by_fi.png.

    python experiment_data/PartC/plot/plot_judge_by_fi.py

Output -> results/partC/semantic_analysis/judge_score_by_fi.png (+ .pdf)
"""
import glob
import json
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y",
    "grid.color": "#E0E0E0", "grid.linewidth": 0.7,
    "savefig.dpi": 300, "figure.dpi": 150,
})

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartC/
_ROOT = os.path.dirname(os.path.dirname(_HERE))
JUDGE_DIR = os.path.join(_HERE, "..", "results", "partC", "fidelity", "judge")
OUT_DIR = os.path.join(_HERE, "..", "results", "partC", "semantic_analysis")

ARM_ORDER = ["cowrie", "on_device", "cloud", "honeyrouter"]
ARM_COLOR = {"cowrie": "#AAAAAA", "on_device": "#7EB3C8",
             "cloud": "#5B7FA6", "honeyrouter": "#E07B39"}
ARM_LABEL = {"cowrie": "Pure Cowrie", "on_device": "Pure On-device LLM",
             "cloud": "Pure Cloud LLM", "honeyrouter": "HydraPoT"}
FI_BANDS = [0, 1, 2, 3, 4]

_SUBSCRIPT = str.maketrans("0123456789", "\u2080\u2081\u2082\u2083\u2084\u2085\u2086\u2087\u2088\u2089")


def _fi_label(fi) -> str:
    """F with a Unicode subscript digit, matching plot_metrics_separate.py."""
    return "F" + str(fi).translate(_SUBSCRIPT)


def _latest_scored_file(arm):
    matches = glob.glob(os.path.join(JUDGE_DIR, arm, "judge_scored_*.jsonl"))
    return max(matches, key=os.path.getmtime) if matches else None


def _load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    by_fi = {arm: defaultdict(list) for arm in ARM_ORDER}
    for arm in ARM_ORDER:
        path = _latest_scored_file(arm)
        if not path:
            print(f"[plot_judge] no judge output for {arm} — skipping")
            continue
        for r in _load(path):
            score = r.get("judge_score")
            fi = r.get("fi_score")
            if score is not None and fi in FI_BANDS:
                by_fi[arm][fi].append(score)

    if not any(by_fi[arm] for arm in ARM_ORDER):
        print(f"[plot_judge] no judge data found under {os.path.relpath(JUDGE_DIR, _ROOT)}/")
        print("  run first: python experiment_data/PartC/judge/llm_judge_score.py score ...")
        raise SystemExit(1)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = np.arange(len(FI_BANDS))
    w = 0.8 / len(ARM_ORDER)
    for i, arm in enumerate(ARM_ORDER):
        vals = [sum(by_fi[arm][fi]) / len(by_fi[arm][fi]) if by_fi[arm][fi] else 0
                for fi in FI_BANDS]
        offset = (i - (len(ARM_ORDER) - 1) / 2) * w
        ax.bar(x + offset, vals, w, label=ARM_LABEL[arm], color=ARM_COLOR[arm],
               edgecolor="white", linewidth=0.6)

    # No title, no legend, no axis label — the paper's caption carries them,
    # same convention as plot_metrics_separate.py.
    ax.set_xticks(x)
    ax.set_xticklabels([_fi_label(fi) for fi in FI_BANDS], fontsize=18)
    ax.tick_params(axis="y", labelsize=15)
    ax.set_ylim(0, 5.3)
    fig.tight_layout()

    os.makedirs(OUT_DIR, exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT_DIR, f"judge_score_by_fi.{ext}"), dpi=300, bbox_inches="tight")
    print(f"[plot_judge] saved {os.path.relpath(OUT_DIR, _ROOT)}/judge_score_by_fi.png (+ .pdf)")
    plt.close(fig)

    # ── companion figure: one bar per agent, pooled over every FI band ────────
    # Pooled over commands, not an average of the five band means: the bands hold
    # very different counts (FI0 alone is ~60% of the dataset), so averaging the
    # means would silently weight a 151-command band like a 1,300-command one.
    fig, ax = plt.subplots(figsize=(7.2, 5.4))
    overall = {arm: [s for fi in FI_BANDS for s in by_fi[arm][fi]] for arm in ARM_ORDER}
    xs = np.arange(len(ARM_ORDER))
    vals = [sum(overall[a]) / len(overall[a]) if overall[a] else 0 for a in ARM_ORDER]
    ax.bar(xs, vals, 0.6, color=[ARM_COLOR[a] for a in ARM_ORDER],
           edgecolor="white", linewidth=0.6)
    for xi, v in zip(xs, vals):
        ax.text(xi, v + 0.08, f"{v:.2f}", ha="center", va="bottom", fontsize=15)
    ax.set_xticks(xs)
    ax.set_xticklabels([ARM_LABEL[a] for a in ARM_ORDER], fontsize=13)
    ax.tick_params(axis="y", labelsize=15)
    ax.set_ylim(0, 5.3)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT_DIR, f"judge_score_overall.{ext}"),
                    dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot_judge] saved {os.path.relpath(OUT_DIR, _ROOT)}/judge_score_overall.png (+ .pdf)")
    for a, v in zip(ARM_ORDER, vals):
        print(f"[plot_judge]   {ARM_LABEL[a]:<22} {v:.3f}   n={len(overall[a]):,}")


if __name__ == "__main__":
    main()
