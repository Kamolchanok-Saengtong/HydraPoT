"""
experiment_data/PartC/plot_metrics_separate.py — one standalone PDF/PNG per fidelity metric,
plus a combined all-in-one PDF/PNG (no overarching caption — per-metric titles
kept, since those are needed to tell the individual files apart).

Reads the CURRENT, already-computed all_metrics_scores.json (no rescoring) —
whatever score_all_metrics.py last produced (deepseek-v4-flash cloud, F4
patched with qwen3.6-plus per the current setup).

    python experiment_data/PartC/plot_metrics_separate.py

Outputs -> results/honeyrouter_replay_latest/all_metrics_separate/:
    cosine_similarity.pdf / .png
    bertscore.pdf / .png
    levenshtein.pdf / .png
    jaro_winkler.pdf / .png
    sequence.pdf / .png
    bleu.pdf / .png
    exact_match.pdf / .png
    all_metrics_combined.pdf / .png   (no top caption, per-metric titles kept)
─────────────────────────────────────────────────────────────────────────────────
"""
import sys
import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(_HERE, "..", "results", "partC", "semantic_analysis")
SCORES = os.path.join(OUT_DIR, "all_metrics_scores.json")

# BERTScore is the one metric that needs the GPU to (re)compute, so it can be the
# one stale number in an otherwise fresh file. --no-bert leaves it out of both the
# per-metric figures and the combined grid.
SKIP_BERT = "--no-bert" in sys.argv
SEP_DIR = os.path.join(OUT_DIR, "all_metrics_separate")
os.makedirs(SEP_DIR, exist_ok=True)

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 16,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y",
    "grid.color": "#E0E0E0", "grid.linewidth": 0.7,
    "savefig.dpi": 300, "figure.dpi": 150,
})

METRICS = [
    ("cosine_score",       "Cosine Similarity",  "cosine_similarity"),
    ("bert_f1",            "BERTScore",          "bertscore"),
    ("levenshtein_score",  "Levenshtein",        "levenshtein"),
    ("jaro_winkler_score", "Jaro-Winkler",       "jaro_winkler"),
    ("sequence_score",     "Sequence",           "sequence"),
    ("bleu_score",         "BLEU",               "bleu"),
    ("exact_match",        "Exact match",        "exact_match"),
]
ARM_ORDER = ["cowrie", "on_device", "cloud", "honeyrouter"]
ARM_COLOR = {"cowrie": "#AAAAAA", "on_device": "#7EB3C8", "cloud": "#5B7FA6", "honeyrouter": "#E07B39"}
ARM_LABEL = {"cowrie": "Pure Cowrie", "on_device": "Pure On-device LLM", "cloud": "Pure Cloud LLM", "honeyrouter": "HydraPoT"}
FI_BANDS = [0, 1, 2, 3, 4]


_SUBSCRIPT = str.maketrans("0123456789", "\u2080\u2081\u2082\u2083\u2084\u2085\u2086\u2087\u2088\u2089")


def _fi_label(fi) -> str:
    """FI band as F with a Unicode subscript digit — F\u2080, F\u2081, ... — matching the
    paper's $F_0$ rather than the literal string 'FI0'."""
    return "F" + str(fi).translate(_SUBSCRIPT)


def _draw(ax, metric, label, summary):
    x = np.arange(len(FI_BANDS))
    w = 0.8 / len(ARM_ORDER)
    for i, arm in enumerate(ARM_ORDER):
        vals = [summary[arm][metric].get(str(fi)) or 0 for fi in FI_BANDS]
        offset = (i - (len(ARM_ORDER) - 1) / 2) * w
        ax.bar(x + offset, vals, w, label=ARM_LABEL[arm], color=ARM_COLOR[arm],
               edgecolor="white", linewidth=0.6)
    ax.set_xticks(x)
    # F with a real subscript digit (F₀ … F₄) so the figure matches the
    # paper's $F_0$ notation instead of reading as the literal text "FI0".
    ax.set_xticklabels([_fi_label(fi) for fi in FI_BANDS], fontsize=18)
    ax.tick_params(axis="y", labelsize=15)
    ax.set_ylim(0, 1.05)


def main():
    d = json.load(open(SCORES))
    if SKIP_BERT:
        global METRICS
        METRICS = [m for m in METRICS if m[0] != "bert_f1"]
    summary = d["per_band"]

    # ── one standalone file per metric ─────────────────────────────────────────
    for metric, label, slug in METRICS:
        fig, ax = plt.subplots(figsize=(7.2, 5.4))
        _draw(ax, metric, label, summary)
        fig.tight_layout()
        png = os.path.join(SEP_DIR, f"{slug}.png")
        pdf = os.path.join(SEP_DIR, f"{slug}.pdf")
        fig.savefig(png, dpi=300, bbox_inches="tight")
        fig.savefig(pdf, bbox_inches="tight")
        plt.close(fig)
        print(f"saved {png}")
        print(f"saved {pdf}")

    # ── combined grid, no overarching caption ───────────────────────────────────
    ncol = 4
    nrow = (len(METRICS) + ncol - 1) // ncol
    fig, axes = plt.subplots(nrow, ncol, figsize=(4.9 * ncol, 4.4 * nrow))
    axes = axes.flatten()
    for ax, (metric, label, _) in zip(axes, METRICS):
        _draw(ax, metric, label, summary)
    for ax in axes[len(METRICS):]:
        ax.axis("off")
    fig.tight_layout()
    png = os.path.join(SEP_DIR, "all_metrics_combined.png")
    pdf = os.path.join(SEP_DIR, "all_metrics_combined.pdf")
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    print(f"saved {png}")
    print(f"saved {pdf}")


if __name__ == "__main__":
    main()
