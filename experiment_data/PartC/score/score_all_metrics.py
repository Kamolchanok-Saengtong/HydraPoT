"""
experiment_data/PartC/score_all_metrics.py — score the 4 arms on ALL fidelity metrics + plot.
─────────────────────────────────────────────────────────────────────────────────
Full metric suite (not just syntax):
    SEMANTIC : cosine (TF-IDF), bert_f1 (BERTScore, GPU-batched)
    SYNTAX   : levenshtein, jaro_winkler, sequence   (rapidfuzz, == fidelity.py)
    N-GRAM   : bleu
    EXACT    : exact_match
for cowrie / on_device / cloud / honeyrouter, grouped by FI band.

Reuses the HoneyRouter replay at results/honeyrouter_replay_latest/honeyrouter.jsonl
(runs replay_honeyrouter.py first only if it's missing). Same normalize_pair() +
empty-string handling as evaluation/fidelity.py, so values line up with the rest
of Part C.

Run (safe on `screen` — BERTScore uses the now-free GPU):
    python experiment_data/PartC/score_all_metrics.py

Outputs -> results/honeyrouter_replay_latest/:
    all_metrics_by_fi.png     grid, one grouped-bar chart per metric (house style)
    all_metrics_scores.json   per-band + overall means
─────────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
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

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "evaluation"))

from rapidfuzz.distance import Levenshtein, Indel, JaroWinkler   # noqa: E402
from normalization import normalize_pair                          # noqa: E402
from fidelity import (                                            # noqa: E402
    cosine_score_response, bleu_score_response, _bert_scorer,
)

RESULTS  = os.path.join(_HERE, "..", "results", "partC")
FIDELITY = os.path.join(RESULTS, "fidelity")              # the current run's arm files
OUT_DIR  = os.path.join(RESULTS, "semantic_analysis")
ARM_FILES = {
    "cowrie":      os.path.join(FIDELITY, "cowrie.jsonl"),
    "on_device":   os.path.join(FIDELITY, "on_device.jsonl"),
    "cloud":       os.path.join(FIDELITY, "cloud.jsonl"),
    "honeyrouter": os.path.join(FIDELITY, "honeyrouter.jsonl"),
}

# plot order / grouping label -> (key, nice label)
METRICS = [
    ("cosine_score",       "Cosine Similarity"),
    ("bert_f1",            "BERTScore"),
    ("levenshtein_score",  "Levenshtein"),
    ("jaro_winkler_score", "Jaro-Winkler"),
    ("sequence_score",     "Sequence"),
    ("bleu_score",         "BLEU"),
    ("exact_match",        "Exact match"),
]
ARM_ORDER = ["cowrie", "on_device", "cloud", "honeyrouter"]

# BERTScore is the ONLY metric that needs the GPU. --no-bert drops it so the six
# CPU metrics can still be rescored while a measurement run holds the GPU.
SKIP_BERT = "--no-bert" in sys.argv
if SKIP_BERT:
    METRICS = [m for m in METRICS if m[0] != "bert_f1"]
ARM_COLOR = {"cowrie": "#AAAAAA", "on_device": "#7EB3C8",
             "cloud": "#5B7FA6", "honeyrouter": "#E07B39"}
ARM_LABEL = {"cowrie": "Pure Cowrie", "on_device": "Pure On-device LLM",
             "cloud": "Pure Cloud LLM", "honeyrouter": "HydraPoT"}
FI_BANDS = [0, 1, 2, 3, 4]


# A handful of captured sessions carry junk/fuzz payloads tens of thousands of
# chars long (e.g. a repeated "PuTTY..." spam string) in response/ground_truth.
# Left uncapped these dominate TF-IDF cosine and bloat BERTScore's GPU batch —
# clip before scoring, same cap the judge already uses on cmd/response.
_MAX_SCORE_CHARS = 2000


def _clip(text):
    if not isinstance(text, str) or len(text) <= _MAX_SCORE_CHARS:
        return text
    return text[:_MAX_SCORE_CHARS]


def _load_valid(path):
    """Yield (fi, resp, gt) for scorable rows (skip missing/ not-ok/ cloud-error)."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            gt, fi, resp = r.get("ground_truth"), r.get("fi_score"), r.get("response")
            if gt is None or fi is None or resp is None or not r.get("ok"):
                continue
            if isinstance(resp, str) and resp.startswith("[cloud error"):
                continue
            yield fi, _clip(resp), _clip(gt)


def _fast_metrics(resp, gt):
    """cosine, bleu, lev, jaro, seq, exact — same edge handling as fidelity.py.

    exact_match compares NORMALIZED text (like every other metric here), so a
    response differing only in a masked dynamic value (PID, IP, timestamp...)
    still counts as exact — consistent with cosine/BLEU/Levenshtein/etc., all
    of which score that case as a perfect match.
    """
    if not resp and not gt:
        return {"cosine_score": 1.0, "bleu_score": 1.0, "levenshtein_score": 1.0,
                "jaro_winkler_score": 1.0, "sequence_score": 1.0, "exact_match": 1}
    if not resp or not gt:
        return {"cosine_score": 0.0, "bleu_score": 0.0, "levenshtein_score": 0.0,
                "jaro_winkler_score": 0.0, "sequence_score": 0.0, "exact_match": 0}
    p, g = normalize_pair(resp, gt)
    return {
        "cosine_score":       cosine_score_response(resp, gt)["cosine_score"],
        "bleu_score":         bleu_score_response(resp, gt)["bleu_score"],
        "levenshtein_score":  round(Levenshtein.normalized_similarity(p, g), 4),
        "jaro_winkler_score": round(JaroWinkler.similarity(p, g), 4),
        "sequence_score":     round(Indel.normalized_similarity(p, g), 4),
        "exact_match":        int(p.strip() == g.strip()),
    }


def _bert_batch(pairs):
    """pairs: list of (resp, gt). Returns list of bert_f1 aligned to pairs.
    Both-empty -> 1.0, one-empty -> 0.0, else BERTScore on normalize_pair'd text
    (matches fidelity.bert_score_response). Non-empty pairs scored in one batch."""
    out = [None] * len(pairs)
    cand, ref, idx = [], [], []
    for i, (resp, gt) in enumerate(pairs):
        if not resp and not gt:
            out[i] = 1.0
        elif not resp or not gt:
            out[i] = 0.0
        else:
            p, g = normalize_pair(resp, gt)
            cand.append(p); ref.append(g); idx.append(i)
    if cand:
        P, R, F1 = _bert_scorer.score(cand, ref)          # GPU-batched internally
        for j, i in enumerate(idx):
            out[i] = round(float(F1[j]), 4)
    return out


def score_arm(arm, path):
    rows = list(_load_valid(path))
    print(f"[all_metrics] {arm:<12} {len(rows):>5} rows — fast metrics...", flush=True)
    fis   = [fi for fi, _, _ in rows]
    fast  = [_fast_metrics(resp, gt) for _, resp, gt in rows]
    if SKIP_BERT:
        bert = [None] * len(rows)
    else:
        print(f"[all_metrics] {arm:<12} BERTScore (GPU batch)...", flush=True)
        bert = _bert_batch([(resp, gt) for _, resp, gt in rows])

    byfi = defaultdict(lambda: defaultdict(list))
    for fi, fm, bf in zip(fis, fast, bert):
        for k, _ in METRICS:
            v = bf if k == "bert_f1" else fm[k]
            byfi[fi][k].append(v)
    return byfi


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("=" * 70)
    print("Scoring fidelity metrics for 4 arms"
          + ("  [--no-bert: skipping BERTScore, no GPU needed]" if SKIP_BERT
             else "  (this loads BERTScore on GPU)"))
    print("=" * 70, flush=True)

    summary = {}   # arm -> metric -> {fi -> mean}
    overall = {}   # arm -> metric -> mean
    for arm in ARM_ORDER:
        byfi = score_arm(arm, ARM_FILES[arm])
        summary[arm] = {k: {} for k, _ in METRICS}
        allv = {k: [] for k, _ in METRICS}
        for fi in FI_BANDS:
            for k, _ in METRICS:
                vals = byfi.get(fi, {}).get(k, [])
                summary[arm][k][fi] = (sum(vals) / len(vals)) if vals else None
                allv[k].extend(vals)
        overall[arm] = {k: (sum(v) / len(v) if v else None) for k, v in allv.items()}

    name = "all_metrics_scores_nobert.json" if SKIP_BERT else "all_metrics_scores.json"
    json.dump({"per_band": summary, "overall": overall},
              open(os.path.join(OUT_DIR, name), "w"), indent=2)

    # ── plot: grid, one grouped-bar chart per metric ──────────────────────────
    ncol = 4
    nrow = (len(METRICS) + ncol - 1) // ncol
    fig, axes = plt.subplots(nrow, ncol, figsize=(4.3 * ncol, 4.0 * nrow))
    axes = axes.flatten()
    x = np.arange(len(FI_BANDS))
    w = 0.8 / len(ARM_ORDER)
    for ax, (metric, label) in zip(axes, METRICS):
        for i, arm in enumerate(ARM_ORDER):
            vals = [summary[arm][metric].get(fi) or 0 for fi in FI_BANDS]
            offset = (i - (len(ARM_ORDER) - 1) / 2) * w
            ax.bar(x + offset, vals, w, label=ARM_LABEL[arm], color=ARM_COLOR[arm],
                   edgecolor="white", linewidth=0.6)
        ax.set_title(label, fontsize=12, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([f"FI{fi}" for fi in FI_BANDS])
        ax.set_ylim(0, 1.05)
        ax.legend(fontsize=7.5)
    for ax in axes[len(METRICS):]:
        ax.axis("off")
    fig.tight_layout()
    out = os.path.join(OUT_DIR, "all_metrics_by_fi.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"\n[all_metrics] saved {out}", flush=True)

    # ── overall table ─────────────────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("OVERALL fidelity (mean over all commands)")
    print("=" * 78)
    print("  " + f"{'arm':<12}" + "".join(f"{lbl.split(' (')[0]:>13}" for _, lbl in METRICS))
    for arm in ARM_ORDER:
        row = "  " + f"{arm:<12}"
        for k, _ in METRICS:
            v = overall[arm][k]
            row += f"{(f'{v:.3f}' if v is not None else '-'):>13}"
        print(row)
    print("\nDONE ->", OUT_DIR)


if __name__ == "__main__":
    main()
