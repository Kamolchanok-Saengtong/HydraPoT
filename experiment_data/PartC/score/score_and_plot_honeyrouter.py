"""
experiment_data/PartC/score_and_plot_honeyrouter.py — one-shot: replay HoneyRouter, score, plot.
─────────────────────────────────────────────────────────────────────────────────
Run this ONE script (safe to leave on `screen`, no API / no GPU / no Cowrie):

    python experiment_data/PartC/score_and_plot_honeyrouter.py

It does three things:
  1. REPLAY  — rebuilds the HoneyRouter arm via the real HydraPoT pipeline with
               lookup stubs (calls replay_honeyrouter.py). Real routing + state,
               responses drawn from the already-collected cowrie/on_device/cloud
               arms. No live agents.
  2. SCORE   — SYNTAX fidelity only (Levenshtein, Jaro-Winkler, Sequence,
               Exact-match) — the metrics you care about — for all 4 arms
               (cowrie / on_device / cloud / honeyrouter), grouped by FI band.
               CPU only; BERTScore/cosine are deliberately skipped.
  3. PLOT    — one grouped-bar chart per metric (2x2), 4 arms x 5 FI bands, plus
               a routing-distribution bar. Saves PNGs + a summary JSON.

Outputs land in:  experiment_data/PartC/results/honeyrouter_replay_latest/
─────────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import subprocess
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")               # headless — works over ssh/screen, no display
import matplotlib.pyplot as plt
import numpy as np

# match the house style from summarize_partC.py exactly
plt.rcParams.update({
    "font.family":       "sans-serif",
    "font.size":         11,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.grid":         True,
    "axes.grid.axis":    "y",
    "grid.color":        "#E0E0E0",
    "grid.linewidth":    0.7,
    "savefig.dpi":       300,
    "figure.dpi":        150,
})

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "evaluation"))

# syntax scorers via rapidfuzz (fast C) — identical formulas to evaluation/fidelity.py:
#   Levenshtein.normalized_similarity  == 1 - dist/max_len   (fidelity levenshtein_score)
#   Indel.normalized_similarity        == difflib ratio      (fidelity sequence_score)
#   JaroWinkler.similarity (prefix 0.1) == fidelity jaro_winkler_score
# Same normalize_pair() pre-processing, same empty-string edge handling, so
# values match fidelity.py's pure-Python versions but ~100x faster (no BERT/cosine).
from rapidfuzz.distance import Levenshtein, Indel, JaroWinkler   # noqa: E402
from normalization import normalize_pair                          # noqa: E402

RESULTS = os.path.join(_HERE, "..", "results", "partC")
OUT_DIR = os.path.join(RESULTS, "honeyrouter_replay_latest")

# the three forced arms (must match replay_honeyrouter.py ARM_FILES)
ARM_FILES = {
    "cowrie":    os.path.join(RESULTS, "fidelity_full109_final",   "cowrie.jsonl"),
    "on_device": os.path.join(RESULTS, "fidelity_20260723_135641", "on_device.jsonl"),
    "cloud":     os.path.join(RESULTS, "fidelity_cloud_new_20260728_131019", "cloud.jsonl"),  # deepseek-v4-flash
}

SYN_METRICS = [
    ("levenshtein_score",  "Levenshtein"),
    ("jaro_winkler_score", "Jaro-Winkler"),
    ("sequence_score",     "Sequence"),
    ("exact_match",        "Exact match"),
]
ARM_ORDER  = ["cowrie", "on_device", "cloud", "honeyrouter"]
# identical palette + labels to summarize_partC.py so all Part C figures match
ARM_COLOR  = {
    "cowrie":      "#AAAAAA",
    "on_device":   "#7EB3C8",
    "cloud":       "#5B7FA6",
    "honeyrouter": "#E07B39",
}
ARM_LABEL  = {
    "cowrie":      "Pure Cowrie",
    "on_device":   "Pure On-device LLM",
    "cloud":       "Pure Cloud LLM",
    "honeyrouter": "HydraPoT",
}
FI_BANDS   = [0, 1, 2, 3, 4]


# ── step 1: replay ────────────────────────────────────────────────────────────
def run_replay():
    print("=" * 70)
    print("STEP 1/3 — replay HoneyRouter through the real pipeline")
    print("=" * 70, flush=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    r = subprocess.run(
        [sys.executable, os.path.join(_HERE, "replay_honeyrouter.py"),
         "--out", OUT_DIR],
        cwd=_ROOT,
    )
    if r.returncode != 0:
        print("[score] replay FAILED — aborting")
        sys.exit(1)


# ── step 2: syntax scoring ────────────────────────────────────────────────────
def _syn_scores(resp, gt):
    """Return the 4 syntax metrics for one (response, ground_truth) pair.
    Mirrors evaluation/fidelity.py: both-empty -> 1.0, one-empty -> 0.0,
    else normalize_pair() then rapidfuzz."""
    exact = int((resp or "").strip() == (gt or "").strip())
    if not resp and not gt:
        return {"levenshtein_score": 1.0, "jaro_winkler_score": 1.0,
                "sequence_score": 1.0, "exact_match": 1}
    if not resp or not gt:
        return {"levenshtein_score": 0.0, "jaro_winkler_score": 0.0,
                "sequence_score": 0.0, "exact_match": 0}
    p, g = normalize_pair(resp, gt)
    return {
        "levenshtein_score":  round(Levenshtein.normalized_similarity(p, g), 4),
        "jaro_winkler_score": round(JaroWinkler.similarity(p, g), 4),
        "sequence_score":     round(Indel.normalized_similarity(p, g), 4),
        "exact_match":        exact,
    }


def _score_file(path, arm):
    """Score one arm file -> {fi_band: [ {metric: val}, ... ]}. Skips
    unusable rows (missing gt/fi, not ok, None response, cloud-error marker)."""
    byfi = defaultdict(list)
    skipped = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            gt, fi, resp = r.get("ground_truth"), r.get("fi_score"), r.get("response")
            if gt is None or fi is None or resp is None or not r.get("ok"):
                skipped += 1
                continue
            if isinstance(resp, str) and resp.startswith("[cloud error"):
                skipped += 1
                continue
            s = _syn_scores(resp, gt)
            byfi[fi].append({k: s[k] for k, _ in SYN_METRICS})
    n = sum(len(v) for v in byfi.values())
    print(f"  scored {arm:<12} {n:>5} rows  (skipped {skipped})", flush=True)
    return byfi


def score_all():
    print("\n" + "=" * 70)
    print("STEP 2/3 — syntax scoring (Levenshtein / Jaro-Winkler / Sequence / Exact)")
    print("=" * 70, flush=True)
    files = dict(ARM_FILES)
    files["honeyrouter"] = os.path.join(OUT_DIR, "honeyrouter.jsonl")

    # per-arm per-band mean of each metric
    summary = {}          # arm -> {metric -> {fi -> mean}}
    overall = {}          # arm -> {metric -> mean over all bands}
    for arm in ARM_ORDER:
        byfi = _score_file(files[arm], arm)
        summary[arm] = {m: {} for m, _ in SYN_METRICS}
        allvals = {m: [] for m, _ in SYN_METRICS}
        for fi in FI_BANDS:
            rows = byfi.get(fi, [])
            for m, _ in SYN_METRICS:
                vals = [row[m] for row in rows]
                summary[arm][m][fi] = (sum(vals) / len(vals)) if vals else None
                allvals[m].extend(vals)
        overall[arm] = {m: (sum(v) / len(v) if v else None) for m, v in allvals.items()}

    json.dump({"per_band": summary, "overall": overall},
              open(os.path.join(OUT_DIR, "syntax_scores.json"), "w"), indent=2)
    return summary, overall


# ── step 3: plots ─────────────────────────────────────────────────────────────
def plot_metrics(summary):
    print("\n" + "=" * 70)
    print("STEP 3/3 — plotting")
    print("=" * 70, flush=True)

    x = np.arange(len(FI_BANDS))
    w = 0.8 / len(ARM_ORDER)
    fig, axes = plt.subplots(2, 2, figsize=(13, 9))
    for ax, (metric, label) in zip(axes.flatten(), SYN_METRICS):
        for i, arm in enumerate(ARM_ORDER):
            vals = [summary[arm][metric].get(fi) or 0 for fi in FI_BANDS]
            offset = (i - (len(ARM_ORDER) - 1) / 2) * w
            ax.bar(x + offset, vals, w, label=ARM_LABEL[arm], color=ARM_COLOR[arm],
                   edgecolor="white", linewidth=0.6)
        ax.set_title(f"{label} by FI band", fontsize=12, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([f"FI{fi}" for fi in FI_BANDS])
        ax.set_ylabel(label)
        ax.set_ylim(0, 1.05)
        ax.legend(fontsize=8.5)
    fig.suptitle("HydraPoT vs single-agent arms — syntax fidelity",
                 fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    out1 = os.path.join(OUT_DIR, "syntax_4arms_by_fi.png")
    fig.savefig(out1, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved {out1}", flush=True)


def plot_routing():
    recs = [json.loads(l) for l in open(os.path.join(OUT_DIR, "honeyrouter.jsonl"))]
    from collections import Counter
    c = Counter(r["routed_to"] for r in recs)
    backends = ["cowrie", "on_device", "cloud"]
    labels   = ["Cowrie", "On-device LLM", "Cloud LLM"]
    vals     = [c.get(b, 0) for b in backends]
    x = np.arange(len(backends))

    fig, ax = plt.subplots(figsize=(6.5, 5.0))
    bars = ax.bar(x, vals, color=[ARM_COLOR[b] for b in backends],
                  edgecolor="white", linewidth=0.8)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + max(vals) * 0.01, str(v),
                ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Commands routed")
    ax.set_title("HydraPoT — routing distribution", fontsize=12, fontweight="bold")
    fig.tight_layout()
    out = os.path.join(OUT_DIR, "routing_distribution.png")
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved {out}", flush=True)


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    run_replay()
    summary, overall = score_all()
    plot_metrics(summary)
    plot_routing()

    print("\n" + "=" * 70)
    print("OVERALL syntax fidelity (mean over all commands)")
    print("=" * 70)
    hdr = "  " + f"{'arm':<12}" + "".join(f"{lbl:>14}" for _, lbl in SYN_METRICS)
    print(hdr)
    for arm in ARM_ORDER:
        row = "  " + f"{arm:<12}"
        for m, _ in SYN_METRICS:
            v = overall[arm][m]
            row += f"{(f'{v:.3f}' if v is not None else '-'):>14}"
        print(row)
    print("\nDONE. Results + PNGs in:", OUT_DIR)


if __name__ == "__main__":
    main()
