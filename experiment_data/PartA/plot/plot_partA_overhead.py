"""
experiment_data/PartA/plot/plot_partA_overhead.py — architecture-overhead bar chart.

Reads the current run under results/partA/<arm>/<arm>.jsonl and plots, per agent,
mean standalone vs HydraPoT latency with the absolute-ms overhead annotated.

    python experiment_data/PartA/plot/plot_partA_overhead.py

Output -> results/partA/figures/architecture_overhead.png (+ .pdf)
"""
import json
import os
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartA/
_ROOT = os.path.dirname(os.path.dirname(_HERE))
RESULTS_DIR = os.path.join(_ROOT, "experiment_data", "results", "partA")
OUT_DIR = os.path.join(RESULTS_DIR, "figures")

# (display, standalone arm, hydrapot arm)
ARMS = [
    ("Cowrie",            "standalone_cowrie", "cowrie_hydrapot"),
    ("Local (on-device)", "standalone_local",  "local_hydrapot"),
    ("Cloud",             "standalone_cloud",  "cloud_hydrapot"),
]
STANDALONE, HYDRAPOT = "#4C78A8", "#F58518"   # colorblind-safe blue / orange


def _read_blocks(path):
    try:
        txt = open(path, encoding="utf-8").read()
    except OSError:
        return []
    dec, i, n, recs = json.JSONDecoder(), 0, len(txt), []
    while i < n:
        while i < n and txt[i] in " \n\r\t":
            i += 1
        if i >= n:
            break
        try:
            o, i = dec.raw_decode(txt, i)
        except json.JSONDecodeError:
            break
        recs.append(o)
    return recs


def _mean_latency(arm):
    xs = [r["latency_ms"] for r in _read_blocks(os.path.join(RESULTS_DIR, arm, f"{arm}.jsonl"))
          if r.get("ok") and isinstance(r.get("latency_ms"), (int, float))]
    return statistics.mean(xs) if xs else 0.0


def main():
    labels, pure, hyd = [], [], []
    for disp, pa, ha in ARMS:
        p, h = _mean_latency(pa), _mean_latency(ha)
        if p or h:
            labels.append(disp); pure.append(p); hyd.append(h)
    if not labels:
        print(f"[plot] no data under {os.path.relpath(RESULTS_DIR, _ROOT)}/ — run Part A first")
        raise SystemExit(1)

    x = range(len(labels))
    w = 0.38
    fig, ax = plt.subplots(figsize=(8, 5))
    b1 = ax.bar([i - w / 2 for i in x], pure, w, label="Standalone", color=STANDALONE)
    b2 = ax.bar([i + w / 2 for i in x], hyd,  w, label="HydraPoT",   color=HYDRAPOT)

    for bars in (b1, b2):
        for bar in bars:
            v = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, v, f"{v:.0f}",
                    ha="center", va="bottom", fontsize=9)
    # overhead annotation per agent
    top = max(hyd + pure)
    for i, (p, h) in enumerate(zip(pure, hyd)):
        over = h - p
        pct = (over / p * 100) if p else 0
        ax.text(i, top * 1.08, f"{over:+.0f} ms\n({pct:+.0f}%)",
                ha="center", va="bottom", fontsize=9, color=HYDRAPOT)

    ax.set_xticks(list(x)); ax.set_xticklabels(labels)
    ax.set_ylabel("Mean latency per command (ms)")
    ax.set_title("Part A — Architecture overhead: standalone vs HydraPoT")
    ax.set_ylim(0, top * 1.25)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.3)
    ax.legend(frameon=False)
    fig.tight_layout()

    os.makedirs(OUT_DIR, exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT_DIR, f"architecture_overhead.{ext}"), dpi=300)
    print(f"[plot] wrote {os.path.relpath(OUT_DIR, _ROOT)}/architecture_overhead.png (+ .pdf)")


if __name__ == "__main__":
    main()
