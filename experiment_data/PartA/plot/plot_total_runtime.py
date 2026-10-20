"""
experiment_data/PartA/plot/plot_total_runtime.py — TOTAL runtime (not average
latency), per professor's request: sum of latency_ms across the whole benchmark
for one trial, then mean + stdev of that total across trials.

The fair-baseline corrections this script used to apply are GONE ON PURPOSE.
They compensated for standalone arms being prompted with the mrheinen dataset's
own short instruction while HydraPoT paid for the full prompt — cloud's pure
total was reconstructed by subtracting machinery_ms×n_commands, and on_device's
was taken from module_overhead.py entirely. agents.py now builds the standalone
arms with the real HydraPoT prompt (state withheld, sync_state=False), so both
sides are measured on equal terms and every arm is read straight from its own
log. Re-introducing either compensation would now double-correct.

    python experiment_data/PartA/plot/plot_total_runtime.py

Output -> results/partA/figures/fig_total_runtime.png (+ .pdf)
"""
import json
import os
import statistics
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# PartA/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_HERE, "plot"))

from plot_partA import COLOR, EDGE_WHITE, HYDRA_EDGE, _clean_axes   # noqa: E402

RESULTS_DIR = os.path.join(_HERE, "..", "results", "partA")
OUT_DIR = os.path.join(RESULTS_DIR, "figures")

# (colour key, display, standalone arm, hydrapot arm)
BACKENDS = [
    ("cowrie",    "Cowrie",        "standalone_cowrie", "cowrie_hydrapot"),
    ("on_device", "On-device LLM", "standalone_local",  "local_hydrapot"),
    ("cloud",     "Cloud LLM",     "standalone_cloud",  "cloud_hydrapot"),
]

plt.rcParams.update({"font.family": "sans-serif", "font.size": 16,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "axes.grid.axis": "y", "grid.color": "#E8E8E8", "grid.linewidth": 0.8,
    "savefig.dpi": 300, "figure.dpi": 150})


def _read_blocks(path):
    """Records from an arm log — tolerates concatenated objects, not just JSONL."""
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


def _trial_totals_s(arm):
    """[total seconds per trial] for one arm."""
    per_trial = defaultdict(float)
    for r in _read_blocks(os.path.join(RESULTS_DIR, arm, f"{arm}.jsonl")):
        lat = r.get("latency_ms")
        if r.get("ok") and isinstance(lat, (int, float)):
            per_trial[r.get("trial")] += lat
    return [v / 1000.0 for v in per_trial.values()]


def _mean_std(secs):
    if not secs:
        return 0.0, 0.0
    return statistics.mean(secs), (statistics.pstdev(secs) if len(secs) > 1 else 0.0)


def main():
    pure, hydrapot = {}, {}
    for key, _disp, pa, ha in BACKENDS:
        pure[key]     = _mean_std(_trial_totals_s(pa))
        hydrapot[key] = _mean_std(_trial_totals_s(ha))

    if not any(pure[k][0] or hydrapot[k][0] for k, _d, _p, _h in BACKENDS):
        print(f"[plot] no data under {os.path.relpath(RESULTS_DIR, _HERE)}/ — run Part A first")
        raise SystemExit(1)

    hydra_real_m, hydra_real_s = _mean_std(_trial_totals_s("honeyrouter"))

    fig, ax = plt.subplots(figsize=(10.0, 6.0))
    x = np.arange(len(BACKENDS))
    w = 0.34
    ymax = max([pure[k][0] for k, _d, _p, _h in BACKENDS]
               + [hydrapot[k][0] for k, _d, _p, _h in BACKENDS])

    def _label(xpos, value):
        ax.text(xpos, value + ymax * 0.015, f"{value:,.0f}s",
                ha="center", va="bottom", fontsize=15, fontweight="bold")

    # Error bars omitted: stdev across trials is a fraction of a percent of
    # every total, so the caps are invisible at this scale. Real values stay
    # in the printed summary and belong in the paper's text/table.
    for i, (key, _disp, _pa, _ha) in enumerate(BACKENDS):
        pm, _ps = pure[key]
        hm, _hs = hydrapot[key]
        ax.bar(x[i] - w / 2, pm, w, color=COLOR[key], alpha=0.55,
               edgecolor=EDGE_WHITE, linewidth=0.8, zorder=3)
        ax.bar(x[i] + w / 2, hm, w, color=COLOR[key],
               edgecolor=HYDRA_EDGE, linewidth=1.6, zorder=3)
        _label(x[i] - w / 2, pm)
        _label(x[i] + w / 2, hm)

    ax.set_xticks(x)
    ax.set_xticklabels([d for _k, d, _p, _h in BACKENDS], fontsize=17)
    ax.set_ylabel("Total runtime per session (s)", fontsize=17)
    ax.tick_params(axis="y", labelsize=15)
    ax.set_ylim(0, ymax * 1.22)

    _clean_axes(ax)
    fig.tight_layout(pad=1.5)
    os.makedirs(OUT_DIR, exist_ok=True)
    out_png = os.path.join(OUT_DIR, "fig_total_runtime.png")
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, "fig_total_runtime.pdf"), bbox_inches="tight")
    plt.close(fig)

    for key, disp, _pa, _ha in BACKENDS:
        pm, ps = pure[key]
        hm, hs = hydrapot[key]
        delta = ((hm - pm) / pm * 100) if pm else 0.0
        print(f"  {disp:<14} standalone={pm:8.2f}s ± {ps:5.2f}s   "
              f"hydrapot={hm:8.2f}s ± {hs:5.2f}s   delta={delta:+.1f}%")
    print(f"  honeyrouter(real) = {hydra_real_m:.2f}s ± {hydra_real_s:.2f}s")
    print(f"saved -> {out_png}")


if __name__ == "__main__":
    main()
