"""
experiment_data/PartC/plot/plot_routing_distribution.py — how many commands each
agent actually answered.

Reads results/partC/fidelity/honeyrouter.jsonl (the arm with natural routing via
classify(); the other three arms are force-routed, so their distribution is 100%
one agent by construction) and plots the share of commands per agent, same house
style as plot_judge_by_fi.py.

    python experiment_data/PartC/plot/plot_routing_distribution.py

Output -> results/partC/semantic_analysis/routing_distribution.png (+ .pdf)
"""
import json
import math
import os
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y",
    "grid.color": "#E0E0E0", "grid.linewidth": 0.7,
    "savefig.dpi": 300, "figure.dpi": 150,
})

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartC/
_ROOT = os.path.dirname(os.path.dirname(_HERE))
ARM_FILE = os.path.join(_HERE, "..", "results", "partC", "fidelity", "honeyrouter.jsonl")
OUT_DIR = os.path.join(_HERE, "..", "results", "partC", "semantic_analysis")

# Same hues plot_judge_by_fi.py gives these agents, so a reader comparing the two
# figures sees one colour per agent throughout.
AGENT_ORDER = ["cowrie", "on_device", "cloud"]
AGENT_COLOR = {"cowrie": "#AAAAAA", "on_device": "#7EB3C8", "cloud": "#5B7FA6"}
AGENT_LABEL = {"cowrie": "Cowrie", "on_device": "On-device LLM",
               "cloud": "Cloud LLM"}


def _load(path):
    with open(path, encoding="utf-8") as f:
        rows = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def main():
    if not os.path.exists(ARM_FILE):
        print(f"[plot_routing] missing {os.path.relpath(ARM_FILE, _ROOT)}")
        raise SystemExit(1)

    rows = _load(ARM_FILE)
    counts = Counter(r.get("routed_to") for r in rows)

    # Rows the pipeline could not route at all are reported in the caption rather
    # than drawn: a single command is an invisible wedge, and silently folding it
    # into an agent would overstate that agent's share.
    unrouted = sum(v for k, v in counts.items() if k not in AGENT_ORDER)
    vals = [counts.get(a, 0) for a in AGENT_ORDER]
    total = sum(vals)

    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    wedges, _ = ax.pie(
        vals,
        colors=[AGENT_COLOR[a] for a in AGENT_ORDER],
        startangle=90, counterclock=False,
        # 2px surface gap between fills, so adjacent wedges read as separate marks
        wedgeprops={"edgecolor": "white", "linewidth": 2},
    )
    ax.axis("equal")

    # No title, no legend box, no caption — the paper's own caption carries all
    # of that, matching plot_metrics_separate.py. Identity still has to survive,
    # so each wedge is labelled in place: a pie has no axis to read names off,
    # and colour alone would leave the reader nothing to map back to an agent.
    for w, a, v in zip(wedges, AGENT_ORDER, vals):
        ang = math.radians((w.theta1 + w.theta2) / 2)
        x, y = 0.62 * math.cos(ang), 0.62 * math.sin(ang)
        ax.text(x, y, f"{v / total * 100:.1f}%",
                ha="center", va="center", fontsize=15, color="#222222")

    fig.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT_DIR, f"routing_distribution.{ext}"),
                    dpi=300, bbox_inches="tight")
    print(f"[plot_routing] saved {os.path.relpath(OUT_DIR, _ROOT)}/"
          f"routing_distribution.png (+ .pdf)")
    for a in AGENT_ORDER:
        c = counts.get(a, 0)
        print(f"[plot_routing]   {AGENT_LABEL[a]:<16} {c:>5,}  {c/total*100:5.1f}%")
    if unrouted:
        print(f"[plot_routing]   {'unrouted':<16} {unrouted:>5,}  (excluded)")


if __name__ == "__main__":
    main()
