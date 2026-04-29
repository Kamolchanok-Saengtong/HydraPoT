"""
eval_compare_themed.py
Evaluates the 6-theme attack dataset scored by Claude and ChatGPT
on both Cowrie and On-Device agents.

Produces 3 SEPARATE figures:
  1. eval_themed_realism.png    — Realism score per theme, grouped bar
  2. eval_themed_radar.png      — Radar charts, score profile per agent/judge
  3. eval_themed_dimensions.png — Score dimension breakdown, grouped bar

Run:
  cd evaluation
  python eval_compare_themed.py
"""

import json
import os
import math
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ── Paths ──────────────────────────────────────────────────────────────────
BASE = "/mnt/data-partition/honeypot/evaluation/interaction_results/LLM_as_judge"
FILES = {
    "cowrie": {
        "chatgpt": f"{BASE}/ChatGPT/cowrie.json",
        "claude":  f"{BASE}/ClaudeAI/cowrie.json",
    },
    "ondevice": {
        "chatgpt": f"{BASE}/ChatGPT/ondevice.json",
        "claude":  f"{BASE}/ClaudeAI/ondevice.json",
    },
}

OUTPUT_DIR = "/mnt/data-partition/honeypot/evaluation/experiment_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Style ──────────────────────────────────────────────────────────────────
PALETTE = {
    ("cowrie",   "chatgpt"): "#3498db",
    ("cowrie",   "claude"):  "#2ecc71",
    ("ondevice", "chatgpt"): "#e67e22",
    ("ondevice", "claude"):  "#9b59b6",
}
HATCH = {
    ("cowrie",   "chatgpt"): "",
    ("cowrie",   "claude"):  "",
    ("ondevice", "chatgpt"): "//",
    ("ondevice", "claude"):  "xx",
}
LABEL = {
    ("cowrie",   "chatgpt"): "Cowrie / ChatGPT",
    ("cowrie",   "claude"):  "Cowrie / Claude",
    ("ondevice", "chatgpt"): "On-Device / ChatGPT",
    ("ondevice", "claude"):  "On-Device / Claude",
}

SCORE_DIMS = [
    "session_score",
    "consistency_score",
    "realism_score",
    "statefulness_score",
    "error_handling_score",
    "behavioral_authenticity_score",
]
DIM_SHORT = [
    "Session",
    "Consistency",
    "Realism",
    "Statefulness",
    "Error\nHandling",
    "Behavioral\nAuth",
]

THEMES_ORDER = [
    "theme1_crypto_jacker",
    "theme2_source_code_auditor",
    "theme3_network_pivoter",
    "theme4_data_exfiltrator",
    "theme5_system_saboteur",
    "theme6_scorched_earth",
]
THEME_SHORT = [
    "T1\nCrypto\nJacker",
    "T2\nSource Code\nAuditor",
    "T3\nNetwork\nPivoter",
    "T4\nData\nExfiltrator",
    "T5\nSystem\nSaboteur",
    "T6\nScorched\nEarth",
]

# ── Helpers ────────────────────────────────────────────────────────────────
def load(path):
    with open(path) as f:
        return json.load(f)

def build_df():
    rows = []
    for agent, judges in FILES.items():
        for judge, path in judges.items():
            if not os.path.exists(path):
                print(f"[!] Missing: {path}")
                continue
            for entry in load(path):
                tid = entry.get("theme_id", entry.get("session_id", ""))
                if not tid.startswith("theme"):
                    continue
                row = {"agent": agent, "judge": judge, "theme_id": tid}
                for dim in SCORE_DIMS:
                    row[dim] = float(entry.get(dim, 0))
                rows.append(row)
    print(f"[✓] Loaded {len(rows)} themed entries")
    return rows

def get_score(rows, agent, judge, theme, dim="realism_score"):
    vals = [r[dim] for r in rows
            if r["agent"] == agent and r["judge"] == judge
            and r["theme_id"] == theme]
    return np.mean(vals) if vals else 0

def avg_across_themes(rows, agent, judge, dim):
    vals = [r[dim] for r in rows
            if r["agent"] == agent and r["judge"] == judge]
    return np.mean(vals) if vals else 0


# ── Figure 1: Realism per theme — grouped bar ─────────────────────────────

def plot_realism_per_theme(rows):
    combos   = list(PALETTE.keys())
    n_themes = len(THEMES_ORDER)
    n_combos = len(combos)
    width    = 0.18
    x        = np.arange(n_themes)
    offsets  = np.linspace(-(n_combos - 1) * width / 2,
                            (n_combos - 1) * width / 2,
                            n_combos)

    fig, ax = plt.subplots(figsize=(14, 6))
    fig.suptitle(
        "Themed Attack Evaluation — Realism Score per Theme\n"
        "(Cowrie vs On-Device, judged by Claude and ChatGPT)",
        fontsize=13, fontweight="bold"
    )

    for i, (ag, ju) in enumerate(combos):
        vals  = [get_score(rows, ag, ju, t, "realism_score")
                 for t in THEMES_ORDER]
        bars  = ax.bar(x + offsets[i], vals, width,
                       label=LABEL[(ag, ju)],
                       color=PALETTE[(ag, ju)],
                       hatch=HATCH[(ag, ju)],
                       alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.08,
                        f"{v:.1f}", ha="center", va="bottom",
                        fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(THEME_SHORT, fontsize=8)
    ax.set_ylim(0, 5.5)
    ax.set_yticks([0, 1, 2, 3, 4, 5])
    ax.set_ylabel("Realism Score (1–5)", fontsize=11)
    ax.axhline(3.0, color="gray", linestyle="--", linewidth=1,
               alpha=0.5, label="Midpoint (3.0)")
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(True, axis="y", alpha=0.3)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_themed_realism.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_themed_realism.png")
    plt.close()


# ── Figure 2: Radar charts — 2×2 grid ─────────────────────────────────────

def plot_radar(rows):
    combos = list(PALETTE.keys())
    N      = len(THEMES_ORDER)
    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]

    # Short theme labels for radar
    radar_labels = ["T1\nCrypto", "T2\nSource", "T3\nNetwork",
                    "T4\nData", "T5\nSaboteur", "T6\nScorched"]

    fig, axes = plt.subplots(2, 2, figsize=(12, 10),
                             subplot_kw=dict(projection="polar"))
    fig.suptitle(
        "Themed Attack Evaluation — Realism Score Radar\n"
        "(score profile per agent per judge across 6 themes)",
        fontsize=13, fontweight="bold"
    )

    for ax, (ag, ju) in zip(axes.flat, combos):
        vals = [get_score(rows, ag, ju, t, "realism_score")
                for t in THEMES_ORDER]
        vals += vals[:1]

        color = PALETTE[(ag, ju)]
        ax.plot(angles, vals, color=color, linewidth=2)
        ax.fill(angles, vals, color=color, alpha=0.2)

        # Value labels at each point
        for angle, val in zip(angles[:-1], vals[:-1]):
            if val > 0:
                ax.text(angle, val + 0.3, f"{val:.1f}",
                        ha="center", va="center", fontsize=8,
                        fontweight="bold", color=color)

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(radar_labels, fontsize=8)
        ax.set_ylim(0, 5)
        ax.set_yticks([1, 2, 3, 4, 5])
        ax.set_yticklabels(["1", "2", "3", "4", "5"], fontsize=7)
        ax.grid(True, alpha=0.3)
        ax.set_title(LABEL[(ag, ju)], fontsize=11,
                     fontweight="bold", pad=15, color=color)

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    out = os.path.join(OUTPUT_DIR, "eval_themed_radar.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_themed_radar.png")
    plt.close()


# ── Figure 3: Score dimension breakdown ────────────────────────────────────

def plot_dimensions(rows):
    combos   = list(PALETTE.keys())
    n_dims   = len(SCORE_DIMS)
    n_combos = len(combos)
    width    = 0.18
    x        = np.arange(n_dims)
    offsets  = np.linspace(-(n_combos - 1) * width / 2,
                            (n_combos - 1) * width / 2,
                            n_combos)

    fig, ax = plt.subplots(figsize=(14, 6))
    fig.suptitle(
        "Themed Attack Evaluation — Score Dimension Breakdown\n"
        "(avg across all 6 themes per agent per judge)",
        fontsize=13, fontweight="bold"
    )

    for i, (ag, ju) in enumerate(combos):
        vals  = [avg_across_themes(rows, ag, ju, dim) for dim in SCORE_DIMS]
        bars  = ax.bar(x + offsets[i], vals, width,
                       label=LABEL[(ag, ju)],
                       color=PALETTE[(ag, ju)],
                       hatch=HATCH[(ag, ju)],
                       alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.05,
                        f"{v:.1f}", ha="center", va="bottom",
                        fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(DIM_SHORT, fontsize=10)
    ax.set_ylim(0, 5.5)
    ax.set_yticks([0, 1, 2, 3, 4, 5])
    ax.set_ylabel("Avg Score (1–5)", fontsize=11)
    ax.axhline(3.0, color="gray", linestyle="--", linewidth=1,
               alpha=0.5, label="Midpoint (3.0)")
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(True, axis="y", alpha=0.3)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_themed_dimensions.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_themed_dimensions.png")
    plt.close()


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    rows = build_df()
    if not rows:
        print("[!] No themed data loaded. Check file paths.")
        return

    plot_realism_per_theme(rows)
    plot_radar(rows)
    plot_dimensions(rows)

    print("\n[✓] All 3 themed figures saved to experiment_results/")

if __name__ == "__main__":
    main()