"""
eval_compare_interaction.py
Evaluates cyberlab interaction sessions scored by Claude and ChatGPT
on both Cowrie and On-Device agents.

Single figure with 2 subplots:
  (a) Per-session realism scores — grouped bar (all 4 combos per session)
  (b) Overall avg per agent — grouped bar by judge

Run:
  cd evaluation
  python eval_compare_interaction.py
"""

import json
import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ── Paths ──────────────────────────────────────────────────────────────────
BASE = "/mnt/data-partition/honeypot/evaluation/interaction_session_eval"
FILES = {
    "cowrie": {
        "chatgpt": f"{BASE}/Cowrie/chatGPT/results.json",
        "claude":  f"{BASE}/Cowrie/claudeAI/results.json",
    },
    "ondevice": {
        "chatgpt": f"{BASE}/Ondevice/chatGPT/results.json",
        "claude":  f"{BASE}/Ondevice/claudeAI/results.json",
    },
}

OUTPUT_DIR = "/mnt/data-partition/honeypot/evaluation/experiment_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

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

COMBOS = list(PALETTE.keys())

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
                sid = entry.get("session_id", entry.get("theme_id", "unknown"))
                if str(sid).startswith("theme"):
                    continue  # skip themed — cyberlab only
                rows.append({
                    "agent":         agent,
                    "judge":         judge,
                    "session_id":    sid,
                    "realism_score": float(entry.get("realism_score", 0)),
                })
    print(f"[✓] Loaded {len(rows)} cyberlab interaction entries")
    return rows

# ── Plot ───────────────────────────────────────────────────────────────────
def plot(rows):
    all_sids  = sorted({r["session_id"] for r in rows})
    n_sessions = len(all_sids)
    n_combos   = len(COMBOS)
    width      = 0.7 / n_combos

    fig, axes = plt.subplots(1, 2, figsize=(18, 6),
                             gridspec_kw={"width_ratios": [3, 1]})
    fig.suptitle(
        "CyberLab Interaction Session Evaluation — Realism Score\n"
        "(Cowrie vs On-Device, judged by Claude and ChatGPT)",
        fontsize=13, fontweight="bold"
    )

    # ── (a) Per-session grouped bar ───────────────────────────────────────
    ax = axes[0]
    x  = np.arange(n_sessions)
    offsets = np.linspace(-(n_combos - 1) * width / 2,
                           (n_combos - 1) * width / 2,
                           n_combos)

    for i, (ag, ju) in enumerate(COMBOS):
        score_map = {}
        for r in rows:
            if r["agent"] == ag and r["judge"] == ju:
                score_map[r["session_id"]] = r["realism_score"]

        vals = [score_map.get(sid, 0) for sid in all_sids]
        bars = ax.bar(x + offsets[i], vals, width,
                      label=LABEL[(ag, ju)],
                      color=PALETTE[(ag, ju)],
                      hatch=HATCH[(ag, ju)],
                      alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.08,
                        f"{v:.0f}", ha="center", va="bottom",
                        fontsize=7)

    # Short session labels
    short_sids = [sid[:8] for sid in all_sids]
    ax.set_xticks(x)
    ax.set_xticklabels(short_sids, fontsize=8, rotation=45, ha="right")
    ax.set_ylim(0, 5.5)
    ax.set_yticks([0, 1, 2, 3, 4, 5])
    ax.set_ylabel("Realism Score (1–5)", fontsize=11)
    ax.set_title("(a) Realism Score per Session — All Agent/Judge Combinations",
                 fontsize=10)
    ax.axhline(3.0, color="gray", linestyle="--", linewidth=1,
               alpha=0.5, label="Midpoint (3.0)")
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(True, axis="y", alpha=0.3)

    # ── (b) Overall avg per agent/judge ───────────────────────────────────
    ax2 = axes[1]
    combo_labels = [LABEL[c] for c in COMBOS]
    combo_avgs   = []
    for ag, ju in COMBOS:
        vals = [r["realism_score"] for r in rows
                if r["agent"] == ag and r["judge"] == ju]
        combo_avgs.append(np.mean(vals) if vals else 0)

    x2    = np.arange(len(COMBOS))
    colors = [PALETTE[c] for c in COMBOS]
    hatches = [HATCH[c] for c in COMBOS]

    bars = ax2.bar(x2, combo_avgs, color=colors, alpha=0.85,
                   edgecolor="white",
                   hatch=[HATCH[c] for c in COMBOS])
    for bar, v in zip(bars, combo_avgs):
        ax2.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 0.08,
                 f"{v:.2f}", ha="center", va="bottom",
                 fontsize=9, fontweight="bold")

    # Short labels for x-axis
    short_combo = ["Cowrie\nChatGPT", "Cowrie\nClaude",
                   "On-Dev\nChatGPT", "On-Dev\nClaude"]
    ax2.set_xticks(x2)
    ax2.set_xticklabels(short_combo, fontsize=8)
    ax2.set_ylim(0, 5.5)
    ax2.set_yticks([0, 1, 2, 3, 4, 5])
    ax2.set_ylabel("Avg Realism Score (1–5)", fontsize=10)
    ax2.set_title("(b) Overall Avg\nby Agent/Judge", fontsize=10)
    ax2.axhline(3.0, color="gray", linestyle="--", linewidth=1, alpha=0.5)
    ax2.grid(True, axis="y", alpha=0.3)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_compare_interaction.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_compare_interaction.png")
    plt.close()

# ── Main ───────────────────────────────────────────────────────────────────
def main():
    rows = build_df()
    if not rows:
        print("[!] No data loaded. Check file paths.")
        return
    plot(rows)

if __name__ == "__main__":
    main()