"""
evaluation/eval_session_cost.py
─────────────────────────────────────────────────────────────────
Session-Level Cost Projection

Uses FI scoring to simulate Honey Router assignment:
  FI0, FI1 → Cowrie   ($0.00)
  FI2, FI3 → On-device ($0.00, local GPU)
  FI4      → Cloud     (token API cost)

Loads:
  1. CyberLab sessions from interaction_mode/
     - Each folder = one session (by session_id)
     - Uses session_results.json per folder
  2. Themed attack sessions from interaction_results/
     - theme1_crypto_jacker/ ... theme6_scorched_earth/
     - Each has cowrie.json + ondevice.json

Produces:
  eval_session_cost.png
    Left : Cost per session bar chart (CyberLab + themed)
    Right: Agent distribution per session (stacked bar)

Run:
  cd evaluation
  python eval_session_cost.py
─────────────────────────────────────────────────────────────────
"""

import json
import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fi_manager import FIScorer, FI_LABELS

# ─── Config ───────────────────────────────────────────────────────────────────

CYBERLAB_DIR    = "/mnt/data-partition/honeypot/evaluation/interaction_mode"
THEMED_DIR      = "/mnt/data-partition/honeypot/evaluation/interaction_results"
OUTPUT_DIR      = "/mnt/data-partition/honeypot/evaluation/experiment_results"

INPUT_COST_PER_1M  = 0.02   # $ per 1M input tokens
OUTPUT_COST_PER_1M = 0.05   # $ per 1M output tokens
MONTHLY_BUDGET     = 0.10   # $

os.makedirs(OUTPUT_DIR, exist_ok=True)
scorer = FIScorer()

# ─── Agent assignment by FI (simulated Honey Router) ──────────────────────────

def fi_to_agent(fi: int) -> str:
    """FI0-1 → Cowrie, FI2-3 → On-device, FI4 → Cloud"""
    if fi <= 1:
        return "cowrie"
    elif fi <= 3:
        return "on_device"
    else:
        return "cloud"

def estimate_tokens(text: str) -> int:
    return len(text) // 4 if text else 0

def calc_cost(in_tok: int, out_tok: int) -> float:
    return (in_tok / 1_000_000 * INPUT_COST_PER_1M +
            out_tok / 1_000_000 * OUTPUT_COST_PER_1M)

# ─── Load CyberLab sessions ──────────────────────────────────────────────────

def load_cyberlab_sessions() -> dict:
    """
    Each subfolder in interaction_mode/ is one session.
    Loads session_results.json from each.
    Returns dict: {session_name: [list of command entries]}
    """
    sessions = {}
    if not os.path.exists(CYBERLAB_DIR):
        print(f"[!] CyberLab dir not found: {CYBERLAB_DIR}")
        return sessions

    for folder in sorted(os.listdir(CYBERLAB_DIR)):
        folder_path = os.path.join(CYBERLAB_DIR, folder)
        if not os.path.isdir(folder_path):
            continue

        # Try session_results.json first, then batch_1.json
        for fname in ["session_results.json", "batch_1.json"]:
            fpath = os.path.join(folder_path, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath) as f:
                        data = json.load(f)
                    if data:
                        # Extract session_id from folder name (last part after _)
                        session_id = folder.split("_")[-1][:8]
                        session_name = f"CyberLab_{session_id}"
                        sessions[session_name] = data
                        print(f"[✓] {session_name}: {len(data)} commands ← {fname}")
                        break
                except Exception as e:
                    print(f"[!] Failed {fpath}: {e}")

    return sessions

# ─── Load themed attack sessions ──────────────────────────────────────────────

def load_themed_sessions() -> dict:
    """
    Each theme folder has cowrie.json + ondevice.json.
    Merge them into one session per theme.
    Returns dict: {theme_name: [list of command entries]}
    """
    sessions = {}
    if not os.path.exists(THEMED_DIR):
        print(f"[!] Themed dir not found: {THEMED_DIR}")
        return sessions

    for folder in sorted(os.listdir(THEMED_DIR)):
        folder_path = os.path.join(THEMED_DIR, folder)
        if not os.path.isdir(folder_path):
            continue
        if not folder.startswith("theme"):
            continue

        combined = []
        for fname in ["cowrie.json", "ondevice.json"]:
            fpath = os.path.join(folder_path, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath) as f:
                        data = json.load(f)
                    if data:
                        combined.extend(data)
                except Exception as e:
                    print(f"[!] Failed {fpath}: {e}")

        if combined:
            # Clean theme name: theme1_crypto_jacker → Crypto Jacker
            theme_label = folder.replace("_", " ").title()
            sessions[theme_label] = combined
            print(f"[✓] {theme_label}: {len(combined)} commands")

    return sessions

# ─── Analyse one session ──────────────────────────────────────────────────────

def analyse_session(commands: list) -> dict:
    """
    For each command in the session:
      1. Score FI
      2. Assign agent via fi_to_agent()
      3. Calculate cost (cloud only, others = $0)
      4. Track per-command tokens for cumulative graph
    """
    total = len(commands)
    agent_counts = defaultdict(int)
    fi_counts    = defaultdict(int)
    total_cost   = 0.0
    cloud_cmds   = 0

    # Per-command tracking for the 3-line graph
    per_cmd = []

    for entry in commands:
        cmd = entry.get("cmd", entry.get("command", ""))
        # Use existing fi if available, otherwise score it
        fi = entry.get("fi")
        if fi is None:
            fi, _ = scorer.score(cmd)

        agent = fi_to_agent(fi)
        agent_counts[agent] += 1
        fi_counts[fi] += 1

        # Estimate tokens for ALL commands (needed for red line)
        response = (entry.get("cowrie_output", "") or
                    entry.get("ondevice_output", "") or
                    entry.get("response", "") or
                    entry.get("output", ""))
        in_tok  = estimate_tokens(cmd)
        out_tok = estimate_tokens(response)
        cmd_tokens = in_tok + out_tok

        # Only cloud commands cost money
        cmd_cost = 0.0
        if agent == "cloud":
            cloud_cmds += 1
            cmd_cost = calc_cost(in_tok, out_tok)
            total_cost += cmd_cost

        per_cmd.append({
            "cmd":       cmd,
            "fi":        fi,
            "agent":     agent,
            "tokens":    cmd_tokens,
            "cost_usd":  cmd_cost,
        })

    return {
        "total_cmds":    total,
        "agent_counts":  dict(agent_counts),
        "fi_counts":     dict(fi_counts),
        "cloud_cmds":    cloud_cmds,
        "total_cost":    total_cost,
        "cowrie_pct":    agent_counts["cowrie"]    / total * 100 if total else 0,
        "ondevice_pct":  agent_counts["on_device"] / total * 100 if total else 0,
        "cloud_pct":     agent_counts["cloud"]     / total * 100 if total else 0,
        "per_cmd":       per_cmd,
    }

# ─── Print summary ────────────────────────────────────────────────────────────

def print_summary(all_sessions: dict):
    print(f"\n{'═'*80}")
    print(f"  SESSION COST PROJECTION — Honey Router Simulation")
    print(f"  FI0-1 → Cowrie ($0)  |  FI2-3 → On-device ($0)  |  FI4 → Cloud ($$)")
    print(f"{'═'*80}")
    print(f"  {'SESSION':<30} {'CMDS':>5} {'COWRIE':>8} {'ON-DEV':>8} {'CLOUD':>8} {'COST':>12}")
    print("─" * 80)

    total_cmds = 0
    total_cost = 0.0
    total_cloud = 0

    for name, stats in all_sessions.items():
        total_cmds  += stats["total_cmds"]
        total_cost  += stats["total_cost"]
        total_cloud += stats["cloud_cmds"]
        print(f"  {name:<30} {stats['total_cmds']:>5} "
              f"{stats['cowrie_pct']:>7.1f}% "
              f"{stats['ondevice_pct']:>7.1f}% "
              f"{stats['cloud_pct']:>7.1f}% "
              f"${stats['total_cost']:>10.6f}")

    print("─" * 80)
    n_sessions = len(all_sessions)
    avg_cost   = total_cost / n_sessions if n_sessions else 0
    sessions_per_budget = MONTHLY_BUDGET / avg_cost if avg_cost > 0 else float('inf')

    print(f"  {'TOTAL':<30} {total_cmds:>5} {'':>8} {'':>8} {total_cloud:>8} ${total_cost:>10.6f}")
    print(f"\n  Avg cost per session     : ${avg_cost:.6f}")
    print(f"  Budget                   : ${MONTHLY_BUDGET:.2f}/month")
    print(f"  Sessions before budget   : {sessions_per_budget:,.0f} sessions")
    print(f"  At 30 sessions/month     : ${avg_cost * 30:.6f}  ({avg_cost * 30 / MONTHLY_BUDGET * 100:.2f}% of budget)")
    print(f"  At 100 sessions/month    : ${avg_cost * 100:.6f}  ({avg_cost * 100 / MONTHLY_BUDGET * 100:.2f}% of budget)")
    print("═" * 80)

# ─── Plot ─────────────────────────────────────────────────────────────────────

def plot_session_cost(all_sessions: dict):
    names = list(all_sessions.keys())
    n     = len(names)

    if n == 0:
        print("[!] No sessions to plot")
        return

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle(
        "Session-Level Cost Projection — Honey Router Simulation\n"
        "FI0–1 → Cowrie ($0)  |  FI2–3 → On-device ($0)  |  FI4 → Cloud (token cost)",
        fontsize=12, fontweight="bold"
    )

    # Short labels for x-axis
    short_names = []
    for name in names:
        if "CyberLab" in name:
            short_names.append(name.replace("CyberLab_", "CL_"))
        else:
            # theme1_crypto_jacker → T1
            parts = name.split()
            if len(parts) >= 1 and parts[0].startswith("Theme"):
                num = ''.join(filter(str.isdigit, parts[0]))
                short_names.append(f"T{num}")
            else:
                short_names.append(name[:8])

    x = np.arange(n)

    # ── Left: cumulative cost across sessions (3-line design) ───────────────
    ax1 = axes[0]
    
    # Build cumulative per session
    expected_cum = []   # red  — all commands' cost if sent to cloud
    actual_cum   = []   # blue — only FI4 cloud cost (after router)
    expected_run = 0.0
    actual_run   = 0.0

    for name in names:
        per_cmd = all_sessions[name].get("per_cmd", [])
        for c in per_cmd:
            # Expected = every command's tokens cost money (no router)
            in_tok  = estimate_tokens(c["cmd"])
            out_tok = max(0, c["tokens"] - in_tok)
            expected_run += calc_cost(in_tok, out_tok)
            # Actual = only cloud agent costs money
            actual_run += c["cost_usd"]
            expected_cum.append(expected_run)
            actual_cum.append(actual_run)

    x_cmds = list(range(1, len(expected_cum) + 1))

    ax1.plot(x_cmds, expected_cum, color="#e74c3c", linewidth=2,
             label="Expected (all cmds to cloud)")
    ax1.plot(x_cmds, actual_cum,   color="#3498db", linewidth=2,
             label="Actual (FI4 only to cloud)")

    # Annotate finals
    if expected_cum:
        ax1.annotate(f"${expected_cum[-1]:.6f}",
                     xy=(x_cmds[-1], expected_cum[-1]),
                     xytext=(6, 4), textcoords="offset points",
                     color="#e74c3c", fontsize=9, fontweight="bold")
    if actual_cum:
        ax1.annotate(f"${actual_cum[-1]:.6f}",
                     xy=(x_cmds[-1], actual_cum[-1]),
                     xytext=(6, -14), textcoords="offset points",
                     color="#3498db", fontsize=9, fontweight="bold")

    # Budget line — zoom to data, show budget as text box if too far above
    data_max = max(expected_cum[-1] if expected_cum else 0,
                   actual_cum[-1] if actual_cum else 0, 0.000001)
    y_top = data_max * 1.35

    if MONTHLY_BUDGET <= y_top:
        ax1.axhline(MONTHLY_BUDGET, color="#2ecc71", linewidth=2,
                    label=f"Budget limit (${MONTHLY_BUDGET:.2f})")
    else:
        ax1.text(0.98, 0.97,
                 f"Budget: ${MONTHLY_BUDGET:.2f}\n(far above — costs are tiny)",
                 transform=ax1.transAxes, fontsize=9, color="#2ecc71",
                 ha="right", va="top",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                           edgecolor="#2ecc71", alpha=0.9))

    ax1.set_ylim(0, y_top)

    # Savings text box
    if expected_cum and actual_cum and expected_cum[-1] > 0:
        saved_pct = (1 - actual_cum[-1] / expected_cum[-1]) * 100
        ax1.text(0.02, 0.95,
                 f"Router saved {saved_pct:.1f}% of cloud cost",
                 transform=ax1.transAxes, fontsize=9, va="top",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                           edgecolor="#3498db", alpha=0.9))

    ax1.set_xlabel("Commands processed (all sessions)", fontsize=10)
    ax1.set_ylabel("Cumulative Cost (USD)", fontsize=10)
    ax1.set_title("(a) Cumulative Cost — Expected vs Actual\n"
                  "(Red=all to cloud, Blue=after router)", fontsize=10)
    ax1.legend(fontsize=8, loc="center left")
    ax1.grid(True, alpha=0.3)

    # Smart y-axis formatting
    import math
    if data_max > 0:
        decimals = max(4, -int(math.floor(math.log10(data_max))) + 2)
        ax1.yaxis.set_major_formatter(
            mticker.FuncFormatter(lambda v, _: f"${v:.{decimals}f}")
        )

    # ── Right: agent distribution stacked bar ─────────────────────────────────
    ax2 = axes[1]
    cowrie_pcts   = [all_sessions[name]["cowrie_pct"]   for name in names]
    ondevice_pcts = [all_sessions[name]["ondevice_pct"] for name in names]
    cloud_pcts    = [all_sessions[name]["cloud_pct"]    for name in names]

    ax2.bar(x, cowrie_pcts, label="Cowrie (FI0–1, $0)",
            color="#3498db", alpha=0.85, edgecolor="white")
    ax2.bar(x, ondevice_pcts, bottom=cowrie_pcts, label="On-device (FI2–3, $0)",
            color="#2ecc71", alpha=0.85, edgecolor="white")
    bottoms = [c + o for c, o in zip(cowrie_pcts, ondevice_pcts)]
    ax2.bar(x, cloud_pcts, bottom=bottoms, label="Cloud (FI4, paid)",
            color="#e74c3c", alpha=0.85, edgecolor="white")

    # Label cloud % on each bar
    for i, (cp, bot) in enumerate(zip(cloud_pcts, bottoms)):
        if cp > 0:
            ax2.text(i, bot + cp/2, f"{cp:.1f}%",
                     ha="center", va="center", fontsize=7, fontweight="bold", color="white")

    ax2.set_xticks(x)
    ax2.set_xticklabels(short_names, fontsize=8, rotation=45, ha="right")
    ax2.set_ylabel("% of Commands", fontsize=10)
    ax2.set_ylim(0, 105)
    ax2.set_title("(b) Agent Distribution per Session\n(Honey Router FI-based assignment)", fontsize=10)
    ax2.legend(fontsize=9, loc="upper right")
    ax2.grid(True, axis="y", alpha=0.3)
    ax2.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_session_cost.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"\n[✓] Saved → eval_session_cost.png")
    plt.close()

# ─── Figure 2: 3-line cumulative token graph (HoneyLLM design) ───────────────

# Token budget limit
BUDGET_TOKENS = int(MONTHLY_BUDGET / (OUTPUT_COST_PER_1M / 1_000_000))

def plot_cumulative_tokens(all_sessions: dict, all_raw_commands: dict):
    """
    HoneyLLM-style 3-line graph — ALL sessions merged in order:

      Red  line : Expected — cumulative tokens if ALL commands sent to cloud
      Blue line : Actual   — cumulative tokens of cloud-only commands (after router)
      Green line: Rate limit — budget cap in tokens (flat)
    """
    # Merge all sessions into one ordered list
    merged_cmds = []
    for name in all_sessions:
        per_cmd = all_sessions[name].get("per_cmd", [])
        for c in per_cmd:
            merged_cmds.append(c)

    if not merged_cmds:
        print("[!] No per-command data for cumulative graph")
        return

    # Build cumulative token series
    expected_cum = []   # red  — all commands' tokens
    actual_cum   = []   # blue — cloud-only tokens
    expected_run = 0
    actual_run   = 0

    for c in merged_cmds:
        expected_run += c["tokens"]
        actual_run   += c["tokens"] if c["agent"] == "cloud" else 0
        expected_cum.append(expected_run / 1000)   # → thousands
        actual_cum.append(actual_run / 1000)

    budget_k = BUDGET_TOKENS / 1000
    x = list(range(1, len(merged_cmds) + 1))

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle(
        "Session Cost Projection — Cumulative Token Consumption\n"
        "(all CyberLab + themed attack sessions merged)",
        fontsize=13, fontweight="bold"
    )

    # 3 lines
    ax.plot(x, expected_cum, color="#e74c3c", linewidth=2,
            label="Expected (all cmds → cloud)")
    ax.plot(x, actual_cum,   color="#3498db", linewidth=2,
            label="Actual (FI4 only → cloud, after router)")
    ax.axhline(budget_k,     color="#2ecc71", linewidth=2,
               label=f"Rate limit (${MONTHLY_BUDGET:.2f} budget ≈ {budget_k:.0f}K tokens)")

    # Annotate final values
    if expected_cum:
        ax.annotate(f"{expected_cum[-1]:.1f}K",
                    xy=(x[-1], expected_cum[-1]),
                    xytext=(6, 4), textcoords="offset points",
                    color="#e74c3c", fontsize=9, fontweight="bold")
    if actual_cum:
        ax.annotate(f"{actual_cum[-1]:.1f}K",
                    xy=(x[-1], actual_cum[-1]),
                    xytext=(6, -14), textcoords="offset points",
                    color="#3498db", fontsize=9, fontweight="bold")

    # Calculate savings
    if expected_cum and actual_cum:
        saved_pct = (1 - actual_cum[-1] / expected_cum[-1]) * 100 if expected_cum[-1] > 0 else 0
        ax.text(0.02, 0.95,
                f"Router saved {saved_pct:.1f}% of cloud tokens\n"
                f"({expected_cum[-1]:.1f}K expected → {actual_cum[-1]:.1f}K actual)",
                transform=ax.transAxes, fontsize=10,
                va="top", ha="left",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                          edgecolor="#3498db", alpha=0.9))

    ax.set_xlabel("Commands processed (all sessions)", fontsize=11)
    ax.set_ylabel("Tokens Consumed (Thousands)", fontsize=11)
    ax.set_title("Cumulative Token Consumption — Expected vs Actual (after Honey Router)",
                 fontsize=11)
    ax.legend(fontsize=10, loc="center left")
    ax.grid(True, alpha=0.3)

    max_y = max(max(expected_cum) if expected_cum else 0, budget_k) * 1.12
    ax.set_ylim(0, max_y)
    ax.set_xlim(0, len(x) + len(x) * 0.03)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_session_cost_tokens.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_session_cost_tokens.png")
    plt.close()

# ─── Main ─────────────────────────────────────────────────────────────────────

def run():
    print("\n" + "═"*60)
    print("  SESSION COST PROJECTION")
    print("═"*60)

    # Load all sessions
    print("\n── Loading CyberLab sessions ──")
    cyberlab = load_cyberlab_sessions()

    print("\n── Loading themed attack sessions ──")
    themed = load_themed_sessions()

    if not cyberlab and not themed:
        print("[!] No session data found — check paths")
        return

    # Analyse each session
    print("\n── Analysing sessions ──")
    all_sessions = {}
    all_raw = {}

    for name, cmds in cyberlab.items():
        all_sessions[name] = analyse_session(cmds)
        all_raw[name] = cmds

    for name, cmds in themed.items():
        all_sessions[name] = analyse_session(cmds)
        all_raw[name] = cmds

    # Print + plot
    print_summary(all_sessions)
    plot_session_cost(all_sessions)
    plot_cumulative_tokens(all_sessions, all_raw)

    print("\n[✓] Session cost projection complete.")

if __name__ == "__main__":
    run()