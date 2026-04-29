"""
evaluation/cost_analysis.py
─────────────────────────────────────────────────────────────────
Token + cost analysis for the honeypot system.

Model  : meta-llama/Llama-3.1-8B-Instruct via Novita
Pricing: Input  $0.02 / 1M tokens
         Output $0.05 / 1M tokens
Budget : $0.10 / month

Produces TWO figures:

  cost_analysis.png
    Left : Cumulative USD cost over commands (your original 3-line design)
             Red   = expected cost (if ALL commands sent to cloud)
             Blue  = actual cost   (cloud commands only)
             Green = budget limit  ($0.10)
    Right : Token usage by agent (grouped bar, input vs output)

  cost_analysis_compute.png
    Grouped bar per FI group showing:
      Left  Y-axis  = Cloud USD cost (estimated from text length)
      Right Y-axis  = On-device GFLOPs (actual logged values)
    → Makes the tradeoff visible:
      "We saved $X by NOT sending these commands to cloud LLM"

Token estimation for cloud (no token counts logged):
  in_tokens  = len(cmd)      // 4
  out_tokens = len(response) // 4

On-device token counts are exact (logged by eval_ondevice.py).
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

CLOUD_FILE      = "/mnt/data-partition/honeypot/evaluation/cloud_agent_dataset/cloud_chatGPT.json"
ONDEVICE_NEW    = "/mnt/data-partition/honeypot/evaluation/eval_ondevice_results_new_model.json"
ONDEVICE_OLD    = "/mnt/data-partition/honeypot/evaluation/eval_ondevice_results.json"
SESSION_LOG     = "/mnt/data-partition/honeypot/session_log.json"
OUTPUT_DIR      = "/mnt/data-partition/honeypot/evaluation/experiment_results"

INPUT_COST_PER_1M  = 0.02   # $ per 1M input tokens
OUTPUT_COST_PER_1M = 0.05   # $ per 1M output tokens
MONTHLY_BUDGET     = 0.10   # $

MAX_ENTRIES = 481
os.makedirs(OUTPUT_DIR, exist_ok=True)
scorer = FIScorer()

FI_COLORS  = ["#2ecc71", "#3498db", "#f39c12", "#e67e22", "#e74c3c"]
FI_XLABELS = [f"FI{fi}\n{FI_LABELS[fi][:8]}.." for fi in range(5)]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_json(path: str) -> list:
    if not os.path.exists(path):
        print(f"[!] Not found: {path}")
        return []
    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Parse error: {path}")
            return []
    data = data[:MAX_ENTRIES]
    print(f"[✓] Loaded {len(data):>4} entries ← {os.path.basename(path)}")
    return data

def estimate_tokens(text: str) -> int:
    """4 chars per token rule — used only when real token counts unavailable."""
    return len(text) // 4 if text else 0

def calc_cost(in_tok: int, out_tok: int) -> float:
    return (in_tok / 1_000_000 * INPUT_COST_PER_1M +
            out_tok / 1_000_000 * OUTPUT_COST_PER_1M)

def get_fi(cmd: str) -> int:
    fi, _ = scorer.score(cmd)
    return fi

# ─── Per-entry cost builders ──────────────────────────────────────────────────

def build_cloud_entries(cloud_data: list) -> list:
    """
    Cloud file has cmd + response text only — no token counts.
    Estimate tokens from character length (len // 4).
    Returns list of dicts with: cmd, fi, in_tok, out_tok, cost_usd
    """
    entries = []
    for r in cloud_data:
        cmd  = r.get("cmd", "")
        resp = r.get("response", "")
        in_tok  = estimate_tokens(cmd)
        out_tok = estimate_tokens(resp)
        entries.append({
            "cmd":      cmd,
            "fi":       get_fi(cmd),
            "in_tok":   in_tok,
            "out_tok":  out_tok,
            "cost_usd": calc_cost(in_tok, out_tok),
        })
    return entries

def build_ondevice_entries(ondevice_data: list, label: str) -> list:
    """
    On-device file has exact in_tokens, out_tokens, gflops per entry.
    Cost is $0 (runs on prof's machine) — but gflops is the compute cost.
    """
    entries = []
    for r in ondevice_data:
        if r.get("skipped"):
            continue
        cmd = r.get("cmd", "")
        entries.append({
            "cmd":     cmd,
            "fi":      get_fi(cmd),
            "in_tok":  r.get("in_tokens", estimate_tokens(cmd)),
            "out_tok": r.get("out_tokens", estimate_tokens(r.get("ondevice_output", ""))),
            "gflops":  r.get("gflops", 0.0),
            "latency": r.get("latency_ms", 0.0),
            "label":   label,
        })
    return entries

def build_session_entries(session_data: list) -> list:
    """
    Session log: real honeypot interactions.
    Cloud commands → estimate tokens from text.
    On-device / Cowrie → no USD cost (free).
    Used for the cumulative cost line graph.
    """
    entries = []
    for e in session_data:
        cmd    = e.get("cmd", "")
        resp   = e.get("response", "")
        agent  = e.get("agent", "unknown")
        in_tok  = estimate_tokens(cmd)
        out_tok = estimate_tokens(resp)
        # Only cloud commands have real USD cost
        actual_cost = calc_cost(in_tok, out_tok) if agent == "cloud" else 0.0
        # Estimated = what it WOULD cost if sent to cloud
        estimated_cost = calc_cost(in_tok, out_tok)
        entries.append({
            "cmd":            cmd,
            "agent":          agent,
            "in_tok":         in_tok,
            "out_tok":        out_tok,
            "actual_cost":    actual_cost,
            "estimated_cost": estimated_cost,
        })
    return entries

# ─── Print summaries ──────────────────────────────────────────────────────────

def print_cloud_summary(entries: list):
    total_in  = sum(e["in_tok"]   for e in entries)
    total_out = sum(e["out_tok"]  for e in entries)
    total_usd = sum(e["cost_usd"] for e in entries)
    print(f"\n{'═'*55}")
    print(f"  CLOUD LLM — TOKEN COST SUMMARY (estimated)")
    print(f"{'═'*55}")
    print(f"  Commands         : {len(entries)}")
    print(f"  Total in tokens  : {total_in:,}  (estimated from cmd length)")
    print(f"  Total out tokens : {total_out:,}  (estimated from response length)")
    print(f"  Total USD cost   : ${total_usd:.6f}")
    print(f"  Avg cost/cmd     : ${total_usd/len(entries):.8f}")
    print(f"  Budget           : ${MONTHLY_BUDGET:.2f}")
    print(f"  Budget used      : {total_usd/MONTHLY_BUDGET*100:.3f}%")
    print("═" * 55)

def print_ondevice_summary(entries: list, label: str):
    total_gflops = sum(e["gflops"] for e in entries)
    avg_latency  = sum(e["latency"] for e in entries) / len(entries) if entries else 0
    # What this compute would cost if rented (A100 ≈ $1.35/hr, ~312 TFLOPS → $0.0000000012/GFLOP)
    equivalent_usd = total_gflops * 0.0000000012
    print(f"\n{'═'*55}")
    print(f"  {label} — COMPUTE SUMMARY")
    print(f"{'═'*55}")
    print(f"  Commands         : {len(entries)}")
    print(f"  Total GFLOPs     : {total_gflops:,.1f}")
    print(f"  Avg GFLOPs/cmd   : {total_gflops/len(entries):.2f}")
    print(f"  Avg latency      : {avg_latency:.1f} ms")
    print(f"  Cloud equivalent : ~${equivalent_usd:.6f}  (A100 reference)")
    print(f"  Actual USD cost  : $0.00  (runs on local GPU)")
    print("═" * 55)

# ─── Figure 1: cost_analysis.png — matches HoneyLLM 3-line design ────────────

# Token budget limit: convert $0.10 budget → max tokens at avg blended rate
# Blended rate ≈ $0.035/1M tokens (mix of input/output) → 0.10/0.035 * 1M ≈ 2.86M tokens
# We keep it simple: budget_tokens = MONTHLY_BUDGET / (OUTPUT_COST_PER_1M/1_000_000)
BUDGET_TOKENS = int(MONTHLY_BUDGET / (OUTPUT_COST_PER_1M / 1_000_000))  # conservative upper bound

def plot_cost_analysis(session_entries: list, cloud_entries: list):
    """
    Matches HoneyLLM Figure 3-2 design:

      Y-axis : Tokens Consumed (Thousands)
      X-axis : Commands processed  (use timestamps from session_log if available)

      Red  line : Queries handled by Cowrie
                  = cumulative tokens of ALL commands (expected if all went to cloud)
      Blue line : Queries handled by Cloud LLM
                  = cumulative tokens of cloud-only commands (actual consumed)
      Green line: Query limit (rate limit / budget cap in tokens)
                  = flat horizontal line at BUDGET_TOKENS

    Right subplot: token usage breakdown by agent (grouped bar)
    """
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("Honeypot Cost Analysis — Token Consumption & Budget Tracking", fontsize=14)

    ax = axes[0]

    # ── Build cumulative token series ─────────────────────────────────────────
    if session_entries:
        all_tok_cum, cloud_tok_cum = [], []
        all_run = cloud_run = 0
        for e in session_entries:
            tok = e["in_tok"] + e["out_tok"]
            all_run   += tok
            cloud_run += tok if e["agent"] == "cloud" else 0
            all_tok_cum.append(all_run / 1000)      # → thousands
            cloud_tok_cum.append(cloud_run / 1000)

        x = list(range(1, len(session_entries) + 1))
        x_label = "Commands processed"

    else:
        # No session log — use cloud eval entries as the expected curve
        print("[!] No session log — using cloud eval set for token curves")
        all_tok_cum, cloud_tok_cum = [], []
        all_run = cloud_run = 0
        for e in cloud_entries:
            tok = e["in_tok"] + e["out_tok"]
            all_run   += tok
            cloud_run += tok   # eval = all cloud, so actual = expected here
            all_tok_cum.append(all_run / 1000)
            cloud_tok_cum.append(cloud_run / 1000)
        x = list(range(1, len(cloud_entries) + 1))
        x_label = "Commands processed (eval set)"

    budget_k = BUDGET_TOKENS / 1000   # flat line in thousands

    # ── Plot three lines ───────────────────────────────────────────────────────
    ax.plot(x, all_tok_cum,   color="#e74c3c", linewidth=2,
            label="Queries handled by Cowrie")           # red  — all traffic
    ax.plot(x, cloud_tok_cum, color="#3498db", linewidth=2,
            label="Queries handled by Cloud LLM")        # blue — cloud only
    ax.axhline(budget_k,      color="#2ecc71", linewidth=2,
               label=f"Query limit (${MONTHLY_BUDGET:.2f} budget ≈ {budget_k:.0f}K tokens)")  # green

    # Annotate final values at end of lines
    if all_tok_cum:
        ax.annotate(f"{all_tok_cum[-1]:.1f}K",
                    xy=(x[-1], all_tok_cum[-1]),
                    xytext=(6, 4), textcoords="offset points",
                    color="#e74c3c", fontsize=9, fontweight="bold")
    if cloud_tok_cum:
        ax.annotate(f"{cloud_tok_cum[-1]:.1f}K",
                    xy=(x[-1], cloud_tok_cum[-1]),
                    xytext=(6, 4), textcoords="offset points",
                    color="#3498db", fontsize=9, fontweight="bold")

    ax.set_xlabel(x_label, fontsize=11)
    ax.set_ylabel("Tokens Consumed (Thousands)", fontsize=11)
    ax.set_title("(a) Token Consumption Over Session", fontsize=12, pad=8)
    ax.legend(fontsize=10, loc="upper left", framealpha=0.9)
    ax.grid(True, alpha=0.3)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:.0f}"))

    # Make y-axis start at 0, give 10% headroom above max line
    max_y = max(max(all_tok_cum) if all_tok_cum else 0, budget_k) * 1.12
    ax.set_ylim(0, max_y)
    ax.set_xlim(0, len(x) + len(x) * 0.05)

    # ── Right: token usage by agent (grouped bar) ─────────────────────────────
    ax2 = axes[1]

    if session_entries:
        agent_data = defaultdict(lambda: {"in": 0, "out": 0, "count": 0})
        for e in session_entries:
            a = e["agent"]
            agent_data[a]["in"]    += e["in_tok"]
            agent_data[a]["out"]   += e["out_tok"]
            agent_data[a]["count"] += 1
        source_note = "(from session log)"
    else:
        # Fallback: show cloud eval tokens, label as cloud agent
        agent_data = defaultdict(lambda: {"in": 0, "out": 0, "count": 0})
        for e in cloud_entries:
            agent_data["cloud"]["in"]    += e["in_tok"]
            agent_data["cloud"]["out"]   += e["out_tok"]
            agent_data["cloud"]["count"] += 1
        source_note = "(eval set — no session log)"

    agents   = list(agent_data.keys())
    in_toks  = [agent_data[a]["in"]    for a in agents]
    out_toks = [agent_data[a]["out"]   for a in agents]
    counts   = [agent_data[a]["count"] for a in agents]
    xpos     = np.arange(len(agents))
    w        = 0.35

    bars_in  = ax2.bar(xpos - w/2, [v/1000 for v in in_toks],  w,
                       label="Input tokens",  color="#3498db", alpha=0.85)
    bars_out = ax2.bar(xpos + w/2, [v/1000 for v in out_toks], w,
                       label="Output tokens", color="#e74c3c", alpha=0.85)

    for bar, val in zip(list(bars_in) + list(bars_out),
                        [v/1000 for v in in_toks] + [v/1000 for v in out_toks]):
        if val > 0:
            ax2.text(bar.get_x() + bar.get_width()/2,
                     bar.get_height() + max(0.2, bar.get_height()*0.02),
                     f"{val:.1f}K", ha="center", va="bottom", fontsize=8)

    ax2.set_xticks(xpos)
    ax2.set_xticklabels([f"{a}\n(n={c})" for a, c in zip(agents, counts)], fontsize=9)
    ax2.set_ylabel("Tokens (Thousands)", fontsize=11)
    ax2.set_title(f"(b) Token Usage by Agent\n{source_note}", fontsize=12, pad=8)
    ax2.legend(fontsize=10)
    ax2.grid(True, axis="y", alpha=0.3)
    ax2.set_ylim(0)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "cost_analysis.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → cost_analysis.png")
    plt.close()

# ─── Figure 2: cost_analysis_compute.png — all agents in USD (single Y-axis) ──

# GFLOPs → USD equivalent conversion
# A100 GPU ≈ $1.35/hr (Hyperstack, 2025) at ~312 TFLOPS (NVIDIA A100 Datasheet)
# → $1.35 / (312,000 GFLOPs/sec × 3600 sec) ≈ $0.0000000012 per GFLOP
GFLOP_TO_USD = 0.0000000012

def gflops_to_usd(gflops: float) -> float:
    """Convert GFLOPs to USD equivalent (A100 cloud rental reference price)."""
    return gflops * GFLOP_TO_USD

def plot_compute_vs_cost(cloud_entries: list,
                         ondevice_old: list,
                         ondevice_new: list):
    """
    ALL costs in USD on a single Y-axis — fully comparable:

      Cloud        → real token API cost  ($0.02/1M in, $0.05/1M out)
      On-device    → GFLOPs × A100 rental rate → USD equivalent
                     (actual cost = $0, but shows "what it would cost to rent")

    Two subplots:
      Left : Grouped bar per FI — 3 bars all in USD
      Right: Cumulative USD lines over commands — all 3 agents same axis
    """
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle(
        "Cost Tradeoff — All Agents Normalised to USD\n"
        "Cloud = token API cost  |  On-device = GFLOPs x A100 rental rate ($1.35/hr reference)",
        fontsize=12
    )

    # ── Convert everything to USD per FI ──────────────────────────────────────
    cloud_fi_usd   = defaultdict(float)
    old_fi_usd     = defaultdict(float)
    new_fi_usd     = defaultdict(float)

    for e in cloud_entries:
        cloud_fi_usd[e["fi"]] += e["cost_usd"]
    for e in ondevice_old:
        old_fi_usd[e["fi"]]   += gflops_to_usd(e["gflops"])
    for e in ondevice_new:
        new_fi_usd[e["fi"]]   += gflops_to_usd(e["gflops"])

    fi_range   = list(range(5))
    cloud_vals = [cloud_fi_usd.get(fi, 0) for fi in fi_range]
    old_vals   = [old_fi_usd.get(fi, 0)   for fi in fi_range]
    new_vals   = [new_fi_usd.get(fi, 0)   for fi in fi_range]

    # ── Left: grouped bar — single Y-axis, all USD ────────────────────────────
    ax1 = axes[0]
    x   = np.arange(5)
    bw  = 0.25

    b1 = ax1.bar(x - bw,  cloud_vals, bw, label="Cloud (token API cost)",
                 color="#e74c3c", alpha=0.85, edgecolor="white")
    b2 = ax1.bar(x,       old_vals,   bw, label="On-device old (GFLOPs → USD equiv.)",
                 color="#e67e22", alpha=0.80, hatch="//", edgecolor="white")
    b3 = ax1.bar(x + bw,  new_vals,   bw, label="On-device new (GFLOPs → USD equiv.)",
                 color="#2ecc71", alpha=0.80, hatch="xx", edgecolor="white")

    # Value labels
    for bars, vals in [(b1, cloud_vals), (b2, old_vals), (b3, new_vals)]:
        for bar, v in zip(bars, vals):
            if v > 0:
                ax1.text(bar.get_x() + bar.get_width()/2,
                         bar.get_height() + max(v * 0.02, 1e-9),
                         f"${v:.6f}", ha="center", va="bottom",
                         fontsize=6, rotation=45)

    ax1.set_xticks(x)
    ax1.set_xticklabels(FI_XLABELS, fontsize=9)
    ax1.set_ylabel("Cost (USD)", fontsize=11)
    ax1.set_title("(a) Cost per FI Group — All Agents in USD\n"
                  "(on-device converted from GFLOPs at A100 rate)", fontsize=10)
    ax1.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"${v:.6f}"))
    ax1.legend(fontsize=9, loc="upper right")
    ax1.grid(True, axis="y", alpha=0.3)
    ax1.set_ylim(0)

    # ── Right: cumulative lines — all in USD, single Y-axis ──────────────────
    ax2 = axes[1]

    # Cloud cumulative
    cloud_cum, r = [], 0.0
    for e in cloud_entries:
        r += e["cost_usd"]
        cloud_cum.append(r)

    # On-device old cumulative (GFLOPs → USD)
    old_cum, r2 = [], 0.0
    for e in ondevice_old:
        r2 += gflops_to_usd(e["gflops"])
        old_cum.append(r2)

    # On-device new cumulative (GFLOPs → USD)
    new_cum, r3 = [], 0.0
    for e in ondevice_new:
        r3 += gflops_to_usd(e["gflops"])
        new_cum.append(r3)

    x_c = list(range(1, len(cloud_cum) + 1))
    x_o = list(range(1, len(old_cum)   + 1))
    x_n = list(range(1, len(new_cum)   + 1))

    ax2.plot(x_c, cloud_cum, color="#e74c3c", linewidth=2,
             label=f"Cloud  (total: ${cloud_cum[-1]:.6f})" if cloud_cum else "Cloud")
    ax2.plot(x_o, old_cum,   color="#e67e22", linewidth=1.5, linestyle="--",
             label=f"On-device old  (total: ${old_cum[-1]:.6f})" if old_cum else "Old")
    ax2.plot(x_n, new_cum,   color="#2ecc71", linewidth=2,
             label=f"On-device new  (total: ${new_cum[-1]:.6f})" if new_cum else "New")

    # Y-axis: zoom to actual data range with 35% headroom for labels
    all_finals = [c[-1] for c in [cloud_cum, old_cum, new_cum] if c]
    data_max   = max(all_finals) if all_finals else 0.001
    y_top      = data_max * 1.35

    ax2.set_ylim(0, y_top)

    # Budget line — draw only if it fits in view, otherwise show as text box
    if MONTHLY_BUDGET <= y_top:
        ax2.axhline(MONTHLY_BUDGET, color="#3498db", linewidth=1.5,
                    linestyle=":", label=f"Budget limit (${MONTHLY_BUDGET:.2f})")
    else:
        ax2.text(0.98, 0.97,
                 f"Budget limit: ${MONTHLY_BUDGET:.2f}\n(way above chart scale — costs are tiny)",
                 transform=ax2.transAxes, fontsize=8, color="#3498db",
                 ha="right", va="top",
                 bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                           edgecolor="#3498db", alpha=0.9))

    # Annotate final totals at end of each line
    for cum, color in [
        (cloud_cum, "#e74c3c"),
        (old_cum,   "#e67e22"),
        (new_cum,   "#2ecc71"),
    ]:
        if cum:
            ax2.annotate(f"${cum[-1]:.6f}",
                         xy=(len(cum), cum[-1]),
                         xytext=(6, 4), textcoords="offset points",
                         color=color, fontsize=8, fontweight="bold")

    ax2.set_xlabel("Command index", fontsize=11)
    ax2.set_ylabel("Cumulative Cost (USD)", fontsize=11)
    ax2.set_title("(b) Cumulative Cost Over Evaluation — All Agents\n"
                  "(on-device GFLOPs converted to USD equivalent)", fontsize=10)

    import math
    decimals = max(4, -int(math.floor(math.log10(data_max))) + 2) if data_max > 0 else 6
    ax2.yaxis.set_major_formatter(
        mticker.FuncFormatter(lambda v, _: f"${v:.{decimals}f}")
    )
    ax2.legend(fontsize=9, loc="upper left")
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "cost_analysis_compute.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → cost_analysis_compute.png")
    plt.close()

# ─── Main ─────────────────────────────────────────────────────────────────────

def run():
    print("\n" + "═"*60)
    print("  COST ANALYSIS")
    print("═"*60)

    # Load data
    cloud_raw      = load_json(CLOUD_FILE)
    ondevice_old_r = load_json(ONDEVICE_OLD)
    ondevice_new_r = load_json(ONDEVICE_NEW)
    session_raw    = load_json(SESSION_LOG) if os.path.exists(SESSION_LOG) else []

    if not cloud_raw and not ondevice_old_r:
        print("[!] No data loaded — check file paths")
        return

    # Build per-entry cost structures
    cloud_entries   = build_cloud_entries(cloud_raw)       if cloud_raw      else []
    ondevice_old    = build_ondevice_entries(ondevice_old_r, "On-Device Old") if ondevice_old_r else []
    ondevice_new    = build_ondevice_entries(ondevice_new_r, "On-Device New") if ondevice_new_r else []
    session_entries = build_session_entries(session_raw)   if session_raw    else []

    # Print summaries
    if cloud_entries:
        print_cloud_summary(cloud_entries)
    if ondevice_old:
        print_ondevice_summary(ondevice_old, "ON-DEVICE (Old model — Qwen 1.5B)")
    if ondevice_new:
        print_ondevice_summary(ondevice_new, "ON-DEVICE (New model — Qwen 7B GGUF)")

    # Quick tradeoff print
    if cloud_entries and ondevice_new:
        cloud_total = sum(e["cost_usd"] for e in cloud_entries)
        new_gflops  = sum(e["gflops"]   for e in ondevice_new)
        cloud_equiv = new_gflops * 0.0000000012
        print(f"\n{'═'*55}")
        print(f"  COST TRADEOFF SUMMARY")
        print(f"{'═'*55}")
        print(f"  Cloud cost (481 cmds)       : ${cloud_total:.6f}")
        print(f"  On-device GFLOPs used       : {new_gflops:,.1f}")
        print(f"  Cloud-equiv compute cost    : ~${cloud_equiv:.6f}  (A100 ref)")
        print(f"  Savings vs all-cloud        : ${cloud_total - 0:.6f}  (on-device = $0)")
        print(f"  Budget remaining            : ${MONTHLY_BUDGET - cloud_total:.6f}")
        print("═" * 55)

    # Plot Figure 1 — original 3-line design
    plot_cost_analysis(session_entries, cloud_entries)

    # Plot Figure 2 — compute vs cost tradeoff
    if cloud_entries and (ondevice_old or ondevice_new):
        plot_compute_vs_cost(cloud_entries, ondevice_old, ondevice_new)

    print("\n[✓] Done — 2 figures saved to experiment_results/")

if __name__ == "__main__":
    run()