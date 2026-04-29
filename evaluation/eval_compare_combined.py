"""
evaluation/eval_combined_compare.py
─────────────────────────────────────────────────────────────────
Produces 3 combined figures for the report:

  Fig 1 → eval_comparison_main.png
    Row 1: Latency by FI — all agents side by side (grouped bar)
    Row 2: Fidelity metrics by FI — all agents side by side (4 subplots)
    Row 3: LLM-as-a-Judge realism by FI — all agents side by side (grouped bar)

  Fig 2 → eval_ondevice_compute.png
    Row 1: GFLOPs vs Latency scatter — old vs new model
    Row 2: VRAM over session — old vs new model

  Fig 3 → eval_model_delta.png
    % improvement (new model vs old model) per metric per FI group

Run:
  cd evaluation
  python eval_combined_compare.py
─────────────────────────────────────────────────────────────────
"""

import json
import os
import sys
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fidelity import score_all
from fi_manager import FIScorer, FI_LABELS

# ─── Config ───────────────────────────────────────────────────────────────────

ONDEVICE_OLD_FILE  = "eval_ondevice_results.json"
ONDEVICE_NEW_FILE  = "eval_ondevice_results_new_model.json"
COWRIE_FILE        = "eval_cowrie_results.json"
CLOUD_RESPONSE_FILE = "/mnt/data-partition/honeypot/evaluation/cloud_agent_dataset/cloud_chatGPT.json"

LLM_JUDGE_DIR = "LLM_as_a_Judge"

# Both judges loaded separately — averaged per agent per FI group
REALISM_PATHS_CLAUDE = {
    "Cowrie":        f"{LLM_JUDGE_DIR}/claudeAI/cowrie/cowrie.json",
    "On-Device Old": f"{LLM_JUDGE_DIR}/claudeAI/ondevice.json",
    "On-Device New": f"{LLM_JUDGE_DIR}/claudeAI/new_model_ondevice/ondevice.json",
    "Cloud":         f"{LLM_JUDGE_DIR}/claudeAI/cloud.json",
}
REALISM_PATHS_CHATGPT = {
    "Cowrie":        f"{LLM_JUDGE_DIR}/chatGPT/cowrie/cowrie.json",
    "On-Device Old": f"{LLM_JUDGE_DIR}/chatGPT/ondevice.json",
    "On-Device New": f"{LLM_JUDGE_DIR}/chatGPT/new_model_ondevice/ondevice.json",
    # Cloud — ChatGPT judge not available, Claude only
}

OUTPUT_DIR  = "/mnt/data-partition/honeypot/evaluation/experiment_results"
MAX_ENTRIES = 481
START_INDEX = 0

scorer = FIScorer()
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Agent display config — name, color, hatch pattern (secondary encoding for accessibility)
AGENTS = [
    {"key": "cowrie",       "label": "Cowrie",          "color": "#3498db", "hatch": ""},
    {"key": "ondevice_old", "label": "On-Device (Old)",  "color": "#e67e22", "hatch": "//"},
    {"key": "ondevice_new", "label": "On-Device (New)",  "color": "#2ecc71", "hatch": "xx"},
    {"key": "cloud",        "label": "Cloud LLM",        "color": "#9b59b6", "hatch": ".."},
]

FI_XLABELS = [f"FI{fi}\n{FI_LABELS[fi][:8]}.." for fi in range(5)]

# ─── Load helpers ─────────────────────────────────────────────────────────────

def load_json(path: str, limit=True) -> list:
    if not os.path.exists(path):
        print(f"[!] Not found: {path}")
        return []
    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Parse error: {path}")
            return []
    if limit and MAX_ENTRIES:
        data = data[START_INDEX:START_INDEX + MAX_ENTRIES]
    print(f"[✓] Loaded {len(data):>4} ← {os.path.basename(path)}")
    return data

def group_by_fi(results: list, cmd_key="cmd") -> dict:
    groups = defaultdict(list)
    for r in results:
        cmd = r.get(cmd_key) or r.get("command", "")
        fi, _ = scorer.score(cmd)
        r["fi"] = fi
        groups[fi].append(r)
    return groups

def group_realism_by_fi(data: list) -> dict:
    groups = defaultdict(list)
    for d in data:
        score = d.get("realism_score")
        if score is None:
            continue
        cmd = d.get("command", d.get("cmd", ""))
        fi, _ = scorer.score(cmd)
        groups[fi].append(score)
    return groups

def fi_avg(groups, fi, key):
    g = groups.get(fi, [])
    vals = [r.get(key, 0) for r in g if r.get(key) is not None]
    return sum(vals) / len(vals) if vals else 0

def fi_latency_avg(groups, fi):
    g = groups.get(fi, [])
    vals = [r["latency_ms"] for r in g if r.get("latency_ms")]
    return sum(vals) / len(vals) if vals else 0

def fi_count(groups, fi):
    return len(groups.get(fi, []))

# ─── Load + score all agents ──────────────────────────────────────────────────

def load_all():
    results = {}

    # Cowrie
    cowrie_raw = load_json(COWRIE_FILE)
    if cowrie_raw:
        cowrie_scored = score_all(cowrie_raw, method="all", output_key="cowrie_output")
        results["cowrie"] = {"scored": cowrie_scored, "groups": group_by_fi(cowrie_scored)}

    # On-Device Old
    old_raw = load_json(ONDEVICE_OLD_FILE)
    if old_raw:
        old_scored = score_all(old_raw, method="all", output_key="ondevice_output")
        results["ondevice_old"] = {"scored": old_scored, "groups": group_by_fi(old_scored)}

    # On-Device New
    new_raw = load_json(ONDEVICE_NEW_FILE)
    if new_raw:
        # pull ground_truth from old results by cmd
        if old_raw:
            gt_lookup = {r["cmd"]: r.get("ground_truth", "") for r in old_raw}
            for r in new_raw:
                r["ground_truth"] = gt_lookup.get(r["cmd"], "")
        new_scored = score_all(new_raw, method="all", output_key="ondevice_output")
        results["ondevice_new"] = {"scored": new_scored, "groups": group_by_fi(new_scored)}

    # Cloud
    cloud_raw = load_json(CLOUD_RESPONSE_FILE)
    if cloud_raw:
        gt_lookup = {}
        for src in [old_raw or [], cowrie_raw or []]:
            for r in src:
                cmd = r.get("cmd", "")
                if cmd and cmd not in gt_lookup:
                    gt_lookup[cmd] = r.get("ground_truth", r.get("cowrie_output", ""))
        for r in cloud_raw:
            r["ground_truth"] = gt_lookup.get(r.get("cmd", ""), "")
        cloud_scored = score_all(
            [{"cmd": r.get("cmd",""), "ground_truth": r.get("ground_truth",""), "cloud_output": r.get("response","")}
             for r in cloud_raw],
            method="all", output_key="cloud_output"
        )
        results["cloud"] = {"scored": cloud_scored, "groups": group_by_fi(cloud_scored)}

    # Realism — load both judges, average scores per agent per FI
    realism_claude  = {}
    realism_chatgpt = {}
    for name, path in REALISM_PATHS_CLAUDE.items():
        data = load_json(path)
        if data:
            realism_claude[name] = group_realism_by_fi(data)
    for name, path in REALISM_PATHS_CHATGPT.items():
        data = load_json(path)   # load_json already handles missing/empty files
        if data:
            realism_chatgpt[name] = group_realism_by_fi(data)

    # Merge: combine scores from both judges into one list per agent per FI
    all_agent_names = set(list(realism_claude.keys()) + list(realism_chatgpt.keys()))
    realism = {}
    for name in all_agent_names:
        merged = defaultdict(list)
        for fi in range(5):
            merged[fi] += realism_claude.get(name,  {}).get(fi, [])
            merged[fi] += realism_chatgpt.get(name, {}).get(fi, [])
        realism[name] = dict(merged)

    loaded_judges = []
    if realism_claude:  loaded_judges.append("Claude")
    if realism_chatgpt: loaded_judges.append("ChatGPT")
    print(f"[INFO] Realism judges loaded: {loaded_judges} — scores averaged per agent/FI")

    return results, realism

# ─── Figure 1: Main Comparison ────────────────────────────────────────────────

def plot_main_comparison(results: dict, realism: dict):
    """
    2-row figure (realism moved to separate figure):
      Row 1 (1 plot):  Latency by FI — all agents grouped bar
      Row 2 (4 plots): Fidelity metric by FI — one subplot per metric
    """
    present = [a for a in AGENTS if a["key"] in results]
    n_agents = len(present)
    x = np.arange(5)
    bar_w = 0.7 / n_agents

    fig = plt.figure(figsize=(18, 10))
    fig.suptitle("Agent Comparison — Latency and Fidelity by FI Group",
                 fontsize=15, fontweight="bold", y=0.98)

    # ── Row 1: Latency ────────────────────────────────────────────────────────
    ax_lat = fig.add_subplot(2, 1, 1)
    for i, agent in enumerate(present):
        groups = results[agent["key"]]["groups"]
        vals   = [fi_latency_avg(groups, fi) for fi in range(5)]
        offset = (i - n_agents/2 + 0.5) * bar_w
        bars   = ax_lat.bar(x + offset, vals, bar_w,
                            label=agent["label"],
                            color=agent["color"],
                            hatch=agent["hatch"],
                            alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            if v > 0:
                ax_lat.text(bar.get_x() + bar.get_width()/2,
                            bar.get_height() + 5,
                            f"{v:.0f}", ha="center", va="bottom", fontsize=7)

    ax_lat.set_xticks(x)
    ax_lat.set_xticklabels(FI_XLABELS, fontsize=9)
    ax_lat.set_ylabel("Avg Latency (ms)", fontsize=10)
    ax_lat.set_title("(a) Latency Comparison by FI Group", fontsize=11, pad=6)
    ax_lat.legend(fontsize=9, loc="upper left")
    ax_lat.grid(True, axis="y", alpha=0.3)
    ax_lat.set_yscale("symlog", linthresh=500)
    ax_lat.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{int(v):,}ms"))

    # ── Row 2: Fidelity (4 subplots) ─────────────────────────────────────────
    METRICS = [
        ("Cosine Similarity",  "cosine_score",   "(b)"),
        ("Sequence Score",     "sequence_score", "(c)"),
        ("BLEU Score",         "bleu_score",     "(d)"),
        ("BERTScore F1",       "bert_f1",        "(e)"),
    ]
    for col, (metric_label, metric_key, subfig_label) in enumerate(METRICS):
        ax = fig.add_subplot(2, 4, 5 + col)
        for i, agent in enumerate(present):
            groups = results[agent["key"]]["groups"]
            vals   = [fi_avg(groups, fi, metric_key) for fi in range(5)]
            offset = (i - n_agents/2 + 0.5) * bar_w
            ax.bar(x + offset, vals, bar_w,
                   color=agent["color"],
                   hatch=agent["hatch"],
                   alpha=0.85, edgecolor="white",
                   label=agent["label"])
        ax.set_xticks(x)
        ax.set_xticklabels(FI_XLABELS, fontsize=8)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Score (0–1)", fontsize=9)
        ax.set_title(f"{subfig_label} {metric_label}", fontsize=10, pad=4)
        ax.grid(True, axis="y", alpha=0.3)
        if col == 0:
            ax.legend(fontsize=7, loc="upper right")

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    out = os.path.join(OUTPUT_DIR, "eval_comparison_main.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_comparison_main.png")
    plt.close()

# ─── Figure 2: On-Device Compute (old vs new) ─────────────────────────────────

def plot_compute_comparison(results: dict):
    """
    2-row figure comparing compute metrics old vs new model:
      Row 1: GFLOPs vs Latency scatter (old | new)
      Row 2: VRAM over session (old vs new, same axes)
    """
    old_results = results.get("ondevice_old", {}).get("scored", [])
    new_results = results.get("ondevice_new", {}).get("scored", [])

    if not old_results and not new_results:
        print("[!] No on-device results, skipping compute figure")
        return

    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    fig.suptitle("On-Device LLM — Compute Comparison: Old vs New Model",
                 fontsize=13, fontweight="bold")

    # ── GFLOPs vs Latency (old) ───────────────────────────────────────────────
    def scatter_gflops(ax, res, title, color_map):
        data = [(r["gflops"], r["latency_ms"], r.get("out_tokens", 0))
                for r in res if r.get("gflops") and r.get("latency_ms")]
        if not data:
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_title(title)
            return
        g, l, t = zip(*data)
        sc = ax.scatter(g, l, c=t, cmap=color_map, alpha=0.65, s=30)
        plt.colorbar(sc, ax=ax).set_label("Output tokens", fontsize=8)
        ax.axvline(np.mean(g), color="red",    linestyle="--", linewidth=1, label=f"Avg GFLOPs {np.mean(g):.0f}")
        ax.axhline(np.mean(l), color="orange", linestyle="--", linewidth=1, label=f"Avg Latency {np.mean(l):.0f}ms")
        ax.set_xlabel("GFLOPs")
        ax.set_ylabel("Latency (ms)")
        ax.set_title(title)
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3)

    scatter_gflops(axes[0][0], old_results, "(a) GFLOPs vs Latency — Old Model", "Blues")
    scatter_gflops(axes[0][1], new_results, "(b) GFLOPs vs Latency — New Model", "Greens")

    # ── VRAM over session (overlaid, old vs new) ───────────────────────────────
    ax_vram = axes[1][0]
    for res, label, color, ls in [
        (old_results, "Old model (Qwen 1.5B)", "#e67e22", "-"),
        (new_results, "New model (Qwen 7B GGUF)", "#2ecc71", "--"),
    ]:
        vram_pts = [(i+1, r["vram_after_mb"]) for i, r in enumerate(res)
                    if r.get("vram_after_mb") is not None]
        if vram_pts:
            idx, vrams = zip(*vram_pts)
            ax_vram.plot(idx, vrams, color=color, linestyle=ls, linewidth=1.5, label=label)
            ax_vram.axhline(np.mean(vrams), color=color, linestyle=":", linewidth=1,
                            alpha=0.6, label=f"Avg {np.mean(vrams):.0f} MB")
    ax_vram.set_xlabel("Command Index")
    ax_vram.set_ylabel("VRAM (MB)")
    ax_vram.set_title("(c) VRAM Usage Over Session (old vs new)")
    ax_vram.legend(fontsize=8)
    ax_vram.grid(True, alpha=0.3)
    ax_vram.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{int(v)} MB"))

    # ── Latency distribution (box plot old vs new per FI) ─────────────────────
    ax_box = axes[1][1]
    old_groups = results.get("ondevice_old", {}).get("groups", {})
    new_groups = results.get("ondevice_new", {}).get("groups", {})
    x = np.arange(5)
    bw = 0.3
    for fi in range(5):
        old_vals = [r["latency_ms"] for r in old_groups.get(fi, []) if r.get("latency_ms")]
        new_vals = [r["latency_ms"] for r in new_groups.get(fi, []) if r.get("latency_ms")]
        if old_vals:
            bp_old = ax_box.boxplot(old_vals, positions=[fi - bw/2], widths=bw*0.8,
                                    patch_artist=True,
                                    boxprops=dict(facecolor="#e67e22", alpha=0.6),
                                    medianprops=dict(color="black"),
                                    whiskerprops=dict(color="#e67e22"),
                                    capprops=dict(color="#e67e22"),
                                    flierprops=dict(marker=".", markersize=3, alpha=0.4))
        if new_vals:
            bp_new = ax_box.boxplot(new_vals, positions=[fi + bw/2], widths=bw*0.8,
                                    patch_artist=True,
                                    boxprops=dict(facecolor="#2ecc71", alpha=0.6),
                                    medianprops=dict(color="black"),
                                    whiskerprops=dict(color="#2ecc71"),
                                    capprops=dict(color="#2ecc71"),
                                    flierprops=dict(marker=".", markersize=3, alpha=0.4))
    ax_box.set_xticks(x)
    ax_box.set_xticklabels(FI_XLABELS, fontsize=8)
    ax_box.set_ylabel("Latency (ms)")
    ax_box.set_title("(d) Latency Distribution by FI (old vs new)")
    ax_box.grid(True, axis="y", alpha=0.3)
    legend_patches = [
        mpatches.Patch(facecolor="#e67e22", alpha=0.6, label="Old model (Qwen 1.5B)"),
        mpatches.Patch(facecolor="#2ecc71", alpha=0.6, label="New model (Qwen 7B GGUF)"),
    ]
    ax_box.legend(handles=legend_patches, fontsize=8)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_ondevice_compute.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_ondevice_compute.png")
    plt.close()

# ─── Figure 3: Model Delta (old → new improvement) ────────────────────────────

def plot_model_delta(results: dict):
    """
    % change in fidelity scores from old → new model, per FI group.
    Positive = improvement, negative = regression.
    """
    old_groups = results.get("ondevice_old", {}).get("groups", {})
    new_groups = results.get("ondevice_new", {}).get("groups", {})
    if not old_groups or not new_groups:
        print("[!] Need both old and new model results for delta figure")
        return

    METRICS = [
        ("Cosine",   "cosine_score",   "#3498db"),
        ("Sequence", "sequence_score", "#2ecc71"),
        ("BLEU",     "bleu_score",     "#e67e22"),
        ("BERT F1",  "bert_f1",        "#9b59b6"),
    ]
    x     = np.arange(5)
    bar_w = 0.18

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.suptitle("On-Device LLM — Fidelity Improvement: Old → New Model (%)",
                 fontsize=13, fontweight="bold")

    for i, (label, key, color) in enumerate(METRICS):
        deltas = []
        for fi in range(5):
            old_v = fi_avg(old_groups, fi, key)
            new_v = fi_avg(new_groups, fi, key)
            if old_v > 0:
                delta = ((new_v - old_v) / old_v) * 100
            else:
                delta = 0
            deltas.append(delta)
        offset = (i - len(METRICS)/2 + 0.5) * bar_w
        bars = ax.bar(x + offset, deltas, bar_w, label=label, color=color, alpha=0.85, edgecolor="white")
        for bar, d in zip(bars, deltas):
            if abs(d) > 1:
                ax.text(bar.get_x() + bar.get_width()/2,
                        bar.get_height() + (1.5 if d >= 0 else -4),
                        f"{d:+.1f}%", ha="center", va="bottom", fontsize=7)

    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(FI_XLABELS, fontsize=9)
    ax.set_ylabel("% Change (positive = improvement)", fontsize=10)
    ax.set_title("Fidelity Score % Change: Old → New Model by FI Group", fontsize=11)
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(True, axis="y", alpha=0.3)

    # Add a light shading for positive region
    ylim = ax.get_ylim()
    ax.axhspan(0, ylim[1] if ylim[1] > 0 else 100, alpha=0.04, color="green")
    ax.axhspan(ylim[0] if ylim[0] < 0 else -50, 0,  alpha=0.04, color="red")

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_model_delta.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_model_delta.png")
    plt.close()


# ─── Figure 4: LLM-as-a-Judge Realism (standalone) ───────────────────────────

def plot_realism_comparison(results: dict, realism: dict):
    """
    Standalone realism figure for section 4.1.1.4.
    Scores are averaged across BOTH Claude and ChatGPT judges.
    Two subplots:
      Left : Grouped bar per FI — all agents, avg of both judges
      Right: Per-judge breakdown — shows Claude vs ChatGPT agree
    """
    present = [a for a in AGENTS if a["key"] in results]
    n_agents = len(present)
    x = np.arange(5)
    bar_w = 0.7 / n_agents

    realism_agent_map = {
        "cowrie":       "Cowrie",
        "ondevice_old": "On-Device Old",
        "ondevice_new": "On-Device New",
        "cloud":        "Cloud",
    }

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle(
        "LLM-as-a-Judge Realism Comparison by FI Group\n"
        "(scores averaged across Claude Sonnet 4.6 and ChatGPT-5 judges)",
        fontsize=13, fontweight="bold"
    )

    # ── Left: averaged scores all agents ─────────────────────────────────────
    ax = axes[0]
    for i, agent in enumerate(present):
        r_key  = realism_agent_map.get(agent["key"])
        groups = realism.get(r_key, {})
        vals   = [
            (sum(groups[fi]) / len(groups[fi])) if groups.get(fi) else 0
            for fi in range(5)
        ]
        offset = (i - n_agents/2 + 0.5) * bar_w
        bars = ax.bar(x + offset, vals, bar_w,
                      label=agent["label"],
                      color=agent["color"],
                      hatch=agent["hatch"],
                      alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2,
                        bar.get_height() + 0.05,
                        f"{v:.2f}", ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x)
    ax.set_xticklabels(FI_XLABELS, fontsize=9)
    ax.set_ylim(0, 5.5)
    ax.set_ylabel("Avg Realism Score (1–5)", fontsize=11)
    ax.set_title("(a) Realism by FI Group — All Agents\n(avg of both judges)", fontsize=10)
    ax.axhline(y=3.0, color="gray", linestyle="--", linewidth=1, alpha=0.5, label="Midpoint (3.0)")
    ax.legend(fontsize=9, loc="upper left")
    ax.grid(True, axis="y", alpha=0.3)

    # ── Right: per-judge side-by-side to show agreement ──────────────────────
    ax2 = axes[1]
    judge_colors = {"Claude": "#3498db", "ChatGPT": "#e67e22"}
    judge_hatches = {"Claude": "", "ChatGPT": "//"}

    # Build per-judge per-agent avg (collapsed across FI for simplicity)
    from collections import defaultdict as dd2
    # reload individual judge data for this subplot
    claude_per_agent  = {}
    chatgpt_per_agent = {}

    import json as _json

    def _safe_load(path):
        try:
            with open(path) as f:
                raw = f.read().strip()
            if not raw:
                print(f"[!] Skipping empty file: {path}")
                return []
            return _json.loads(raw)[:MAX_ENTRIES]
        except Exception as e:
            print(f"[!] Skipping invalid file: {path} ({e})")
            return []

    for name, path in REALISM_PATHS_CLAUDE.items():
        if os.path.exists(path):
            data = _safe_load(path)
            scores = [d.get("realism_score") for d in data if d.get("realism_score") is not None]
            if scores:
                claude_per_agent[name] = sum(scores) / len(scores)

    for name, path in REALISM_PATHS_CHATGPT.items():
        if os.path.exists(path):
            data = _safe_load(path)
            scores = [d.get("realism_score") for d in data if d.get("realism_score") is not None]
            if scores:
                chatgpt_per_agent[name] = sum(scores) / len(scores)

    agent_labels = [realism_agent_map[a["key"]] for a in present
                    if realism_agent_map.get(a["key"]) in
                    (set(claude_per_agent) | set(chatgpt_per_agent))]
    x2   = np.arange(len(agent_labels))
    bw2  = 0.35
    agent_colors = {a["label"]: a["color"] for a in AGENTS}

    for j, (judge_name, per_agent, jcolor, jhatch) in enumerate([
        ("Claude",  claude_per_agent,  "#3498db", ""),
        ("ChatGPT", chatgpt_per_agent, "#e67e22", "//"),
    ]):
        vals = [per_agent.get(name, 0) for name in agent_labels]
        offset = (j - 1) * bw2 + bw2/2
        bars = ax2.bar(x2 + offset, vals, bw2,
                       label=f"{judge_name} judge",
                       color=jcolor, hatch=jhatch,
                       alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            if v > 0:
                ax2.text(bar.get_x() + bar.get_width()/2,
                         bar.get_height() + 0.05,
                         f"{v:.2f}", ha="center", va="bottom", fontsize=8)

    ax2.set_xticks(x2)
    ax2.set_xticklabels(agent_labels, fontsize=9)
    ax2.set_ylim(0, 5.5)
    ax2.set_ylabel("Avg Realism Score (1–5)", fontsize=11)
    ax2.set_title("(b) Per-Judge Overall Avg — Claude vs ChatGPT\n(shows judge agreement per agent)", fontsize=10)
    ax2.axhline(y=3.0, color="gray", linestyle="--", linewidth=1, alpha=0.5)
    ax2.legend(fontsize=9)
    ax2.grid(True, axis="y", alpha=0.3)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_realism_comparison.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"[✓] Saved → eval_realism_comparison.png")
    plt.close()

# ─── Main ─────────────────────────────────────────────────────────────────────

def run():
    print("\n" + "═"*60)
    print("  COMBINED COMPARISON EVALUATION")
    print("═"*60 + "\n")

    results, realism = load_all()

    if not results:
        print("[!] No results loaded. Check file paths.")
        return

    print(f"\n[INFO] Agents loaded: {list(results.keys())}")
    print(f"[INFO] Realism data: {list(realism.keys())}\n")

    # Figure 1 — latency + fidelity (section 4.1.1.3)
    plot_main_comparison(results, realism)

    # Figure 2 — on-device compute (GFLOPs, VRAM, latency dist)
    plot_compute_comparison(results)

    # Figure 3 — model improvement delta old → new
    plot_model_delta(results)

    # Figure 4 — realism standalone (section 4.1.1.4), both judges averaged
    plot_realism_comparison(results, realism)

    print("\n" + "═"*60)
    print("  DONE — 4 figures saved to experiment_results/")
    print("═"*60)

if __name__ == "__main__":
    run()