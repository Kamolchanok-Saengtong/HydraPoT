"""
evaluation/eval_compare.py
─────────────────────────────────────────────────────────────────
Evaluates and visualizes both On-Device LLM and Cowrie results.

Switch between ondevice/cowrie using `chosen` variable in run().

On-Device  → eval_ondevice_metrics.png
  - GFLOPs vs Latency
  - VRAM over session
  - Fidelity by FI group
  - Latency by FI group
  - Multi-metric by FI group (cosine/sequence/bleu/bert)

Cowrie     → eval_cowrie_metrics.png
  - Fidelity by FI group
  - Latency by FI group
  - Multi-metric by FI group

Run:
  cd evaluation
  python eval_compare.py
─────────────────────────────────────────────────────────────────
"""
"""
evaluation/eval_compare.py
"""
"""
evaluation/eval_compare.py
"""

import json
import os
import sys
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fidelity import score_all
from fi_manager import FIScorer, FI_LABELS

# ─── Config ───────────────────────────────────────────────────────────────────

ONDEVICE_FILE     = "eval_ondevice_results.json"
COWRIE_FILE       = "eval_cowrie_results.json"
NEW_MODEL_FILE    = "eval_ondevice_results_new_model.json"

scorer        = FIScorer()
FI_COLORS     = ["#2ecc71", "#3498db", "#f39c12", "#e67e22", "#e74c3c"]
OUTPUT_DIR    = "/mnt/data-partition/honeypot/evaluation/experiment_results"
MAX_ENTRIES   = 481
START_INDEX   = 0
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Load ─────────────────────────────────────────────────────────────────────

def load_results(path: str) -> list:
    if not os.path.exists(path):
        print(f"[!] {path} not found")
        return []
    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Failed to parse {path}")
            return []
    if MAX_ENTRIES is not None:
        data = data[START_INDEX:START_INDEX + MAX_ENTRIES]
    else:
        data = data[START_INDEX:]
    print(f"[INFO] Loaded {len(data)} entries from {path}")
    return data

def merge_new_model_with_old(old_results: list, new_model_results: list) -> list:
    """
    New model file has latency/gflops but may have different order.
    Match by 'cmd' to bring latency/gflops into the scored old results.
    """
    new_lookup = {r["cmd"]: r for r in new_model_results}
    merged = []
    for r in old_results:
        cmd = r["cmd"]
        new = new_lookup.get(cmd, {})
        merged.append({
            **r,
            "latency_ms":    new.get("latency_ms",   None),
            "gflops":        new.get("gflops",        None),
            "in_tokens":     new.get("in_tokens",     None),
            "out_tokens":    new.get("out_tokens",    None),
            "vram_after_mb": new.get("vram_after_mb", None),
            "ram_delta_mb":  new.get("ram_delta_mb",  None),
            "ondevice_output": r.get("ondevice_output", new.get("ondevice_output", "")),
        })
    return merged

# ─── Group by FI ──────────────────────────────────────────────────────────────

def group_by_fi(results: list) -> dict:
    groups = defaultdict(list)
    for r in results:
        fi, _ = scorer.score(r["cmd"])
        r["fi"] = fi
        groups[fi].append(r)
    return groups

# ─── Summaries ────────────────────────────────────────────────────────────────

def print_ondevice_summary(results: list, label="ON-DEVICE"):
    valid = [r for r in results if not r.get("skipped")]
    total = len(valid)
    if not total:
        return

    def avg(key): 
        vals = [r[key] for r in valid if r.get(key) is not None]
        return sum(vals) / len(vals) if vals else 0

    exact_matches = sum(1 for r in valid if r.get("exact_match") == 1)

    print(f"\n{'═'*50}\n  {label} METRICS SUMMARY\n{'═'*50}")
    print(f"  Total commands   : {total}")
    print(f"  Avg latency      : {avg('latency_ms'):.1f} ms")
    print(f"  Avg GFLOPs       : {avg('gflops'):.4f}")
    print(f"  Avg input tokens : {avg('in_tokens'):.1f}")
    print(f"  Avg output tokens: {avg('out_tokens'):.1f}")
    print(f"  Avg VRAM         : {avg('vram_after_mb'):.2f} MB")
    print("─" * 50)
    print(f"  Avg cosine sim   : {avg('cosine_score'):.4f}")
    print(f"  Avg sequence sim : {avg('sequence_score'):.4f}")
    print(f"  Avg BLEU         : {avg('bleu_score'):.4f}")
    print(f"  Avg BERTScore F1 : {avg('bert_f1'):.4f}")
    print(f"  Exact matches    : {exact_matches} / {total}  ({exact_matches/total*100:.1f}%)")
    print("═" * 50 + "\n")

def print_cowrie_summary(results: list):
    valid = [r for r in results if not r.get("skipped")]
    total = len(valid)
    if not total:
        return

    def avg(key):
        vals = [r[key] for r in valid if r.get(key) is not None]
        return sum(vals) / len(vals) if vals else 0

    exact_matches = sum(1 for r in valid if r.get("exact_match") == 1)

    print(f"\n{'═'*50}\n  COWRIE METRICS SUMMARY\n{'═'*50}")
    print(f"  Total commands   : {total}")
    print(f"  Avg latency      : {avg('latency_ms'):.1f} ms")
    print("─" * 50)
    print(f"  Avg cosine sim   : {avg('cosine_score'):.4f}")
    print(f"  Avg sequence sim : {avg('sequence_score'):.4f}")
    print(f"  Avg BLEU         : {avg('bleu_score'):.4f}")
    print(f"  Avg BERTScore F1 : {avg('bert_f1'):.4f}")
    print(f"  Exact matches    : {exact_matches} / {total}  ({exact_matches/total*100:.1f}%)")
    print("═" * 50 + "\n")

def print_fi_summary(groups: dict, label: str = ""):
    print(f"\n{'═'*70}\n  FIDELITY BY FI GROUP — {label}\n{'═'*70}")
    print(f"  {'FI':<5} {'LABEL':<30} {'CMDS':>5}  {'COSINE':>8}  {'SEQUENCE':>8}  {'BLEU':>8}  {'BERT':>8}")
    print("─" * 70)
    for fi in range(5):
        group = groups.get(fi, [])
        if not group:
            print(f"  {fi:<5} {FI_LABELS[fi]:<30} {'0':>5}  {'N/A':>8}")
            continue
        def avg(k): return sum(r.get(k, 0) for r in group) / len(group)
        print(f"  {fi:<5} {FI_LABELS[fi]:<30} {len(group):>5} {avg('cosine_score'):>8.4f}  {avg('sequence_score'):>8.4f}  {avg('bleu_score'):>8.4f}  {avg('bert_f1'):>8.4f}")
    print("═" * 70 + "\n")

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fi_labels_short():
    return [f"FI {fi}\n{FI_LABELS[fi][:10]}.." for fi in range(5)]

# ─── Shared Plot Functions ────────────────────────────────────────────────────

def plot_gflops_vs_latency(results: list, ax, title="GFLOPs vs Latency"):
    data = [(r["gflops"], r["latency_ms"], r.get("out_tokens", 0))
            for r in results if r.get("gflops") and r.get("latency_ms")]
    if not data:
        ax.text(0.5, 0.5, "No GFLOPs data", ha="center", va="center",
                transform=ax.transAxes, fontsize=12)
        ax.set_title(title)
        return
    gflops, latency, out_tokens = zip(*data)
    sc = ax.scatter(gflops, latency, c=out_tokens, cmap="Blues", alpha=0.7, s=40)
    plt.colorbar(sc, ax=ax).set_label("Output Tokens")
    ax.axvline(x=sum(gflops)/len(gflops),  color="red",    linestyle="--", linewidth=1, label="Avg GFLOPs")
    ax.axhline(y=sum(latency)/len(latency), color="orange", linestyle="--", linewidth=1, label="Avg Latency")
    ax.set_xlabel("GFLOPs")
    ax.set_ylabel("Latency (ms)")
    ax.set_title(f"{title}\n(color = output tokens)")
    ax.legend(loc="upper left")
    ax.grid(True, alpha=0.3)

def plot_vram_over_session(results: list, ax, title="VRAM Usage Over Session"):
    vram_data = [(i+1, r["vram_after_mb"]) for i, r in enumerate(results) if r.get("vram_after_mb") is not None]
    if not vram_data:
        ax.text(0.5, 0.5, "No VRAM data", ha="center", va="center",
                transform=ax.transAxes, fontsize=12)
        ax.set_title(title)
        return
    indices, vrams = zip(*vram_data)
    ax.plot(indices, vrams, color="purple", linewidth=2)
    ax.set_xlabel("Command Index")
    ax.set_ylabel("VRAM (MB)")
    ax.set_title(title)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{int(x)} MB"))
    ax.grid(True, alpha=0.3)

def plot_latency_by_fi(groups: dict, ax, title="Latency by FI Group"):
    latencies, counts = [], []
    for fi in range(5):
        group = groups.get(fi, [])
        counts.append(len(group))
        valid = [r["latency_ms"] for r in group if r.get("latency_ms")]
        latencies.append(sum(valid) / len(valid) if valid else 0)
    bars = ax.bar(_fi_labels_short(), latencies, color=FI_COLORS, alpha=0.8)
    for bar, count, lat in zip(bars, counts, latencies):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f"{lat:.0f}ms\n(n={count})", ha="center", va="bottom", fontsize=8)
    ax.set_ylabel("Avg Latency (ms)")
    ax.set_title(title)
    ax.grid(True, alpha=0.3, axis="y")

def plot_multi_metric_by_fi(groups: dict, ax, title="Metrics by FI Group"):
    metrics       = {"Cosine": "cosine_score", "Sequence": "sequence_score",
                     "BLEU": "bleu_score", "BERT F1": "bert_f1"}
    metric_colors = ["#3498db", "#2ecc71", "#e67e22", "#9b59b6"]
    x         = np.arange(5)
    bar_width = 0.18
    for i, (label, key) in enumerate(metrics.items()):
        values = [sum(r.get(key, 0) for r in groups.get(fi, [])) / len(groups.get(fi, [1]))
                  if groups.get(fi) else 0 for fi in range(5)]
        offset = (i - len(metrics)/2 + 0.5) * bar_width
        ax.bar(x + offset, values, bar_width, label=label,
               color=metric_colors[i], alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(_fi_labels_short())
    ax.set_ylabel("Score (0-1)")
    ax.set_title(f"{title}\n(cosine / sequence / BLEU / BERT per FI group)")
    ax.set_ylim(0, 1.0)
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(True, alpha=0.3, axis="y")

# ─── LLM-as-a-Judge ──────────────────────────────────────────────────────────

LLM_JUDGE_PATH = "LLM_as_a_Judge"

def load_realism_results():
    paths = {
        "chatgpt_cowrie":       f"{LLM_JUDGE_PATH}/chatGPT/cowrie.json",
        "chatgpt_ondevice":     f"{LLM_JUDGE_PATH}/chatGPT/ondevice.json",
        "claude_cowrie":        f"{LLM_JUDGE_PATH}/claudeAI/cowrie.json",
        "claude_ondevice":      f"{LLM_JUDGE_PATH}/claudeAI/ondevice.json",
        "chatgpt_new_cowrie":   f"{LLM_JUDGE_PATH}/chatGPT/cowrie/cowrie.json",
        "chatgpt_new_ondevice": f"{LLM_JUDGE_PATH}/chatGPT/new_model_ondevice/ondevice.json",
        "claude_new_cowrie":    f"{LLM_JUDGE_PATH}/claudeAI/cowrie/cowrie.json",
        "claude_new_ondevice":  f"{LLM_JUDGE_PATH}/claudeAI/new_model_ondevice/ondevice.json",
    }
    all_data = {}
    for name, path in paths.items():
        if not os.path.exists(path):
            print(f"[!] Missing: {path}")
            continue
        with open(path) as f:
            try:
                data = json.load(f)
                if MAX_ENTRIES is not None:
                    data = data[START_INDEX:START_INDEX + MAX_ENTRIES]
                all_data[name] = data
                print(f"[✓] Loaded {len(data):>4} entries ← {path}")
            except Exception as e:
                print(f"[!] Failed {path}: {e}")
    return all_data

def compute_realism_avg(data):
    scores = [d["realism_score"] for d in data if "realism_score" in d]
    return sum(scores) / len(scores) if scores else 0

def group_realism_by_fi(data):
    groups = defaultdict(list)
    for d in data:
        score = d.get("realism_score")
        if score is None:
            continue
        fi, _ = scorer.score(d.get("command", ""))
        groups[fi].append(score)
    return groups

def plot_realism_side_by_side(realism_data):
    LABEL_MAP = {
        "chatgpt_cowrie":       "ChatGPT Cowrie",
        "claude_cowrie":        "Claude Cowrie",
        "chatgpt_ondevice":     "ChatGPT On-Device",
        "claude_ondevice":      "Claude On-Device",
        "chatgpt_new_cowrie":   "ChatGPT Cowrie (New)",
        "claude_new_cowrie":    "Claude Cowrie (New)",
        "chatgpt_new_ondevice": "ChatGPT On-Device (New)",
        "claude_new_ondevice":  "Claude On-Device (New)",
    }
    for group in [
        {"filename": "eval_realism_original.png", "title_suffix": "(Original Model)", "filter": lambda k: "new" not in k},
        {"filename": "eval_realism_new.png",      "title_suffix": "(New Model)",      "filter": lambda k: "new" in k},
    ]:
        keys = [k for k in realism_data if group["filter"](k)]
        if not keys: continue
        cowrie_keys   = [k for k in keys if "cowrie"   in k]
        ondevice_keys = [k for k in keys if "ondevice" in k]
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        fig.suptitle(f"Realism Scores {group['title_suffix']}", fontsize=16)
        def build_subplot(ax, subplot_keys, title):
            if not subplot_keys:
                ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
                return
            x     = np.arange(5)
            width = 0.8 / len(subplot_keys)
            for i, key in enumerate(subplot_keys):
                fi_groups = group_realism_by_fi(realism_data[key])
                values = [sum(fi_groups.get(fi, [])) / len(fi_groups.get(fi, [1]))
                          if fi_groups.get(fi) else 0 for fi in range(5)]
                offset = (i - len(subplot_keys)/2 + 0.5) * width
                bars = ax.bar(x + offset, values, width, label=LABEL_MAP.get(key, key), alpha=0.85)
                for bar, val in zip(bars, values):
                    if val > 0:
                        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                                f"{val:.2f}", ha="center", va="bottom", fontsize=8)
            ax.set_xticks(x)
            ax.set_xticklabels(_fi_labels_short())
            ax.set_ylim(0, 5.5)
            ax.set_ylabel("Realism Score (1–5)")
            ax.set_title(title)
            ax.legend(fontsize=8)
            ax.grid(True, axis="y", alpha=0.3)
        build_subplot(axes[0], cowrie_keys,   "Cowrie Comparison")
        build_subplot(axes[1], ondevice_keys, "On-Device Comparison")
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        out_path = os.path.join(OUTPUT_DIR, group["filename"])
        plt.savefig(out_path, dpi=150)
        print(f"[✓] Saved → {out_path}")
        plt.close()

# ─── Main ─────────────────────────────────────────────────────────────────────

def run():

    # ─── 1. ORIGINAL ON-DEVICE ───────────────────────────────────────────
    ondevice_results = load_results(ONDEVICE_FILE)
    if ondevice_results:
        ondevice_results = score_all(ondevice_results, method="all", output_key="ondevice_output")
        ondevice_groups  = group_by_fi(ondevice_results)
        print_ondevice_summary(ondevice_results, label="ON-DEVICE (Original)")
        print_fi_summary(ondevice_groups, label="ON-DEVICE LLM (Original)")

        fig, axes = plt.subplots(2, 2, figsize=(12, 8))
        fig.suptitle("On-Device LLM (Original) — Full Evaluation", fontsize=14)
        plot_gflops_vs_latency(ondevice_results, axes[0][0], title="GFLOPs vs Latency")
        plot_vram_over_session(ondevice_results, axes[0][1])
        plot_latency_by_fi(ondevice_groups,      axes[1][0], title="Latency by FI Group")
        plot_multi_metric_by_fi(ondevice_groups, axes[1][1], title="On-Device Metrics by FI")
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "eval_ondevice_metrics.png"), dpi=150)
        print("[✓] Saved → eval_ondevice_metrics.png")
        plt.close()

    # ─── 2. NEW MODEL ────────────────────────────────────────────────────
    new_model_raw     = load_results(NEW_MODEL_FILE)
    if new_model_raw and ondevice_results:
        # score fidelity using ondevice_output field (already has ground_truth from original file)
        # match by cmd to get ground_truth from original results
        gt_lookup = {r["cmd"]: r.get("ground_truth", "") for r in ondevice_results}
        for r in new_model_raw:
            r["ground_truth"] = gt_lookup.get(r["cmd"], "")

        new_model_scored  = score_all(new_model_raw, method="all", output_key="ondevice_output")
        new_model_groups  = group_by_fi(new_model_scored)
        print_ondevice_summary(new_model_scored, label="ON-DEVICE (New Model)")
        print_fi_summary(new_model_groups, label="ON-DEVICE LLM (New Model)")

        fig, axes = plt.subplots(2, 2, figsize=(12, 8))
        fig.suptitle("On-Device LLM (New Model) — Full Evaluation", fontsize=14)
        plot_gflops_vs_latency(new_model_scored, axes[0][0], title="GFLOPs vs Latency (New Model)")
        plot_vram_over_session(new_model_scored, axes[0][1], title="VRAM Usage (New Model)")
        plot_latency_by_fi(new_model_groups,     axes[1][0], title="Latency by FI (New Model)")
        plot_multi_metric_by_fi(new_model_groups,axes[1][1], title="New Model Metrics by FI")
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "eval_ondevice_metrics_new_model.png"), dpi=150)
        print("[✓] Saved → eval_ondevice_metrics_new_model.png")
        plt.close()

    # ─── 3. COWRIE ───────────────────────────────────────────────────────
    cowrie_results = load_results(COWRIE_FILE)
    if cowrie_results:
        cowrie_results = score_all(cowrie_results, method="all", output_key="cowrie_output")
        cowrie_groups  = group_by_fi(cowrie_results)
        print_cowrie_summary(cowrie_results)
        print_fi_summary(cowrie_groups, label="COWRIE")

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle("Cowrie — Full Evaluation", fontsize=14)
        plot_latency_by_fi(cowrie_groups,     axes[0], title="Cowrie Latency by FI")
        plot_multi_metric_by_fi(cowrie_groups,axes[1], title="Cowrie Metrics by FI")
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "eval_cowrie_metrics.png"), dpi=150)
        print("[✓] Saved → eval_cowrie_metrics.png")
        plt.close()

    # ─── 4. REALISM (LLM-as-a-Judge) ────────────────────────────────────
    realism_data = load_realism_results()
    print(f"\n{'═'*50}\n  LLM-as-a-Judge REALISM SUMMARY\n{'═'*50}")
    for name, data in realism_data.items():
        print(f"{name:<25} → Avg Realism: {compute_realism_avg(data):.3f}")

    print(f"\n{'═'*70}\n  REALISM BY FI GROUP\n{'═'*70}")
    print(f"{'MODEL':<25} {'FI':<5} {'CMDS':>5} {'AVG':>8}")
    print("─" * 70)
    for name, data in realism_data.items():
        groups = group_realism_by_fi(data)
        for fi in range(5):
            scores = groups.get(fi, [])
            avg    = sum(scores) / len(scores) if scores else 0
            print(f"{name:<25} {fi:<5} {len(scores):>5} {avg:>8.3f}")
        print("─" * 70)

    plot_realism_side_by_side(realism_data)

    # ─── 5. ALL MODELS REALISM IN ONE GRAPH ──────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    models  = list(realism_data.keys())
    x       = np.arange(5)
    width   = 0.2
    for i, model in enumerate(models):
        groups = group_realism_by_fi(realism_data[model])
        values = [sum(groups.get(fi, [])) / len(groups.get(fi, [1]))
                  if groups.get(fi) else 0 for fi in range(5)]
        counts = [len(groups.get(fi, [])) for fi in range(5)]
        offset = (i - len(models)/2) * width + width/2
        bars = ax.bar(x + offset, values, width, label=model)
        for bar, val, cnt in zip(bars, values, counts):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                        f"{val:.2f}\n(n={cnt})", ha='center', va='bottom', fontsize=6)
    ax.set_xticks(x)
    ax.set_xticklabels(_fi_labels_short())
    ax.set_ylabel("Realism Score (1–5)")
    ax.set_title("Realism Comparison Across Models (by FI)")
    ax.set_ylim(0, 5)
    ax.legend(fontsize=8)
    ax.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "eval_realism_all_models.png"), dpi=150)
    print("[✓] Saved → eval_realism_all_models.png")
    plt.show()

if __name__ == "__main__":
    run()