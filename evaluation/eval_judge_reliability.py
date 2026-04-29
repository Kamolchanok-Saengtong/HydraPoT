"""
evaluation/eval_judge_reliability.py
─────────────────────────────────────────────────────────────────
Judge Reliability Validation

PURPOSE:
  Validates that Claude and ChatGPT are reliable judges by scoring
  commands from the CyberLab dataset — a trusted real-world attack
  source. Since these are REAL attacker commands on a REAL Linux
  system, responses should be genuinely realistic → judges should
  score them 4–5. If they do, the judge methodology is trustworthy.

Loads:
  LLM_as_a_Judge/AI/chatGPT.json   ← ChatGPT judge scores on CyberLab
  LLM_as_a_Judge/AI/claude.json    ← Claude judge scores on CyberLab

Produces:
  eval_judge_reliability.png
    Left : Score distribution histogram — both judges side by side
           Shows whether scores cluster at 4-5 (reliable) or spread low
    Middle: Avg score by FI group — grouped bar (Claude vs ChatGPT)
           Shows whether reliability holds across different command types
    Right : Agreement scatter — Claude score vs ChatGPT score per command
           Points near the diagonal = judges agree → consistent

Run:
  cd evaluation
  python eval_judge_reliability.py
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

CHATGPT_FILE = "LLM_as_a_Judge/AI/chatGPT.json"
CLAUDE_FILE  = "LLM_as_a_Judge/AI/claude.json"
OUTPUT_DIR   = "/mnt/data-partition/honeypot/evaluation/experiment_results"

os.makedirs(OUTPUT_DIR, exist_ok=True)
scorer = FIScorer()

FI_XLABELS = [f"FI{fi}\n{FI_LABELS[fi][:8]}.." for fi in range(5)]

# ─── Load ─────────────────────────────────────────────────────────────────────

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
    print(f"[✓] Loaded {len(data):>4} entries ← {os.path.basename(path)}")
    return data

def get_fi(cmd: str) -> int:
    fi, _ = scorer.score(cmd)
    return fi

# ─── Process entries ──────────────────────────────────────────────────────────

def extract_scores(data: list) -> list:
    """
    Returns list of dicts: {cmd, fi, score}
    Handles both possible key names: 'realism_score' or 'score'
    and both 'command' or 'cmd' for the command field.
    """
    out = []
    for d in data:
        score = d.get("realism_score") or d.get("score")
        cmd   = d.get("command") or d.get("cmd", "")
        if score is None:
            continue
        out.append({
            "cmd":   cmd,
            "fi":    get_fi(cmd),
            "score": float(score),
        })
    return out

def group_by_fi(entries: list) -> dict:
    groups = defaultdict(list)
    for e in entries:
        groups[e["fi"]].append(e["score"])
    return groups

# ─── Print summary ────────────────────────────────────────────────────────────

def print_summary(entries: list, label: str):
    scores = [e["score"] for e in entries]
    if not scores:
        print(f"[!] No scores for {label}")
        return
    avg  = sum(scores) / len(scores)
    high = sum(1 for s in scores if s >= 4.0)
    pct  = high / len(scores) * 100

    print(f"\n{'═'*55}")
    print(f"  {label} — RELIABILITY SUMMARY")
    print(f"{'═'*55}")
    print(f"  Total judged     : {len(scores)}")
    print(f"  Avg score        : {avg:.3f} / 5.0")
    print(f"  Min / Max        : {min(scores):.1f} / {max(scores):.1f}")
    print(f"  Scores >= 4.0    : {high} / {len(scores)}  ({pct:.1f}%)")
    print(f"  Verdict          : {'RELIABLE (judge scores real cmds highly)' if avg >= 3.5 else 'QUESTIONABLE (judge too harsh on real data)'}")
    print("═" * 55)

    print(f"\n  Score breakdown by FI:")
    groups = group_by_fi(entries)
    for fi in range(5):
        s = groups.get(fi, [])
        if s:
            print(f"    FI{fi} {FI_LABELS[fi]:<25} n={len(s):>4}  avg={sum(s)/len(s):.3f}")

# ─── Plot ─────────────────────────────────────────────────────────────────────

def plot_reliability(chatgpt_entries: list, claude_entries: list):
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle(
        "LLM-as-a-Judge Reliability Validation\n"
        "Huggingface/Mrheinen/linux-commands Dataset[13]",
        fontsize=13, fontweight="bold"
    )

    chatgpt_scores = [e["score"] for e in chatgpt_entries]
    claude_scores  = [e["score"] for e in claude_entries]

    # ── Left: score distribution histogram ────────────────────────────────────
    ax = axes[0]
    bins = [0.5, 1.5, 2.5, 3.5, 4.5, 5.5]
    ax.hist(chatgpt_scores, bins=bins, alpha=0.7, color="#e67e22",
            label=f"ChatGPT (avg={sum(chatgpt_scores)/len(chatgpt_scores):.2f})",
            edgecolor="white", width=0.38, align="mid",
            weights=[1/len(chatgpt_scores)]*len(chatgpt_scores))
    ax.hist(claude_scores,  bins=bins, alpha=0.7, color="#3498db",
            label=f"Claude  (avg={sum(claude_scores)/len(claude_scores):.2f})",
            edgecolor="white", width=0.38, align="right",
            weights=[1/len(claude_scores)]*len(claude_scores))

    # Shade the "good" zone (4-5)
    ax.axvspan(3.5, 5.5, alpha=0.08, color="green", label="Expected zone (4–5)")
    ax.axvline(4.0, color="green", linewidth=1, linestyle="--", alpha=0.6)

    ax.set_xlabel("Realism Score (1–5)", fontsize=11)
    ax.set_ylabel("Proportion of Commands", fontsize=11)
    ax.set_title("(a) Score Distribution\n(should cluster at 4–5)", fontsize=10)
    ax.set_xlim(0.5, 5.5)
    ax.set_ylim(0, 1.0)
    ax.set_xticks([1, 2, 3, 4, 5])
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
    ax.legend(fontsize=9)
    ax.grid(True, axis="y", alpha=0.3)

    # Annotate avg lines
    for scores, color, label in [
        (chatgpt_scores, "#e67e22", "ChatGPT"),
        (claude_scores,  "#3498db", "Claude"),
    ]:
        avg = sum(scores) / len(scores)
        ax.axvline(avg, color=color, linewidth=2, linestyle="-", alpha=0.8)
        ax.text(avg + 0.05, 0.92, f"{label}\navg={avg:.2f}",
                color=color, fontsize=8, va="top")

    # ── Middle: avg score by FI group ─────────────────────────────────────────
    ax2 = axes[1]
    chatgpt_fi = group_by_fi(chatgpt_entries)
    claude_fi  = group_by_fi(claude_entries)

    x  = np.arange(5)
    bw = 0.35

    chatgpt_avgs = [sum(chatgpt_fi[fi])/len(chatgpt_fi[fi]) if chatgpt_fi.get(fi) else 0
                    for fi in range(5)]
    claude_avgs  = [sum(claude_fi[fi])/len(claude_fi[fi])   if claude_fi.get(fi)  else 0
                    for fi in range(5)]
    chatgpt_ns   = [len(chatgpt_fi.get(fi, [])) for fi in range(5)]
    claude_ns    = [len(claude_fi.get(fi,  [])) for fi in range(5)]

    b1 = ax2.bar(x - bw/2, chatgpt_avgs, bw, label="ChatGPT judge",
                 color="#e67e22", alpha=0.85, edgecolor="white")
    b2 = ax2.bar(x + bw/2, claude_avgs,  bw, label="Claude judge",
                 color="#3498db", alpha=0.85, edgecolor="white")

    for bar, v, n in zip(list(b1) + list(b2),
                         chatgpt_avgs + claude_avgs,
                         chatgpt_ns   + claude_ns):
        if v > 0:
            ax2.text(bar.get_x() + bar.get_width()/2,
                     bar.get_height() + 0.04,
                     f"{v:.2f}\n(n={n})", ha="center", va="bottom", fontsize=7)

    # Expected zone shading
    ax2.axhspan(4.0, 5.0, alpha=0.08, color="green")
    ax2.axhline(4.0, color="green", linewidth=1, linestyle="--",
                alpha=0.6, label="Expected min (4.0)")

    ax2.set_xticks(x)
    ax2.set_xticklabels(FI_XLABELS, fontsize=9)
    ax2.set_ylim(0, 5.5)
    ax2.set_ylabel("Avg Realism Score (1–5)", fontsize=11)
    ax2.set_title("(b) Avg Score by FI Group\n(both judges should stay above 4.0)", fontsize=10)
    ax2.legend(fontsize=9)
    ax2.grid(True, axis="y", alpha=0.3)

    # ── Right: agreement scatter (Claude vs ChatGPT per command) ──────────────
    ax3 = axes[2]

    # Match by command text
    chatgpt_lookup = {e["cmd"]: e["score"] for e in chatgpt_entries}
    paired = [(chatgpt_lookup[e["cmd"]], e["score"])
              for e in claude_entries if e["cmd"] in chatgpt_lookup]

    if paired:
        gpt_s, cld_s = zip(*paired)
        gpt_s = list(gpt_s)
        cld_s = list(cld_s)

        # Color points by agreement gap
        gaps   = [abs(g - c) for g, c in zip(gpt_s, cld_s)]
        sc = ax3.scatter(gpt_s, cld_s, c=gaps, cmap="RdYlGn_r",
                         alpha=0.6, s=30, vmin=0, vmax=2)
        plt.colorbar(sc, ax=ax3).set_label("Score gap (0=agree)", fontsize=8)

        # Perfect agreement diagonal
        ax3.plot([1, 5], [1, 5], color="gray", linewidth=1.5,
                 linestyle="--", alpha=0.7, label="Perfect agreement")

        # Correlation
        corr = np.corrcoef(gpt_s, cld_s)[0, 1]
        ax3.text(0.05, 0.95, f"Correlation: r={corr:.3f}",
                 transform=ax3.transAxes, fontsize=10, va="top",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                           edgecolor="gray", alpha=0.8))

        agree_pct = sum(1 for g in gaps if g <= 1.0) / len(gaps) * 100
        ax3.text(0.05, 0.85, f"Within ±1: {agree_pct:.1f}%",
                 transform=ax3.transAxes, fontsize=10, va="top",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                           edgecolor="gray", alpha=0.8))

        ax3.set_xlabel("ChatGPT Score", fontsize=11)
        ax3.set_ylabel("Claude Score", fontsize=11)
        ax3.set_xlim(0.5, 5.5)
        ax3.set_ylim(0.5, 5.5)
        ax3.set_xticks([1, 2, 3, 4, 5])
        ax3.set_yticks([1, 2, 3, 4, 5])
        ax3.legend(fontsize=9)
    else:
        ax3.text(0.5, 0.5, "No matched commands\nbetween judges",
                 ha="center", va="center", transform=ax3.transAxes, fontsize=12)

    ax3.set_title("(c) Judge Agreement\n(points near diagonal = judges agree)", fontsize=10)
    ax3.grid(True, alpha=0.3)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_judge_reliability.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"\n[✓] Saved → eval_judge_reliability.png")
    plt.close()

# ─── Main ─────────────────────────────────────────────────────────────────────

def run():
    print("\n" + "═"*60)
    print("  JUDGE RELIABILITY VALIDATION")
    print("  (CyberLab real attack commands — expected score: 4–5)")
    print("═"*60)

    chatgpt_raw = load_json(CHATGPT_FILE)
    claude_raw  = load_json(CLAUDE_FILE)

    if not chatgpt_raw and not claude_raw:
        print("[!] No data found — check file paths")
        return

    chatgpt_entries = extract_scores(chatgpt_raw) if chatgpt_raw else []
    claude_entries  = extract_scores(claude_raw)  if claude_raw  else []

    if chatgpt_entries:
        print_summary(chatgpt_entries, "ChatGPT Judge")
    if claude_entries:
        print_summary(claude_entries,  "Claude Judge")

    # Inter-judge agreement summary
    if chatgpt_entries and claude_entries:
        gpt_avg = sum(e["score"] for e in chatgpt_entries) / len(chatgpt_entries)
        cld_avg = sum(e["score"] for e in claude_entries)  / len(claude_entries)
        print(f"\n{'═'*55}")
        print(f"  INTER-JUDGE COMPARISON")
        print(f"{'═'*55}")
        print(f"  ChatGPT avg score : {gpt_avg:.3f}")
        print(f"  Claude avg score  : {cld_avg:.3f}")
        print(f"  Difference        : {abs(gpt_avg - cld_avg):.3f}")
        print(f"  Verdict           : {'CONSISTENT (both judges agree)' if abs(gpt_avg - cld_avg) < 0.5 else 'DIVERGENT (judges disagree — investigate)'}")
        print("═" * 55)

    plot_reliability(chatgpt_entries, claude_entries)
    print("\n[✓] Judge reliability validation complete.")

if __name__ == "__main__":
    run()