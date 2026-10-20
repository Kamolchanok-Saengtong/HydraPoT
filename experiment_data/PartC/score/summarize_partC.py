"""
experiment_data/PartC/summarize_partC.py — Part C: fidelity scoring + summary figures
─────────────────────────────────────────────────────────────────
Reads the 4 arm JSONL files written by run_partC.py, scores every
scoreable record (ground_truth is not None) using evaluation/fidelity.py
(cosine/sequence/BLEU/BERTScore-F1 + exact_match — evaluation/normalization.py's
normalize_pair is already applied inside each scorer), and produces a
terminal summary + 5 figures.

Cost is NOT re-estimated the way evaluation/cost_analysis.py does (that
script estimates tokens from character length because the old cloud
dataset never logged real usage). run_partC.py already logs real
prompt_tokens/completion_tokens/cost for the cloud arm and cpu_pct/
ram_delta_mb for every arm via usage_with_cost() — this script just
aggregates what's already there. On-device has no GFLOPs logged (unlike
the old evaluation/ pipeline), so its "cost" is reported as latency +
CPU/RAM, not a USD equivalent.

Usage:
    python experiment_data/PartC/summarize_partC.py <run_id>
"""

import os

import sys
import json
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, os.path.join(_ROOT, "evaluation"),
          os.path.join(_ROOT, "experiment_data")):
    if p not in sys.path:
        sys.path.insert(0, p)

from _common import load_jsonl

from fidelity import all_score_response

RESULTS_DIR = os.path.join(_HERE, "..", "results", "partC")
ARMS = ("cowrie", "on_device", "cloud", "honeyrouter")

COLOR = {
    "cowrie":      "#AAAAAA",
    "on_device":   "#7EB3C8",
    "cloud":       "#5B7FA6",
    "honeyrouter": "#E07B39",
}
ARM_LABEL = {
    "cowrie":      "Pure Cowrie",
    "on_device":   "Pure On-device LLM",
    "cloud":       "Pure Cloud LLM",
    "honeyrouter": "HydraPoT",
}

plt.rcParams.update({
    "font.family":       "sans-serif",
    "font.size":         11,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.grid":         True,
    "axes.grid.axis":    "y",
    "grid.color":        "#E0E0E0",
    "grid.linewidth":    0.7,
    "savefig.dpi":       300,
    "figure.dpi":        150,
})


# ─── data loading ─────────────────────────────────────────────────────────────

def load_run(run_id):
    run_dir = os.path.join(RESULTS_DIR, f"fidelity_{run_id}")
    data = {}
    for arm in ARMS:
        path = os.path.join(run_dir, f"{arm}.jsonl")
        data[arm] = load_jsonl(path) if os.path.exists(path) else []
    return run_dir, data


# ─── scoring ──────────────────────────────────────────────────────────────────

def score_records(records):
    """Attach fidelity scores in-place to every scoreable record."""
    scored = 0
    for r in records:
        if not r.get("ok") or r.get("ground_truth") is None or r.get("response") is None:
            continue
        r["_scores"] = all_score_response(r["response"], r["ground_truth"])
        scored += 1
    return scored


def write_scored_records(arm, records, run_dir):
    """
    Persist every scoreable record — identifying fields + its full _scores
    dict (bert_f1, cosine_score, sequence_score, bleu_score, exact_match,
    bert_precision, bert_recall) — to scored_<arm>.jsonl so per-command
    fidelity numbers survive after this script exits, instead of only
    living in the in-memory aggregate.
    """
    scored = [r for r in records if "_scores" in r]
    if not scored:
        return None
    path = os.path.join(run_dir, f"scored_{arm}.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for r in scored:
            rec = {
                "run_id":       r.get("run_id"),
                "trial":        r.get("trial"),
                "cmd_index":    r.get("cmd_index"),
                "cmd":          r.get("cmd"),
                "source":       r.get("source"),
                "fi_score":     r.get("fi_score"),
                "arm":          r.get("arm"),
                "routed_to":    r.get("routed_to"),
                "ground_truth": r.get("ground_truth"),
                "response":     r.get("response"),
                **r["_scores"],
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def _mean(vals):
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else None


def aggregate_fidelity(records):
    scored = [r for r in records if "_scores" in r]
    if not scored:
        return None
    return {
        "n_scored":           len(scored),
        "bert_f1":            _mean([r["_scores"]["bert_f1"]            for r in scored]),
        "cosine_score":       _mean([r["_scores"]["cosine_score"]       for r in scored]),
        "sequence_score":     _mean([r["_scores"]["sequence_score"]     for r in scored]),
        "levenshtein_score":  _mean([r["_scores"]["levenshtein_score"]  for r in scored]),
        "jaro_winkler_score": _mean([r["_scores"]["jaro_winkler_score"] for r in scored]),
        "bleu_score":         _mean([r["_scores"]["bleu_score"]         for r in scored]),
        "exact_match_pct":    _mean([r["_scores"]["exact_match"]        for r in scored]) * 100,
    }


def aggregate_by_fi(records):
    by_fi = defaultdict(list)
    for r in records:
        if "_scores" in r and r.get("fi_score") is not None:
            by_fi[r["fi_score"]].append(r["_scores"]["bert_f1"])
    return {fi: _mean(vals) for fi, vals in sorted(by_fi.items())}


def aggregate_cost(records):
    ok = [r for r in records if r.get("ok")]
    return {
        "avg_inference_ms":       _mean([r.get("inference_ms")  for r in ok]),
        "avg_cpu_pct":            _mean([r.get("cpu_pct")       for r in ok]),
        "avg_ram_delta_mb":       _mean([r.get("ram_delta_mb")  for r in ok]),
        "total_cost_usd":         sum(r.get("cost") or 0 for r in ok),
        "total_prompt_tokens":    sum(r.get("prompt_tokens") or 0 for r in ok),
        "total_completion_tokens": sum(r.get("completion_tokens") or 0 for r in ok),
        "avg_gflops":             _mean([r.get("gflops") for r in ok]),
        "total_gflops":           sum(r.get("gflops") or 0 for r in ok),
    }


def routing_distribution(honeyrouter_records):
    counts = defaultdict(int)
    total = 0
    for r in honeyrouter_records:
        if not r.get("ok"):
            continue
        dest = r.get("routed_to")
        if dest is None:
            continue
        counts[dest] += 1
        total += 1
    if total == 0:
        return None
    return {k: v / total * 100 for k, v in counts.items()}


# ─── figures — no baked-in titles (captions live in the paper) ────────────────

def _save(fig, path):
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def fig1_fidelity_by_arm(fidelity, outdir):
    arms = [a for a in ARMS if fidelity.get(a)]
    if not arms:
        print("[summarize_partC] fig1: no fidelity data, skipping")
        return None
    vals = [fidelity[a]["bert_f1"] for a in arms]
    x = np.arange(len(arms))

    fig, ax = plt.subplots(figsize=(7.5, 5.0))
    bars = ax.bar(x, vals, color=[COLOR[a] for a in arms], edgecolor="white", linewidth=0.8)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.015, f"{v:.3f}",
                 ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([ARM_LABEL[a] for a in arms], fontsize=10)
    ax.set_ylabel("BERTScore F1")
    ax.set_ylim(0, 1.05)
    fig.tight_layout()
    path = os.path.join(outdir, "fig1_fidelity_by_arm.png")
    _save(fig, path)
    return path


def fig1b_multi_metric_by_arm(fidelity, outdir):
    """
    Grouped bar: cosine / sequence / BLEU / BERTScore-F1 / exact-match-rate,
    one group per arm — the surface metrics (cosine/sequence/bleu/exact)
    alongside BERTScore so the compressed-high-range BERTScore-only view
    from fig1 doesn't stand alone.
    """
    arms = [a for a in ARMS if fidelity.get(a)]
    if not arms:
        print("[summarize_partC] fig1b: no fidelity data, skipping")
        return None

    metrics = [
        ("cosine_score",        "Cosine"),
        ("sequence_score",      "Sequence"),
        ("levenshtein_score",   "Levenshtein"),
        ("jaro_winkler_score",  "Jaro-Winkler"),
        ("bleu_score",          "BLEU"),
        ("bert_f1",             "BERTScore F1"),
        ("exact_match_pct",     "Exact match"),  # 0-100, rescaled below
    ]

    x = np.arange(len(arms))
    w = 0.8 / len(metrics)

    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    for i, (field, label) in enumerate(metrics):
        vals = []
        for a in arms:
            v = fidelity[a][field]
            vals.append(v / 100 if field == "exact_match_pct" else v)
        offset = (i - (len(metrics) - 1) / 2) * w
        ax.bar(x + offset, vals, w, label=label, edgecolor="white", linewidth=0.5)

    ax.set_xticks(x)
    ax.set_xticklabels([ARM_LABEL[a] for a in arms], fontsize=10)
    ax.set_ylabel("Score (exact-match shown as rate 0-1)")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=8.5, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.14))
    fig.tight_layout()
    path = os.path.join(outdir, "fig1b_multi_metric_by_arm.png")
    _save(fig, path)
    return path


def fig2_fidelity_by_fi(by_fi_all, outdir):
    fi_bands = sorted({fi for arm_data in by_fi_all.values() for fi in arm_data})
    arms = [a for a in ARMS if by_fi_all.get(a)]
    if not fi_bands or not arms:
        print("[summarize_partC] fig2: no per-FI data, skipping")
        return None

    x = np.arange(len(fi_bands))
    w = 0.8 / len(arms)

    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    for i, a in enumerate(arms):
        vals = [by_fi_all[a].get(fi) or 0 for fi in fi_bands]
        offset = (i - (len(arms) - 1) / 2) * w
        ax.bar(x + offset, vals, w, label=ARM_LABEL[a], color=COLOR[a],
               edgecolor="white", linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels([f"FI{fi}" for fi in fi_bands])
    ax.set_ylabel("BERTScore F1")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=8.5)
    fig.tight_layout()
    path = os.path.join(outdir, "fig2_fidelity_by_fi.png")
    _save(fig, path)
    return path


def fig3_routing_distribution(dist, outdir):
    if dist is None:
        print("[summarize_partC] fig3: no 'routed_to' data, skipping")
        return None

    backends = ["cowrie", "on_device", "cloud"]
    labels   = ["Cowrie", "On-device LLM", "Cloud LLM"]
    pcts     = [dist.get(b, 0.0) for b in backends]
    x = np.arange(len(backends))

    fig, ax = plt.subplots(figsize=(6.5, 5.0))
    bars = ax.bar(x, pcts, color=[COLOR[b] for b in backends], edgecolor="white", linewidth=0.8)
    ymax = max(pcts) if pcts else 100
    for bar, pct in zip(bars, pcts):
        ax.text(bar.get_x() + bar.get_width() / 2, pct + ymax * 0.02, f"{pct:.1f}%",
                 ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Share of routed commands (%)")
    ax.set_ylim(0, ymax * 1.22)
    fig.tight_layout()
    path = os.path.join(outdir, "fig3_routing_distribution.png")
    _save(fig, path)
    return path


def fig3b_routing_distribution_pie(dist, outdir):
    """Pie-chart view of the same routing distribution as fig3's bar chart —
    which fraction of commands HoneyRouter sent to each backend agent."""
    if dist is None:
        print("[summarize_partC] fig3b: no 'routed_to' data, skipping")
        return None

    backends = ["cowrie", "on_device", "cloud"]
    labels   = ["Cowrie", "On-device LLM", "Cloud LLM"]
    pcts     = [dist.get(b, 0.0) for b in backends]
    keep = [(l, p, COLOR[b]) for b, l, p in zip(backends, labels, pcts) if p > 0]
    if not keep:
        print("[summarize_partC] fig3b: all routing shares are zero, skipping")
        return None
    labels_kept, pcts_kept, colors_kept = zip(*keep)

    fig, ax = plt.subplots(figsize=(6.5, 6.0))
    wedges, _, autotexts = ax.pie(
        pcts_kept,
        labels=labels_kept,
        colors=colors_kept,
        autopct="%.1f%%",
        startangle=90,
        wedgeprops={"edgecolor": "white", "linewidth": 1.2},
        textprops={"fontsize": 10},
    )
    for at in autotexts:
        at.set_fontweight("bold")
        at.set_color("white")
    ax.set_aspect("equal")
    fig.tight_layout()
    path = os.path.join(outdir, "fig3b_routing_distribution_pie.png")
    _save(fig, path)
    return path


def fig4_cost_vs_fidelity(fidelity, cost, outdir):
    arms = [a for a in ARMS if fidelity.get(a) and cost.get(a)
            and cost[a]["avg_inference_ms"] is not None]
    if not arms:
        print("[summarize_partC] fig4: no cost+fidelity overlap, skipping")
        return None

    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    for a in arms:
        x = cost[a]["avg_inference_ms"]
        y = fidelity[a]["bert_f1"]
        ax.scatter(x, y, s=150, color=COLOR[a], edgecolor="white", linewidth=1.2, zorder=3)
        ax.annotate(ARM_LABEL[a], (x, y), xytext=(8, 6), textcoords="offset points", fontsize=9)
    ax.set_xlabel("Average inference latency (ms)")
    ax.set_ylabel("BERTScore F1")
    fig.tight_layout()
    path = os.path.join(outdir, "fig4_cost_vs_fidelity.png")
    _save(fig, path)
    return path


def fig5_state_size(honeyrouter_records, outdir):
    pts = [(r["cmd_index"], r["state_size"]) for r in honeyrouter_records
           if r.get("ok") and r.get("state_size") is not None]
    if not pts:
        print("[summarize_partC] fig5: no state_size data, skipping")
        return None
    pts.sort()
    xs, ys = zip(*pts)

    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    ax.plot(xs, ys, color=COLOR["honeyrouter"], linewidth=1.6)
    ax.set_xlabel("Query index")
    ax.set_ylabel("State size (tracked files + packages)")
    fig.tight_layout()
    path = os.path.join(outdir, "fig5_state_size.png")
    _save(fig, path)
    return path


# ─── terminal summary ───────────────────────────────────────────────────────

def print_summary(run_id, fidelity, cost, dist):
    W = 78
    print(f"\n{'='*W}")
    print(f"  Part C Summary — run_id: {run_id}")
    print(f"{'='*W}\n")

    print("Fidelity (BERTScore F1):")
    for a in ARMS:
        f = fidelity.get(a)
        val = f"{f['bert_f1']:.3f}" if f else "n/a"
        print(f"  {ARM_LABEL[a]:<20}: {val}")

    print("\nOther fidelity metrics per arm:")
    for a in ARMS:
        f = fidelity.get(a)
        if not f:
            continue
        print(f"  {ARM_LABEL[a]:<20} n={f['n_scored']:<5} "
              f"cosine={f['cosine_score']:.3f}  sequence={f['sequence_score']:.3f}  "
              f"levenshtein={f['levenshtein_score']:.3f}  jaro_winkler={f['jaro_winkler_score']:.3f}  "
              f"bleu={f['bleu_score']:.3f}  exact={f['exact_match_pct']:.1f}%")

    print("\nCost / overhead per arm:")
    for a in ARMS:
        c = cost.get(a)
        if not c:
            continue
        line = f"  {ARM_LABEL[a]:<20}"
        if c["avg_inference_ms"] is not None:
            line += f" avg_ms={c['avg_inference_ms']:.1f}"
        if c["avg_cpu_pct"] is not None:
            line += f"  cpu={c['avg_cpu_pct']:.1f}%"
        if c["avg_ram_delta_mb"] is not None:
            line += f"  ram_delta={c['avg_ram_delta_mb']:.1f}MB"
        if c["total_cost_usd"]:
            total_tok = c["total_prompt_tokens"] + c["total_completion_tokens"]
            line += f"  cost=${c['total_cost_usd']:.4f}  tokens={total_tok:,}"
        if c.get("avg_gflops") is not None:
            line += f"  avg_gflops={c['avg_gflops']:.2f}  total_gflops={c['total_gflops']:,.1f}"
        print(line)

    if dist:
        print("\nRouting distribution (HydraPoT):")
        print("  " + " | ".join(f"{k}: {v:.1f}%" for k, v in dist.items()))

    print(f"\n{'='*W}\n")


# ─── main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("usage: python experiment_data/PartC/summarize_partC.py <run_id>")
        sys.exit(1)
    run_id = sys.argv[1]

    run_dir, data = load_run(run_id)
    if not any(data.values()):
        print(f"[summarize_partC] no records found under {run_dir}")
        sys.exit(1)

    for arm, records in data.items():
        n = score_records(records)
        print(f"[summarize_partC] {arm}: scored {n}/{len(records)} records")
        scored_path = write_scored_records(arm, records, run_dir)
        if scored_path:
            print(f"[summarize_partC] {arm}: per-record scores -> {os.path.basename(scored_path)}")

    fidelity  = {a: aggregate_fidelity(data[a]) for a in ARMS}
    by_fi_all = {a: aggregate_by_fi(data[a])     for a in ARMS}
    cost      = {a: aggregate_cost(data[a])      for a in ARMS}
    dist      = routing_distribution(data["honeyrouter"])

    print_summary(run_id, fidelity, cost, dist)

    outdir = os.path.join(run_dir, "figures")
    os.makedirs(outdir, exist_ok=True)

    made = []
    for path in (
        fig1_fidelity_by_arm(fidelity, outdir),
        fig1b_multi_metric_by_arm(fidelity, outdir),
        fig2_fidelity_by_fi(by_fi_all, outdir),
        fig3_routing_distribution(dist, outdir),
        fig3b_routing_distribution_pie(dist, outdir),
        fig4_cost_vs_fidelity(fidelity, cost, outdir),
        fig5_state_size(data["honeyrouter"], outdir),
    ):
        if path:
            made.append(path)

    print(f"[summarize_partC] {len(made)} figures saved to: {outdir}")
    for m in made:
        print(f"  {os.path.basename(m)}")


if __name__ == "__main__":
    main()
