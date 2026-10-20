"""
experiment_data/plot_dataset_distribution.py
─────────────────────────────────────────────────────────────────
Plots FI-band distribution AND agent routing distribution for each
dataset, so you can see both impact severity and routing decisions.

Charts produced (saved to experiment_data/results/dataset_distribution/):
  1. fi_distribution_all.png       — FI bands side by side per dataset
  2. fi_distribution_each.png      — one subplot per dataset (FI)
  3. mixed_workload_preview.png    — balanced sample vs raw pool
  4. class_imbalance.png           — imbalance ratio heatmap (FI)
  5. agent_distribution_all.png    — cowrie/on_device/cloud per dataset
  6. agent_distribution_each.png   — one subplot per dataset (agent)

Run from project root:
    python experiment_data/plot_dataset_distribution.py
    python experiment_data/plot_dataset_distribution.py --per-band 10
"""

import os
import sys
import json
import argparse
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

from prompt.fi_manager import FIScorer
from workloads import (
    load_mrheinen, load_obfuscated, load_cyberlab_sessions,
    MRHEINEN_FILE, OBFUSCATED_FILE, CYBERLAB_FILE,
)

ML4NET_FILE = os.environ.get(
    "NSC_ML4NET_FILE",
    os.path.join(_ROOT, "dataset", "ml4net_full.json"),
)

OUT_DIR = os.path.join(_HERE, "results", "shared", "dataset_distribution")

# ── colors ────────────────────────────────────────────────────────────────────

FI_COLORS = {
    0: "#4C9F70",
    1: "#8DC26F",
    2: "#E1C84A",
    3: "#E8873A",
    4: "#C0504D",
}

AGENT_COLORS = {
    "cowrie":    "#4C9F70",
    "on_device": "#E1A730",
    "cloud":     "#C0504D",
}

AGENTS = ["cowrie", "on_device", "cloud"]


# ─── loaders ──────────────────────────────────────────────────────────────────

def score_commands(commands: list[str]) -> dict[int, list[str]]:
    scorer = FIScorer()
    buckets: dict[int, list[str]] = {i: [] for i in range(5)}
    for cmd in commands:
        fi, _ = scorer.score(cmd)
        buckets[fi].append(cmd)
    return buckets


def route_commands(commands: list[str]) -> dict[str, list[str]]:
    """Classify each command to cowrie / on_device / cloud using real router."""
    try:
        from core.router import classify
    except ImportError:
        print("[dist] WARNING: router.py not importable — run from project root")
        return {"cowrie": commands, "on_device": [], "cloud": []}

    buckets: dict[str, list[str]] = {a: [] for a in AGENTS}
    for cmd in commands:
        agent = classify(cmd, [])
        buckets.setdefault(agent, []).append(cmd)
    return buckets


def _load_ml4net_sample(max_sessions: int = 5000) -> list[str]:
    """Load a sample of commands from ml4net_full.json."""
    if not os.path.exists(ML4NET_FILE):
        return []
    data = json.load(open(ML4NET_FILE, encoding="utf-8"))
    cmds = []
    for entry in data[:max_sessions]:
        raw = entry.get("commands", "")
        for part in raw.split(";"):
            c = part.strip()
            if c:
                cmds.append(c)
    seen = set()
    return [c for c in cmds if not (c in seen or seen.add(c))]


def load_all_datasets() -> dict[str, list[str]]:
    """Return {label: [cmd, ...]} for every available dataset."""
    datasets: dict[str, list[str]] = {}

    if os.path.exists(MRHEINEN_FILE):
        cmds = load_mrheinen()
        datasets["mrheinen\n(linux-commands)"] = cmds
        print(f"[dist] mrheinen: {len(cmds)} commands")
    else:
        print(f"[dist] mrheinen not found, skipping")

    if os.path.exists(OBFUSCATED_FILE):
        cmds = load_obfuscated()
        datasets["obfuscated\n(benchmark)"] = cmds
        print(f"[dist] obfuscated benchmark: {len(cmds)} commands")
    else:
        print(f"[dist] obfuscated benchmark not found, skipping")

    if os.path.exists(ML4NET_FILE):
        cmds = _load_ml4net_sample(max_sessions=5000)
        datasets["ML4Net\n(real sessions)"] = cmds
        print(f"[dist] ML4Net: {len(cmds)} commands (5000 sessions sample)")
    else:
        print(f"[dist] ML4Net not found, skipping")

    if os.path.exists(CYBERLAB_FILE):
        sessions = load_cyberlab_sessions()
        cmds = [cmd for s in sessions for cmd in s["commands"]]
        datasets["cyberlab\n(2019-05-13)"] = cmds
        print(f"[dist] cyberlab: {len(cmds)} commands")
    else:
        print(f"[dist] cyberlab not found, skipping")

    if not datasets:
        print("[dist] ERROR: no datasets found.")
        sys.exit(1)

    return datasets


# ─── FI charts (unchanged logic, just uses list[str] now) ─────────────────────

def chart_fi_all(datasets: dict, outdir: str):
    ds_names = list(datasets.keys())
    n_ds = len(ds_names)
    fi_bands = list(range(5))

    fig, ax = plt.subplots(figsize=(max(8, n_ds * 3 + 2), 5))
    x = np.arange(n_ds)
    bar_w = 0.14
    offsets = np.linspace(-(len(fi_bands)-1)/2 * bar_w,
                           (len(fi_bands)-1)/2 * bar_w,
                           len(fi_bands))

    fi_buckets = {name: score_commands(cmds) for name, cmds in datasets.items()}

    for i, fi in enumerate(fi_bands):
        counts = []
        for name in ds_names:
            total = len(datasets[name])
            cnt = len(fi_buckets[name].get(fi, []))
            counts.append(cnt / total * 100 if total else 0)
        bars = ax.bar(x + offsets[i], counts, bar_w,
                      label=f"FI {fi}", color=FI_COLORS[fi],
                      edgecolor="white", linewidth=0.5)
        for bar, pct in zip(bars, counts):
            if pct >= 3:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                        f"{pct:.0f}%", ha="center", va="bottom",
                        fontsize=7, color="#444")

    ax.set_xticks(x)
    ax.set_xticklabels(ds_names, fontsize=10)
    ax.set_ylabel("% of dataset")
    ax.set_title("FI band distribution — per dataset", fontsize=13, pad=12)
    ax.set_ylim(0, 100)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(title="FI band", bbox_to_anchor=(1.01, 1), loc="upper left",
              fontsize=9, title_fontsize=9)
    fig.tight_layout()

    path = os.path.join(outdir, "fi_distribution_all.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dist] saved: {os.path.basename(path)}")
    return path


def chart_fi_each(datasets: dict, outdir: str):
    n = len(datasets)
    fig, axes = plt.subplots(1, n, figsize=(n * 4, 4), sharey=False)
    if n == 1:
        axes = [axes]

    for ax, (name, cmds) in zip(axes, datasets.items()):
        buckets = score_commands(cmds)
        total = len(cmds)
        counts = [len(buckets.get(fi, [])) for fi in range(5)]
        pcts   = [c / total * 100 if total else 0 for c in counts]

        bars = ax.bar(range(5), pcts,
                      color=[FI_COLORS[fi] for fi in range(5)],
                      edgecolor="white", linewidth=0.8, width=0.6)
        for bar, pct, cnt in zip(bars, pcts, counts):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f"{pct:.0f}%\n({cnt})", ha="center", va="bottom", fontsize=8)

        ax.set_title(name.replace("\n", " "), fontsize=10, pad=8)
        ax.set_xticks(range(5))
        ax.set_xticklabels([f"FI {i}" for i in range(5)], fontsize=8)
        ax.set_ylabel("%" if ax == axes[0] else "")
        ax.set_ylim(0, 105)
        ax.spines[["top", "right"]].set_visible(False)
        ax.text(0.98, 0.97, f"n={total}", transform=ax.transAxes,
                ha="right", va="top", fontsize=8, color="#888")

    fig.suptitle("FI distribution per dataset", fontsize=13, y=1.02)
    fig.tight_layout()

    path = os.path.join(outdir, "fi_distribution_each.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dist] saved: {os.path.basename(path)}")
    return path


def chart_mixed_preview(datasets: dict, per_band: int, outdir: str):
    all_buckets: dict[int, list[str]] = {i: [] for i in range(5)}
    for cmds in datasets.values():
        buckets = score_commands(cmds)
        for fi, fc in buckets.items():
            all_buckets[fi].extend(fc)

    total_raw = sum(len(v) for v in all_buckets.values())
    raw_pcts  = [len(all_buckets[fi]) / total_raw * 100 if total_raw else 0
                 for fi in range(5)]

    sampled_counts = [min(len(all_buckets[fi]), per_band) for fi in range(5)]
    total_sampled  = sum(sampled_counts)
    sampled_pcts   = [c / total_sampled * 100 if total_sampled else 0
                      for c in sampled_counts]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))

    bars1 = ax1.bar(range(5), raw_pcts,
                    color=[FI_COLORS[fi] for fi in range(5)],
                    edgecolor="white", linewidth=0.8, width=0.6)
    for bar, pct, cnt in zip(bars1, raw_pcts, [len(all_buckets[fi]) for fi in range(5)]):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                 f"{pct:.0f}%\n({cnt})", ha="center", va="bottom", fontsize=8)
    ax1.set_title(f"Raw merged pool (n={total_raw})", fontsize=11)
    ax1.set_xticks(range(5))
    ax1.set_xticklabels([f"FI {i}" for i in range(5)], fontsize=9)
    ax1.set_ylabel("%")
    ax1.set_ylim(0, 105)
    ax1.spines[["top", "right"]].set_visible(False)

    bars2 = ax2.bar(range(5), sampled_pcts,
                    color=[FI_COLORS[fi] for fi in range(5)],
                    edgecolor="white", linewidth=0.8, width=0.6)
    for bar, pct, cnt in zip(bars2, sampled_pcts, sampled_counts):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                 f"{pct:.0f}%\n({cnt})", ha="center", va="bottom", fontsize=8)
    ax2.set_title(f"Balanced sample (≤{per_band}/band, n={total_sampled})", fontsize=11)
    ax2.set_xticks(range(5))
    ax2.set_xticklabels([f"FI {i}" for i in range(5)], fontsize=9)
    ax2.set_ylim(0, 105)
    ax2.spines[["top", "right"]].set_visible(False)

    fig.suptitle("Raw pool vs. balanced sample for Part A workload",
                 fontsize=13, y=1.02)
    fig.tight_layout()

    path = os.path.join(outdir, "mixed_workload_preview.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dist] saved: {os.path.basename(path)}")
    return path


def chart_imbalance_heatmap(datasets: dict, outdir: str):
    ds_names = [n.replace("\n", " ") for n in datasets.keys()]
    matrix   = []

    for name, cmds in datasets.items():
        buckets = score_commands(cmds)
        counts  = [len(buckets.get(fi, [])) for fi in range(5)]
        max_cnt = max(counts) if max(counts) > 0 else 1
        ratios  = [min(max_cnt / c if c > 0 else 99.0, 99.0) for c in counts]
        matrix.append(ratios)

    matrix = np.array(matrix)

    fig, ax = plt.subplots(figsize=(7, max(3, len(ds_names) * 1.2 + 1.5)))
    im = ax.imshow(matrix, cmap="RdYlGn_r", aspect="auto",
                   vmin=1.0, vmax=min(matrix.max(), 30))

    ax.set_xticks(range(5))
    ax.set_xticklabels([f"FI {i}" for i in range(5)], fontsize=10)
    ax.set_yticks(range(len(ds_names)))
    ax.set_yticklabels(ds_names, fontsize=10)

    for i in range(len(ds_names)):
        for j in range(5):
            val = matrix[i, j]
            txt = f"{val:.0f}×" if val < 99 else "∞"
            color = "white" if val > 10 else "black"
            ax.text(j, i, txt, ha="center", va="center",
                    fontsize=10, color=color, fontweight="500")

    plt.colorbar(im, ax=ax, label="imbalance ratio (1× = balanced)")
    ax.set_title("Class imbalance per FI band\n(how many × more than the rarest band)",
                 fontsize=11, pad=10)
    fig.tight_layout()

    path = os.path.join(outdir, "class_imbalance.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dist] saved: {os.path.basename(path)}")
    return path


# ─── agent distribution charts (NEW) ─────────────────────────────────────────

def chart_agent_all(datasets: dict, outdir: str):
    """
    Grouped bar chart: cowrie / on_device / cloud % per dataset.
    This shows how the real router distributes each dataset across agents.
    """
    ds_names = list(datasets.keys())
    n_ds     = len(ds_names)

    # pre-compute routing for all datasets
    routing  = {name: route_commands(cmds) for name, cmds in datasets.items()}

    fig, ax = plt.subplots(figsize=(max(8, n_ds * 3 + 2), 5))
    x     = np.arange(n_ds)
    bar_w = 0.22
    offsets = np.linspace(-(len(AGENTS)-1)/2 * bar_w,
                           (len(AGENTS)-1)/2 * bar_w,
                           len(AGENTS))

    for i, agent in enumerate(AGENTS):
        counts = []
        for name in ds_names:
            total = len(datasets[name])
            cnt   = len(routing[name].get(agent, []))
            counts.append(cnt / total * 100 if total else 0)

        bars = ax.bar(x + offsets[i], counts, bar_w,
                      label=agent, color=AGENT_COLORS[agent],
                      edgecolor="white", linewidth=0.5)
        for bar, pct in zip(bars, counts):
            if pct >= 2:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                        f"{pct:.0f}%", ha="center", va="bottom",
                        fontsize=8, color="#333")

    ax.set_xticks(x)
    ax.set_xticklabels(ds_names, fontsize=10)
    ax.set_ylabel("% of dataset")
    ax.set_title("Agent routing distribution — per dataset", fontsize=13, pad=12)
    ax.set_ylim(0, 105)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(title="agent", bbox_to_anchor=(1.01, 1), loc="upper left",
              fontsize=9, title_fontsize=9)
    fig.tight_layout()

    path = os.path.join(outdir, "agent_distribution_all.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dist] saved: {os.path.basename(path)}")
    return path


def chart_agent_each(datasets: dict, outdir: str):
    """
    One subplot per dataset showing cowrie/on_device/cloud as a stacked
    horizontal bar — makes it easy to see the cloud fraction at a glance.
    """
    n    = len(datasets)
    fig, axes = plt.subplots(1, n, figsize=(n * 3.5, 4), sharey=False)
    if n == 1:
        axes = [axes]

    for ax, (name, cmds) in zip(axes, datasets.items()):
        routing = route_commands(cmds)
        total   = len(cmds)
        counts  = [len(routing.get(a, [])) for a in AGENTS]
        pcts    = [c / total * 100 if total else 0 for c in counts]

        bars = ax.bar(AGENTS, pcts,
                      color=[AGENT_COLORS[a] for a in AGENTS],
                      edgecolor="white", linewidth=0.8, width=0.5)
        for bar, pct, cnt in zip(bars, pcts, counts):
            if pct >= 1:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                        f"{pct:.0f}%\n({cnt})", ha="center", va="bottom", fontsize=8)

        ax.set_title(name.replace("\n", " "), fontsize=10, pad=8)
        ax.set_xticklabels(AGENTS, fontsize=8)
        ax.set_ylabel("%" if ax == axes[0] else "")
        ax.set_ylim(0, 110)
        ax.spines[["top", "right"]].set_visible(False)
        ax.text(0.98, 0.97, f"n={total}", transform=ax.transAxes,
                ha="right", va="top", fontsize=8, color="#888")

    fig.suptitle("Agent routing distribution per dataset\n"
                 "(based on HydraPoT router — semantic reconstruction policy)",
                 fontsize=12, y=1.04)
    fig.tight_layout()

    path = os.path.join(outdir, "agent_distribution_each.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dist] saved: {os.path.basename(path)}")
    return path


# ─── terminal summary ─────────────────────────────────────────────────────────

def print_summary(datasets: dict, per_band: int):
    print("\n" + "═" * 65)
    print("  DATASET SUMMARY")
    print("═" * 65)

    # per-dataset breakdown
    for name, cmds in datasets.items():
        total   = len(cmds)
        fi_b    = score_commands(cmds)
        routing = route_commands(cmds)
        print(f"\n  {name.replace(chr(10), ' ')}  (n={total})")
        print(f"  {'─'*40}")
        print(f"  FI distribution:")
        for fi in range(5):
            cnt = len(fi_b.get(fi, []))
            pct = cnt / total * 100 if total else 0
            print(f"    FI {fi}  {cnt:5d}  {pct:5.1f}%  {'█' * int(pct/2)}")
        print(f"  Agent routing:")
        for agent in AGENTS:
            cnt = len(routing.get(agent, []))
            pct = cnt / total * 100 if total else 0
            print(f"    {agent:<10}  {cnt:5d}  {pct:5.1f}%  {'█' * int(pct/2)}")

    # combined pool across all datasets (deduped)
    print("\n" + "═" * 65)
    print("  COMBINED POOL  (all datasets merged, deduped)")
    print("═" * 65)

    seen: set[str] = set()
    pool_by_agent: dict[str, list[str]] = {a: [] for a in AGENTS}
    for cmds in datasets.values():
        for cmd in cmds:
            if cmd not in seen:
                seen.add(cmd)
                agent = route_commands([cmd]).get("cowrie", []) and "cowrie" or None
                # re-route individually
    # route the full deduped pool at once
    from core.router import classify
    all_unique = list(seen)
    for cmd in all_unique:
        agent = classify(cmd, [])
        pool_by_agent.setdefault(agent, []).append(cmd)

    total_pool = len(all_unique)
    print(f"\n  Total unique commands: {total_pool}")
    print(f"\n  {'agent':<12}  {'available':>10}  {'% of pool':>10}")
    print(f"  {'─'*40}")
    for agent in AGENTS:
        cnt = len(pool_by_agent.get(agent, []))
        pct = cnt / total_pool * 100 if total_pool else 0
        print(f"  {agent:<12}  {cnt:>10,}  {pct:>9.1f}%  {'█' * int(pct/2)}")

    # feasibility check for Part A
    print("\n" + "─" * 65)
    print("  PART A SAMPLING FEASIBILITY  (per-agent stratified)")
    print("─" * 65)
    print(f"  {'per_agent':>10}  {'total cmds':>10}  {'total measurements':>20}  feasible?")
    print(f"  {'─'*60}")
    min_pool = min(len(pool_by_agent.get(a, [])) for a in AGENTS)
    for n in [30, 50, 100, 150, 200, 300]:
        feasible  = all(len(pool_by_agent.get(a, [])) >= n for a in AGENTS)
        total_c   = n * 3
        total_m   = total_c * 30 * 4   # × trials × arms
        flag      = "✓" if feasible else f"✗ (max={min_pool})"
        print(f"  {n:>10}  {total_c:>10}  {total_m:>20,}  {flag}")

    print(f"\n  → run:  python experiment_data/build_partA_workload.py --per-agent N")
    print("═" * 65 + "\n")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Plot FI + agent distribution for HydraPoT NSC datasets"
    )
    ap.add_argument("--per-band", type=int, default=10)
    ap.add_argument("--out-dir",  type=str, default=OUT_DIR)
    ap.add_argument("--ml4net-sessions", type=int, default=5000,
                    help="number of ML4Net sessions to sample (default 5000)")
    ap.add_argument("--explore", action="store_true",
                    help="terminal-only mode: show pool stats + feasibility, "
                         "skip all chart generation (fast)")
    args = ap.parse_args()

    datasets = load_all_datasets()
    print_summary(datasets, args.per_band)

    if args.explore:
        return   # terminal output only, no charts

    os.makedirs(args.out_dir, exist_ok=True)

    # FI charts
    chart_fi_all(datasets, args.out_dir)
    chart_fi_each(datasets, args.out_dir)
    chart_mixed_preview(datasets, args.per_band, args.out_dir)
    chart_imbalance_heatmap(datasets, args.out_dir)

    # Agent routing charts
    chart_agent_all(datasets, args.out_dir)
    chart_agent_each(datasets, args.out_dir)

    print(f"\n[dist] all charts saved to: {args.out_dir}")


if __name__ == "__main__":
    main()