"""
experiment_data/PartA/plot_partA_percentiles.py
─────────────────────────────────────────────────────────────────
Adds p50/p95/p99 latency + stdev error bars on top of plot_partA.py's
existing report, WITHOUT touching compute_stats (marked "UNCHANGED — do
not modify" in that file) — this reads the same raw records and computes
everything fresh via get_vals()/measure.percentile(), which are already
general-purpose, unprotected helpers.

Usage:
    python experiment_data/PartA/plot_partA_percentiles.py <architecture_overhead dir> [run_id]
    (omit run_id for the latest single run; pass "combined" to use every
    run_id found under the directory)
─────────────────────────────────────────────────────────────────
"""
import os
import sys
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# measure.py lives at the project ROOT now — it is a production module the
# sandbox calls, not sandbox code. Keep the root on sys.path for it.
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")))
import plot_partA as pp
import measure as M

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ARMS_ORDER = [
    ("cowrie_pure", "Pure Cowrie"),
    ("cowrie_hydrapot", "Cowrie (HydraPoT)"),
    ("on_device_pure", "Pure On-device"),
    ("on_device_hydrapot", "On-device (HydraPoT)"),
    ("cloud_pure", "Pure Cloud"),
    ("cloud_hydrapot", "Cloud (HydraPoT)"),
    ("honeyrouter", "HoneyRouter"),
]


def load_records(arch_dir, run_id):
    all_records = []
    for root, _, files in os.walk(arch_dir):
        for f in files:
            if f.endswith(".jsonl"):
                all_records.extend(pp.load_arm_file(os.path.join(root, f)))

    if run_id == "combined":
        return all_records, sorted({r.get("run_id") for r in all_records if r.get("run_id")})

    rids = sorted({r.get("run_id") for r in all_records if r.get("run_id")})
    if run_id is None and rids:
        run_id = rids[-1]
    return [r for r in all_records if r.get("run_id") == run_id], [run_id]


def per_arm_latency_stats(records):
    out = {}
    for arm, label in ARMS_ORDER:
        lat = pp.get_vals(records, arm, "latency_ms")
        if not lat:
            continue
        p25  = M.percentile(lat, 25)
        p75  = M.percentile(lat, 75)
        mean = statistics.mean(lat)
        out[arm] = {
            "label": label,
            "n":     len(lat),
            "mean":  round(mean, 2),
            "std":   round(statistics.pstdev(lat), 2) if len(lat) > 1 else 0.0,
            "p25":   p25,
            "p50":   M.percentile(lat, 50),
            "p75":   p75,
            "iqr":   round(p75 - p25, 2) if p25 is not None and p75 is not None else None,
            "p95":   M.percentile(lat, 95),
            "p99":   M.percentile(lat, 99),
            # matches compute_stats's own definition: 1000/mean_latency_ms
            "throughput": round(1000.0 / mean, 3) if mean else None,
        }
    return out


def print_table(stats):
    # stdev is reported (per requirement) alongside IQR — IQR is the more
    # defensible spread statistic for this data (stdev > mean for several
    # arms here, the signature of a heavily right-skewed distribution,
    # where "mean ± stdev" implies a physically-impossible negative
    # latency at -1 sigma), included as a robustness check, not a
    # replacement.
    print(f"\n{'arm':<24} {'n':>5} {'mean':>9} {'stdev':>9} {'IQR':>9} {'p50':>9} {'p95':>9} {'p99':>9} {'thpt(r/s)':>10}")
    print("-" * 108)
    for arm, label in ARMS_ORDER:
        if arm not in stats:
            continue
        d = stats[arm]
        print(f"{d['label']:<24} {d['n']:>5} {d['mean']:>9.1f} {d['std']:>9.1f} {d['iqr']:>9.1f} "
              f"{d['p50']:>9.1f} {d['p95']:>9.1f} {d['p99']:>9.1f} {d['throughput']:>10.3f}")


def make_figure(stats, outpath):
    arms = [a for a, _ in ARMS_ORDER if a in stats]
    labels = [stats[a]["label"] for a in arms]
    means = [stats[a]["mean"] for a in arms]
    stds = [stats[a]["std"] for a in arms]
    p50s = [stats[a]["p50"] for a in arms]
    p95s = [stats[a]["p95"] for a in arms]
    p99s = [stats[a]["p99"] for a in arms]

    x = range(len(arms))
    w = 0.2

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar([i - 1.5 * w for i in x], means, w, yerr=stds, capsize=4,
           label="mean ± stdev", color="#4C72B0")
    ax.bar([i - 0.5 * w for i in x], p50s, w, label="p50", color="#55A868")
    ax.bar([i + 0.5 * w for i in x], p95s, w, label="p95", color="#C44E52")
    ax.bar([i + 1.5 * w for i in x], p99s, w, label="p99", color="#8172B2")

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Part A — latency mean/stdev + p50/p95/p99 per arm")
    ax.legend()
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"\n[plot] saved {outpath}")


def main():
    if len(sys.argv) < 2:
        print("usage: python plot_partA_percentiles.py <architecture_overhead dir> [run_id|combined]")
        sys.exit(1)
    arch_dir = sys.argv[1]
    run_id = sys.argv[2] if len(sys.argv) > 2 else None

    records, rids = load_records(arch_dir, run_id)
    if not records:
        print(f"[plot] no records found under {arch_dir}")
        sys.exit(1)
    print(f"[plot] using run(s): {rids}  ({len(records)} records)")

    stats = per_arm_latency_stats(records)
    print_table(stats)

    suffix = "combined" if run_id == "combined" else (rids[0] or "latest")
    outdir = os.path.join(arch_dir, "figures_combined" if run_id == "combined" else "figures")
    os.makedirs(outdir, exist_ok=True)
    make_figure(stats, os.path.join(outdir, f"fig10_latency_percentiles_{suffix}.png"))


if __name__ == "__main__":
    main()
