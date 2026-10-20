"""
experiment_data/PartA/print_partA_resource_table.py
─────────────────────────────────────────────────────────────────
Prints a 7-arm table of VRAM / RAM / CPU utilization (mean ± stdev) —
terminal-only, no figures, no file writes. Reuses the same record loading
as plot_partA_percentiles.py.

Usage:
    python experiment_data/PartA/print_partA_resource_table.py <architecture_overhead dir> [run_id|combined]
─────────────────────────────────────────────────────────────────
"""
import os
import sys
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import plot_partA as pp
from plot_partA_percentiles import load_records, ARMS_ORDER


def _stat(records, arm, field):
    vals = pp.get_vals(records, arm, field)
    if not vals:
        return None
    return {
        "n":    len(vals),
        "mean": round(statistics.mean(vals), 2),
        "std":  round(statistics.pstdev(vals), 2) if len(vals) > 1 else 0.0,
    }


def main():
    if len(sys.argv) < 2:
        print("usage: python print_partA_resource_table.py <architecture_overhead dir> [run_id|combined]")
        sys.exit(1)
    arch_dir = sys.argv[1]
    run_id = sys.argv[2] if len(sys.argv) > 2 else None

    records, rids = load_records(arch_dir, run_id)
    if not records:
        print(f"[table] no records found under {arch_dir}")
        sys.exit(1)
    print(f"[table] using run(s): {rids}  ({len(records)} records)\n")

    fields = [
        ("vram_after_mb", "VRAM(MB)"),
        ("ram_after_mb",  "RAM(MB)"),
        ("cpu_pct",       "CPU(%)"),
    ]

    for field, label in fields:
        print(f"\n{label}")
        header = f"{'arm':<24} {'n':>6} {'mean':>12} {'stdev':>12}"
        print(header)
        print("-" * len(header))
        for arm, arm_label in ARMS_ORDER:
            s = _stat(records, arm, field)
            if s is None:
                continue
            print(f"{arm_label:<24} {s['n']:>6} {s['mean']:>12.2f} {s['std']:>12.2f}")


if __name__ == "__main__":
    main()
