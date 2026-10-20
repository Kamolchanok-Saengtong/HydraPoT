#!/usr/bin/env python3
"""
experiment_data/reproduce.py — re-derive the numbers in the paper's tables.

Each Part already has a summary script, but every one wants a run id or a
directory that a reader has no way to guess. This supplies them.

    python experiment_data/reproduce.py --list      what data is present
    python experiment_data/reproduce.py --part A
    python experiment_data/reproduce.py --all

It only READS existing results. To regenerate the results themselves, run
PartX/run_partX.py first -- that needs the agents, a GPU and an API key.
"""
import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
PY = sys.executable

# part -> (paper table, script, args, the path its inputs live in)
# Parts that take minutes, so a reader does not think it has hung.
SLOW = {"C": "loads BERTScore on GPU over ~2,200 records x 4 arms"}

PARTS = {
    "A": ("Table: per-arm resource overhead",
          "PartA/plot/print_partA_resource_table.py",
          ["results/partA/architecture_overhead", "combined"],
          "results/partA/architecture_overhead"),
    "B": ("Table: context preservation / state ablation",
          "PartB/score/summarize_partB.py",
          ["merged"],
          "results/partB"),
    "C": ("Table: fidelity, latency and cost per arm",
          "PartC/score/summarize_partC.py",
          ["full109_final"],   # summarize_partC prefixes "fidelity_"
          "results/partC/fidelity_full109_final"),
}


def present(rel: str) -> bool:
    return os.path.exists(os.path.join(_HERE, rel))


def show_list() -> None:
    print("\n  part  paper table                                    data present")
    print("  " + "-" * 72)
    for k, (table, _s, _a, data) in PARTS.items():
        print(f"  {k}     {table:<46} {'yes' if present(data) else 'NO'}")
    print(f"\n  data root: {_HERE}\n")


def run_part(key: str) -> int:
    table, script, args, data = PARTS[key]
    print("\n" + "=" * 72)
    print(f"  Part {key} — {table}")
    print("=" * 72)
    if not present(data):
        print(f"  missing: {data}")
        print(f"  run experiment_data/Part{key}/run_part{key}.py first\n")
        return 1
    # A path argument must be absolute: the scripts run with cwd at the repo
    # root, where "PartA/..." does not exist.
    args = [os.path.join(_HERE, x) if "/" in x else x for x in args]
    cmd = [PY, os.path.join(_HERE, script), *args]
    print(f"  $ {' '.join(cmd[1:])}")
    if key in SLOW:
        print(f"  this takes several minutes: {SLOW[key]}")
    # Flushed, or the banner lands after the child's output when piped.
    print(flush=True)
    return subprocess.run(cmd, cwd=_ROOT).returncode


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--part", choices=sorted(PARTS), help="re-derive one part")
    ap.add_argument("--all", action="store_true", help="every part in order")
    ap.add_argument("--list", action="store_true", help="show what data is present")
    a = ap.parse_args()

    if a.list or not (a.part or a.all):
        show_list()
        return
    keys = sorted(PARTS) if a.all else [a.part]
    bad = [k for k in keys if run_part(k) != 0]
    if bad:
        print(f"\n  did not complete: {', '.join(bad)}\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
