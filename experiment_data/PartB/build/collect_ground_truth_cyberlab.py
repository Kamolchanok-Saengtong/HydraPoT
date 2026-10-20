"""
experiment_data/PartB/collect_ground_truth_cyberlab.py
─────────────────────────────────────────────────────────────────
Same ground-truth collection as collect_ground_truth_ml4net.py, applied to
dataset/stateful_benchmark_cyberlab_deduped.json instead. Runs each deduped
cyberlab stateful pair for real in a throwaway Ubuntu 22.04 Docker
container and writes the test_cmd's real output back as "ground_truth", in
place. Skips any pair that already has ground_truth collected.

Safety: any setup_cmd or test_cmd that directly EXECUTES a local file
(matches "./<name>") is BLOCKED — never run for real, recorded as
ground_truth=null, blocked=true.

Requires working Docker access.

Usage:
    python experiment_data/PartB/collect_ground_truth_cyberlab.py
─────────────────────────────────────────────────────────────────
"""

import os
import re
import sys
import json

# PartB/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _NSC, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from build_partB_benchmark import start_container, reset_container, exec_cmd, stop_container

DATASET_PATH = os.path.join(_ROOT, "dataset", "stateful_benchmark_cyberlab_deduped.json")


def _executes_local_file(cmd: str) -> bool:
    return bool(re.match(r"^\./\S+", cmd.strip()))


def main():
    records = json.load(open(DATASET_PATH, encoding="utf-8"))
    todo = [r for r in records if "ground_truth" not in r["pair"]]
    print(f"[ground-truth] {len(records)} pairs total, "
          f"{len(records) - len(todo)} already collected (skipped), {len(todo)} to run")

    if not todo:
        print("[ground-truth] nothing new to collect")
        return

    start_container()

    n_ok, n_empty, n_blocked = 0, 0, 0

    try:
        for i, rec in enumerate(todo, 1):
            pair      = rec["pair"]
            setup_cmd = pair["setup_cmd"]
            test_cmd  = pair["test_cmd"]

            if i > 1:
                reset_container()

            if _executes_local_file(setup_cmd) or _executes_local_file(test_cmd):
                pair["ground_truth"] = None
                pair["blocked"]      = True
                n_blocked += 1
                print(f"[{i}/{len(todo)}] BLOCKED (executes local file): {test_cmd[:70]}")
                continue

            exec_cmd(setup_cmd)
            ground_truth, _rc = exec_cmd(test_cmd)
            pair["ground_truth"] = ground_truth
            pair["blocked"]      = False

            if ground_truth.strip():
                n_ok += 1
                status = "OK"
            else:
                n_empty += 1
                status = "EMPTY"
            print(f"[{i}/{len(todo)}] {status}: {test_cmd[:60]!r} -> {ground_truth[:60]!r}")

    finally:
        stop_container()

    with open(DATASET_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    total = len(todo)
    runnable = n_ok + n_empty
    print(f"\n[ground-truth] wrote {DATASET_PATH}")
    print(f"[ground-truth] {n_ok}/{total} succeeded (non-empty ground truth)")
    print(f"[ground-truth] {n_empty}/{total} ran but produced empty output")
    print(f"[ground-truth] {n_blocked}/{total} blocked (direct binary execution, skipped for safety)")
    if runnable:
        print(f"[ground-truth] success rate of runnable pairs: {n_ok}/{runnable} = {100*n_ok/runnable:.1f}%")


if __name__ == "__main__":
    main()
