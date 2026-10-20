"""
experiment_data/PartB/collect_ground_truth_ml4net.py
─────────────────────────────────────────────────────────────────
Runs each deduped ml4net stateful pair (setup_cmd, test_cmd) for real in a
throwaway Ubuntu 22.04 Docker container and writes the test_cmd's real
output back into dataset/stateful_benchmark_ml4net_deduped.json as
"ground_truth", in place.

Reuses build_partB_benchmark.py's Docker helpers (start_container/
reset_container/exec_cmd/stop_container) — same image, same container
lifecycle, nothing reinvented. Container is reset between every pair for a
clean filesystem each time.

Safety: any setup_cmd or test_cmd that directly EXECUTES a local file
(matches "./<name>") is BLOCKED — never run for real, even in the
throwaway container (this is how the reconstructed usb_ver-style malware
binaries from the ml4net chunked-ELF-drop sessions get handled). Recorded
as ground_truth=null, blocked=true — same convention Part C already uses
for its own BLOCKED command set (rm, dd, kill, etc.). Every other pair
(echo/touch/mkdir/cat/ls/chmod/cd/useradd/id/systemctl/export) runs for
real.

Requires working Docker access (your user in the `docker` group, or a
shell where `sudo docker` doesn't prompt for a password) — this script
does not attempt to escalate or bypass that itself.

Usage:
    python experiment_data/PartB/collect_ground_truth_ml4net.py
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

DATASET_PATH = os.path.join(_ROOT, "dataset", "stateful_benchmark_ml4net_deduped.json")


def _executes_local_file(cmd: str) -> bool:
    """True if `cmd` directly runs a local file (e.g. './usb_ver') — never
    run for real, even in a throwaway container."""
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
