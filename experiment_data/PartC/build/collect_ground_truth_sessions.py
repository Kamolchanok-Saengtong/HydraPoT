"""
experiment_data/PartC/collect_ground_truth_sessions.py
─────────────────────────────────────────────────────────────────
Runs every session in dataset/partC_stateful_sessions.json for real in a
throwaway Ubuntu 22.04 Docker container. Commands within ONE session run
in order inside the SAME container — so state accumulates realistically
(e.g. 'mkdir foo' then 'cd foo' actually sees that directory). The
container is reset to a fresh state only BETWEEN different sessions, never
between commands within the same session.

Reuses build_partB_benchmark.py's Docker helpers (start_container/
reset_container/exec_cmd/stop_container) — same image, same lifecycle,
nothing reinvented.

Writes ground_truth back into dataset/partC_stateful_sessions.json in
place, adding a "ground_truth" field to every command dict. Checkpoints
every 10 sessions (and on exit) so progress isn't lost if interrupted —
this can be a long run (2000+ docker exec calls plus ~270 container resets).

Every session in this file was already filtered to have ZERO blocked
commands (see select_stateful_sessions.py), so "blocked" should never
actually trigger here — handled anyway for safety/robustness.

Requires working Docker access (your user in the `docker` group, or a
shell where `sudo docker` doesn't prompt for a password) — this script
does not attempt to escalate or bypass that itself.

Usage:
    python experiment_data/PartC/collect_ground_truth_sessions.py
─────────────────────────────────────────────────────────────────
"""

import os
import sys
import json

# PartC/, not this sub-folder: _NSC and _ROOT are derived from it.
_HERE  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSC   = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT  = os.path.abspath(os.path.join(_HERE, "..", ".."))
_PARTB = os.path.join(_NSC, "PartB")
for p in (_ROOT, _NSC, _PARTB):
    if p not in sys.path:
        sys.path.insert(0, p)

from build_partB_benchmark import start_container, reset_container, exec_cmd, stop_container

DATASET_PATH = os.path.join(_ROOT, "dataset", "partC_stateful_sessions.json")


def _checkpoint(data):
    with open(DATASET_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    data     = json.load(open(DATASET_PATH, encoding="utf-8"))
    sessions = data["sessions"]
    total_sessions = len(sessions)
    total_commands = sum(len(s["commands"]) for s in sessions)
    print(f"[ground-truth] {total_sessions} sessions, {total_commands} commands to run")

    start_container()

    n_ok = n_empty = n_blocked = n_error = done_commands = 0

    try:
        for i, s in enumerate(sessions, 1):
            if i > 1:
                reset_container()   # fresh container PER SESSION, not per command

            for c in s["commands"]:
                if c.get("blocked"):
                    c["ground_truth"] = None
                    n_blocked += 1
                    continue

                # any single command failing (timeout, decode issue, docker
                # hiccup, etc.) must not kill a run that's collecting 2000+
                # commands across ~270 container resets
                try:
                    ground_truth, _rc = exec_cmd(c["cmd"])
                except Exception as e:
                    c["ground_truth"] = None
                    c["error"] = str(e)
                    n_error += 1
                    done_commands += 1
                    continue

                c["ground_truth"] = ground_truth
                if ground_truth.strip():
                    n_ok += 1
                else:
                    n_empty += 1
                done_commands += 1

            if i % 10 == 0 or i == total_sessions:
                print(f"[ground-truth] {i}/{total_sessions} sessions, "
                      f"{done_commands}/{total_commands} commands "
                      f"({n_ok} ok, {n_empty} empty, {n_blocked} blocked, {n_error} error)")
                _checkpoint(data)   # don't lose progress if interrupted

    finally:
        stop_container()
        _checkpoint(data)

    runnable = n_ok + n_empty
    print(f"\n[ground-truth] done -> {DATASET_PATH}")
    print(f"[ground-truth] {n_ok}/{total_commands} succeeded (non-empty ground truth)")
    print(f"[ground-truth] {n_empty}/{total_commands} ran but produced empty output")
    print(f"[ground-truth] {n_blocked}/{total_commands} blocked (skipped for safety)")
    print(f"[ground-truth] {n_error}/{total_commands} errored (see each record's \"error\" field)")
    if runnable:
        print(f"[ground-truth] success rate of runnable commands: "
              f"{n_ok}/{runnable} = {100*n_ok/runnable:.1f}%")


if __name__ == "__main__":
    main()
