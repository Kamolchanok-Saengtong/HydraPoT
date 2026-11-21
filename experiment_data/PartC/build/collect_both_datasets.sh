#!/usr/bin/env bash
# experiment_data/PartC/build/collect_both_datasets.sh — select sessions and
# collect Docker ground truth for BOTH source datasets, ml4net and cyberlab,
# as two separate files.
#
# Separate on purpose: the two are not comparable. ml4net has 233k sessions
# and 407k distinct commands across all five FI bands; cyberlab_2019-05-13
# has 174 sessions and 23 distinct commands with FI3 and FI4 empty, so a
# balanced selection from it is impossible. Pooling them would bury cyberlab
# (23 commands against 407k) and make neither result interpretable. Two
# files, named dataset_groundtruth_<source>_<N>.json, keep them reportable
# side by side.
#
# Each dataset goes through the same two stages: select_stateful_sessions.py
# picks sessions and writes a fresh file with no ground truth in it, then
# collect_ground_truth_sessions.py runs every command for real in a throwaway
# Ubuntu container (built from config.yaml) and writes the output back.
#
# Requires working Docker: build_partB_benchmark.py shells out to
# `sudo docker`, so run this where sudo does not prompt, or the collection
# stage will hang on a password prompt it cannot answer.
#
# Usage:
#     experiment_data/PartC/build/collect_both_datasets.sh [TARGET_COMMANDS]
#
#     TARGET_COMMANDS  minimum RUNNABLE commands wanted per dataset
#                      (default 50000). cyberlab cannot reach a large target
#                      -- it holds under a thousand runnable commands in
#                      total -- so it stops when its pool is exhausted and
#                      says so. That is expected, not a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
source honeypot_new/bin/activate

TARGET="${1:-50000}"
LOGDIR="experiment_data/results/partC/ground_truth_logs"
mkdir -p "$LOGDIR"
STAMP="$(date +%Y%m%d_%H%M%S)"

SELECT="experiment_data/PartC/build/select_stateful_sessions.py"

run_one() {
    local source="$1"
    local log="$LOGDIR/${source}_${STAMP}.log"
    echo
    echo "=============================================================="
    echo "  $source  (target $TARGET runnable commands)"
    echo "  log: $log"
    echo "=============================================================="
    # --collect chains straight into collect_ground_truth_sessions.py on the
    # file just written, so the dataset path is never typed by hand and a
    # stale one cannot be picked up by mistake.
    #
    # Not `set -e`'s problem to decide: a failure in one source should not
    # throw away the other source's hours of collection, so the exit code is
    # captured and reported at the end instead of killing the script.
    if python -u "$SELECT" --source "$source" \
            --target-commands "$TARGET" --collect 2>&1 | tee "$log"; then
        echo "[$source] done"
        return 0
    else
        echo "[$source] FAILED — see $log"
        return 1
    fi
}

failed=()
for source in ml4net cyberlab; do
    run_one "$source" || failed+=("$source")
done

echo
echo "=============================================================="
echo "  datasets written"
echo "=============================================================="
ls -la dataset/dataset_groundtruth_*.json 2>/dev/null || echo "  (none)"

# A dataset is only usable if every command actually got ground truth. A run
# interrupted part way leaves nulls behind -- which is deliberate, so they
# are visible -- and this is where they become visible.
echo
echo "  per-file completeness:"
python -u - <<'PY'
import glob, json, os
for path in sorted(glob.glob("dataset/dataset_groundtruth_*.json")):
    d = json.load(open(path, encoding="utf-8"))
    cmds = [c for s in d["sessions"] for c in s["commands"]]
    got = sum(1 for c in cmds if c.get("ground_truth") is not None)
    err = sum(1 for c in cmds if c.get("error"))
    pct = 100 * got / len(cmds) if cmds else 0
    flag = "" if got == len(cmds) else "   <-- INCOMPLETE"
    print(f"    {os.path.basename(path):<46} "
          f"{got}/{len(cmds)} ({pct:.1f}%) collected, {err} errored{flag}")
PY

if ((${#failed[@]})); then
    echo
    echo "  FAILED: ${failed[*]}"
    exit 1
fi
echo
echo "  both datasets collected"
