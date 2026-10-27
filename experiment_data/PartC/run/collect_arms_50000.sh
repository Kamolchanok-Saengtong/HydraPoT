#!/usr/bin/env bash
# experiment_data/PartC/run/collect_arms_50000.sh — once ground truth is
# collected, run the four arms over the 50,006-command dataset.
#
# Waits for collect_ground_truth_sessions.py to exit first: the arms are
# scored against ground_truth, so starting while it is still being written
# would score the arms against nulls.
#
# Output goes to results/partC/fidelity_50000/ -- run_partC.py turns --tag X
# into fidelity_X, so the existing results/partC/fidelity/ (the 2179-command
# run every current Part C number comes from) is left alone.
#
# Arm order is deliberate: the three forced arms first, the regex router last.
# Each forced arm is one agent answering every command, which is what the
# router's choices are later compared against; honeyrouter leaves
# force_agent=None so core/router.py classify() decides, and that is the
# regex baseline HoneyRouter v2 has to beat.
#
# Usage:
#   experiment_data/PartC/run/collect_arms_50000.sh [GT_PID]
#
#     GT_PID  the ground-truth collector to wait for (default: found by name,
#             and if none is running it starts immediately)
#
# COSTS REAL MONEY: the cloud arm answers all ~50,000 runnable commands at
# roughly $0.00058 each, so expect ~$29 for that arm alone, plus whatever
# share honeyrouter routes to cloud.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
source honeypot_new/bin/activate

DATASET="dataset/dataset_groundtruth_ml4net_50006.json"
TAG="50000"
OUT="experiment_data/results/partC/fidelity_${TAG}"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG="experiment_data/results/partC/arms_${TAG}_${STAMP}.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

# Watched BY NAME, not by a latched PID: the collector may be killed and
# restarted (it was, to get sudo out of its path) and a PID captured here
# would then be dead while the real run carried on.
GT_PAT='collect_ground_truth_sessions.py'

echo "dataset  $DATASET"
echo "output   $OUT"
echo "log      $LOG"
echo

if pgrep -f "$GT_PAT" >/dev/null; then
    echo "waiting for ground truth to finish (polling by name) ..."
    # Polling, not `wait`: that only works for children of this shell, and the
    # collector runs in its own screen. Two consecutive misses before giving
    # up, so a restart between polls is not read as "finished".
    misses=0
    while (( misses < 2 )); do
        sleep 60
        if pgrep -f "$GT_PAT" >/dev/null; then misses=0; else misses=$((misses+1)); fi
    done
    echo "ground truth finished at $(date '+%F %T')"
else
    echo "no ground-truth collector running -- checking the dataset directly"
fi
echo

# Refuse to run against a half-filled dataset. A command with ground_truth
# null cannot be scored, and finding that out after paying for 50,000 cloud
# calls is the expensive way to learn it.
python -u - "$DATASET" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
cmds = [c for s in d["sessions"] for c in s["commands"]]
missing = sum(1 for c in cmds if c.get("ground_truth") is None)
print(f"[check] {len(cmds)} commands, {len(cmds)-missing} with ground truth, "
      f"{missing} missing")
if missing:
    raise SystemExit(
        f"[check] ABORT: {missing} commands have no ground truth yet.\n"
        f"        Let the collector finish, or re-run it on this dataset.")
PY
echo

# on_device LAST. It is ~3.7s/command on the local GPU -- about 50 hours for
# 50,000 commands -- so running it second would block cloud and honeyrouter
# behind it and leave an overnight run with one finished arm instead of three.
for ARM in cowrie cloud honeyrouter on_device; do
    echo "############ arm: $ARM ############"
    date '+start %F %T'
    python -u experiment_data/PartC/run/run_partC.py \
        --sessions "$DATASET" \
        --arms "$ARM" \
        --tag "$TAG"
    date '+done  %F %T'
    echo
done

echo "############ what was written ############"
ls -la "$OUT"
for ARM in cowrie cloud honeyrouter on_device; do
    F="$OUT/${ARM}.jsonl"
    [[ -f "$F" ]] && printf "  %-14s %s rows\n" "$ARM" "$(wc -l < "$F")"
done

echo
echo "next -- judge these fresh (7 rotating keys), then score:"
echo "  python experiment_data/PartC/judge/llm_judge_score.py score \\"
echo "      --results-dir $OUT --api-key-env API_KEY"
echo
echo "done -> $LOG"
