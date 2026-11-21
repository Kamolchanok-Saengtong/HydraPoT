#!/usr/bin/env bash
# bench+2learn+net: the identity is 3 numbers per agent -- the GPQA benchmark score plus
# 2 learned numbers -- all trained together with the f/g heads. One number per agent puts
# the three agents on a line and the middle one (on-device) can never be picked; with 3
# numbers it can. Trains it, then live omega-sweeps it, then prints the table.
#
#   bash experiment_data/PartC/run/sweep_live_learn_x2.sh              # train + sweep
#   bash experiment_data/PartC/run/sweep_live_learn_x2.sh --train-only
set -euo pipefail
cd "$(dirname "$0")/../../.."

SESSIONS="dataset/partC_stateful_sessions.json"
OMEGAS="0,0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.75,1.0,1.25,1.5,1.75,2.0"
# train_ml_router.py names its own folder (<identity>_<axis>_x<extra>); moved to the readable name
TRAINED="experiment_data/results/partC_ml_router/vector_learn_gpqa_x2"
CFG="experiment_data/results/partC_ml_router/bench+2learn+net"
SEED="experiment_data/results/partC_ml_router/benchmarklist.seed.json"

echo "TRAIN  [bench+2learn+net]  ->  $CFG"
rm -rf "$CFG" "$TRAINED"; mkdir -p "$TRAINED"
cp -v "$SEED" "$TRAINED/benchmarklist.json"
python experiment_data/PartC/run/train_ml_router.py --identity bench-learn+net --axis gpqa --extra-dims 2
mv "$TRAINED" "$CFG"

[ "${1:-}" = "--train-only" ] && { echo "trained; sweep skipped"; exit 0; }

echo "LIVE SWEEP  [bench+2learn+net]  ->  $CFG"
python experiment_data/PartC/score/eval_irt_sweep.py \
  --config-dir "$CFG" --sessions "$SESSIONS" --omega-sweep "$OMEGAS"

python experiment_data/PartC/score/summarize_honeyrouter_v2.py --metrics \
  --runs "bench-learn+net=bench-learn+net" "bench+2learn+net=bench+2learn+net"
