#!/usr/bin/env bash
# The 4th identity experiment, bench-learn+net: the identity starts at the GPQA
# benchmark score and is TRAINED together with the f/g heads. Trains it, live
# omega-sweeps it, then prints one table with all four.
#
#   paper-128        irt           learned, 128 numbers          trained
#   bench-fixed      vector        benchmark score, frozen       no network
#   bench-fixed+net  vector_irt    benchmark score, frozen       trained
#   bench-learn+net  vector_learn  benchmark score, LEARNED      trained   <- this script
#
# Only this config's folder is touched. A learned identity can move an arm out
# of the middle and make on_device reachable, so the sweep may need the GPU.
#
#   bash experiment_data/PartC/run/sweep_live_learn.sh            # train + sweep
#   bash experiment_data/PartC/run/sweep_live_learn.sh --train-only
set -euo pipefail
cd "$(dirname "$0")/../../.."

SESSIONS="dataset/partC_stateful_sessions.json"
OMEGAS="0,0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.75,1.0,1.25,1.5,1.75,2.0"
# train_ml_router.py names its own folder (<identity>_<axis>); we move it to the readable name
TRAINED="experiment_data/results/partC_ml_router/vector_learn_gpqa"
CFG="experiment_data/results/partC_ml_router/bench-learn+net"
SEED="experiment_data/results/partC_ml_router/benchmarklist.seed.json"

echo "TRAIN  [bench-learn+net]  ->  $CFG"
rm -rf "$CFG" "$TRAINED"; mkdir -p "$TRAINED"
cp -v "$SEED" "$TRAINED/benchmarklist.json"   # fixed, dated benchmark numbers
python experiment_data/PartC/run/train_ml_router.py --identity bench-learn+net --axis gpqa
mv "$TRAINED" "$CFG"

[ "${1:-}" = "--train-only" ] && { echo "trained; sweep skipped"; exit 0; }

echo "LIVE SWEEP  [bench-learn+net]  ->  $CFG"
python experiment_data/PartC/score/eval_irt_sweep.py \
  --config-dir "$CFG" --sessions "$SESSIONS" --omega-sweep "$OMEGAS"

python experiment_data/PartC/score/summarize_honeyrouter_v2.py --metrics \
  --runs paper-128=irt_paper bench-fixed=vector_gpqa \
         bench-fixed+net=vector_irt_gpqa "bench-learn+net=bench-learn+net"
