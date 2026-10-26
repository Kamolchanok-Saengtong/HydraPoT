#!/usr/bin/env bash
# experiment_data/PartC/run/train_honeyrouter_irt.sh — retrain the IRT/NN/PPO
# HoneyRouter (honeyrouter/cli.py --train) on the current, reorg-consistent
# data, sweep the cost-tradeoff omega in [0,2] at 5 points, and copy the
# trained model + its performance into experiment_data/results/partC/ --
# nothing is written back into honeyrouter/out/ by this script, that
# directory is just where the phase scripts keep their own checkpoints.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
source honeypot_new/bin/activate

OUT="experiment_data/results/partC/honeyrouter_irt"
mkdir -p "$OUT"

echo "[1/2] training (phase 1 IRT -> phase 2 policy pretrain -> phase 3 PPO) ..."
python -u honeyrouter/cli.py --train

echo "[2/2] reviewing: omega sweep, 5 points in [0,2] ..."
python -u honeyrouter/cli.py --review --points 5 --policy rl \
  | tee "$OUT/review.txt"

python -u -c "
import json, sys
sys.path.insert(0, '.')
from honeyrouter.cli import sweep, baselines
json.dump({'sweep': sweep('rl', points=5), 'baselines': baselines()},
          open('$OUT/review.json', 'w'), indent=2)
"

echo "[3/3] 6-metric semantic score + real judge score, per omega point ..."
python -u experiment_data/PartC/score/eval_irt_sweep.py --points 5 --policy rl \
  | tee "$OUT/sweep_semantic_and_judge.txt"

cp honeyrouter/out/predictor.pt "$OUT/"
cp honeyrouter/out/routing_policy.pt "$OUT/"
cp honeyrouter/out/routing_policy_rl.pt "$OUT/"
cp honeyrouter/out/router_state.json "$OUT/" 2>/dev/null || true

echo
echo "wrote model + performance -> $OUT/"
ls -la "$OUT"
