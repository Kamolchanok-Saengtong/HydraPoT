#!/usr/bin/env bash
# Re-run the LIVE omega-sweep for all 3 trained configs with --force, after the
# Cowrie/on_device connection fix in run_partC.py (irt_router now connects both,
# so forced cowrie/on_device picks return real output instead of empty).
#
# Training is NOT repeated -- the trained policies on disk are reused. Only the
# live sweep is redone, which re-bills cloud and re-runs cowrie/on_device.
#
#   bash experiment_data/PartC/run/resweep_live.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."          # repo root

SESSIONS="dataset/partC_stateful_sessions.json"
OMEGAS="0,0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.75,1.0,1.25,1.5,1.75,2.0"
CONFIGS=(
  "experiment_data/results/partC_ml_router/irt_paper"
  "experiment_data/results/partC_ml_router/vector_gpqa"
  "experiment_data/results/partC_ml_router/vector_irt_gpqa"
)

for cfg in "${CONFIGS[@]}"; do
  echo "======================================================================"
  echo "  RE-SWEEP (live, --force)  ->  $cfg"
  echo "======================================================================"
  python experiment_data/PartC/score/eval_irt_sweep.py \
    --config-dir "$cfg" \
    --sessions "$SESSIONS" \
    --omega-sweep "$OMEGAS" \
    --force
  echo
done

echo "======================================================================"
echo "  RESULT — irt vs vector vs vector_irt (gpqa), post-fix"
echo "======================================================================"
python experiment_data/PartC/score/summarize_honeyrouter_v2.py \
  --runs irt=irt_paper vector=vector_gpqa vector_irt=vector_irt_gpqa --metrics \
  > experiment_data/results/partC_ml_router/summary_metrics.txt
cat experiment_data/results/partC_ml_router/summary_metrics.txt

echo
echo "DONE. Per-config curves refreshed: <config>/omega_sweep.json"
