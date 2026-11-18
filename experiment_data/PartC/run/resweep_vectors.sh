#!/usr/bin/env bash
# Re-sweep ONLY the two GPU-free configs (vector, vector_irt). Both route only
# to cowrie+cloud, so on_device is never needed -- they run even while the GPU
# is busy with another job. irt (which routes ~22% to on_device) is handled
# separately once the GPU frees.
#
# Needs the Cowrie-capture fix (run_partC needs_cowrie) and the non-fatal
# on_device load (agents.py) already in place.
#
#   bash experiment_data/PartC/run/resweep_vectors.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."

SESSIONS="dataset/partC_stateful_sessions.json"
OMEGAS="0,0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.75,1.0,1.25,1.5,1.75,2.0"
CONFIGS=(
  "experiment_data/results/partC_ml_router/vector_gpqa"
  "experiment_data/results/partC_ml_router/vector_irt_gpqa"
)

for cfg in "${CONFIGS[@]}"; do
  echo "======================================================================"
  echo "  RE-SWEEP (live, --force, GPU-free)  ->  $cfg"
  echo "======================================================================"
  python experiment_data/PartC/score/eval_irt_sweep.py \
    --config-dir "$cfg" \
    --sessions "$SESSIONS" \
    --omega-sweep "$OMEGAS" \
    --force
  echo
done

echo "DONE (vector + vector_irt). irt still pending a free GPU."
echo "Regenerate the table with:"
echo "  python experiment_data/PartC/score/summarize_honeyrouter_v2.py \\"
echo "    --runs irt=irt_paper vector=vector_gpqa vector_irt=vector_irt_gpqa --metrics"
