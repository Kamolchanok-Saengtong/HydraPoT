#!/usr/bin/env bash
# One shot: RETRAIN 3 router configs, then LIVE omega-sweep each.
# A 3-way identity ablation, all on the GPQA axis:
#   - irt         : paper, identity LEARNED from the replay      (baseline)
#   - vector      : identity = frozen benchmark score, NO head   (--identity vector --axis gpqa)
#   - vector_irt  : frozen benchmark score + TRAINED f/g heads   (--identity vector_irt --axis gpqa)
#
# Training reads results/partC/fidelity/ (the 2179-command set) and is fast/no
# cloud. The sweep is LIVE: the picked agent is really called per omega (fresh
# state, real on-device/cloud inference), so every omega bills the cloud. Safe
# to leave on `screen`.
#
# Dense where it matters: 0.05 steps through [0,0.5] then 0.25 up to 2.0 -- the
# same 17-point shape as last time. The sweep is incremental, so re-running
# after a crash only computes omegas not already on disk.
#
#   bash experiment_data/PartC/run/sweep_live_both.sh
set -euo pipefail

cd "$(dirname "$0")/../../.."          # repo root

SESSIONS="dataset/partC_stateful_sessions.json"   # the original 2179-command set
OMEGAS="0,0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.75,1.0,1.25,1.5,1.75,2.0"

# label | train flags | config folder the training writes to
RUNS=(
  "irt||experiment_data/results/partC_ml_router/irt_paper"
  "vector|--identity vector --axis gpqa|experiment_data/results/partC_ml_router/vector_gpqa"
  "vector_irt|--identity vector_irt --axis gpqa|experiment_data/results/partC_ml_router/vector_irt_gpqa"
)

echo "sessions : $SESSIONS"
echo "omegas   : $OMEGAS"
echo

# Pinned benchmark cache (both axes, retrieved 2026-10-31). Seeded into each
# config folder BEFORE training so Phase 1 reads it instead of fetching from
# benchmarklist.com -- the live net fetch is flaky ("connection reset") and a
# thesis run should use fixed, dated numbers anyway.
SEED="experiment_data/results/partC_ml_router/benchmarklist.seed.json"

# ── 1. retrain both ───────────────────────────────────────────────────────────
for r in "${RUNS[@]}"; do
  IFS="|" read -r label flags cfg <<< "$r"
  echo "======================================================================"
  echo "  TRAIN  [$label]  ->  $cfg"
  echo "======================================================================"
  rm -rf "$cfg"                               # clean slate -- fresh retrain
  mkdir -p "$cfg"
  cp -v "$SEED" "$cfg/benchmarklist.json"     # pre-seed cache, no network fetch
  # shellcheck disable=SC2086
  python experiment_data/PartC/run/train_ml_router.py $flags
  echo
done

# ── 2. live sweep both ────────────────────────────────────────────────────────
for r in "${RUNS[@]}"; do
  IFS="|" read -r label flags cfg <<< "$r"
  echo "======================================================================"
  echo "  LIVE SWEEP  [$label]  ->  $cfg"
  echo "======================================================================"

  # A replay-based sweep left over from before is backed up once, so the live
  # curve starts clean instead of reusing replay points. An existing LIVE sweep
  # is kept -- the incremental cache extends it rather than re-billing it.
  sweep="$cfg/omega_sweep.json"
  if [ -f "$sweep" ] && ! grep -q '"mode": "live"' "$sweep"; then
    mv -v "$sweep" "$cfg/omega_sweep.replay.bak"
  fi

  python experiment_data/PartC/score/eval_irt_sweep.py \
    --config-dir "$cfg" \
    --sessions "$SESSIONS" \
    --omega-sweep "$OMEGAS"
  echo
done

# ── 3. compare the two axes ───────────────────────────────────────────────────
echo "======================================================================"
echo "  RESULT — irt vs vector vs vector_irt (gpqa)"
echo "======================================================================"
python experiment_data/PartC/score/summarize_honeyrouter_v2.py \
  --runs irt=irt_paper vector=vector_gpqa vector_irt=vector_irt_gpqa

echo
echo "DONE. Per-config curves: <config>/omega_sweep.json"
