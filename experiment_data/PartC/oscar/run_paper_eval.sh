#!/usr/bin/env bash
# Old vs new HydraPoT, sized like OSCAR's evaluation (Gil et al. TDSC 2026):
#   Table I    create-then-revisit, N=30 sessions per system
#   Table XIV  session length L = 5 20 40 80 160, 3 runs each
# All model-served commands go to the cloud LLM on both sides.
#
#   bash run_paper_eval.sh <old repo> <new repo> <results dir>
set -u
OLD=$1
NEW=$2
OUT=$3
PY=/mnt/data-partition/honeypot/honeypot_new/bin/python
cd "$(dirname "$0")"
mkdir -p "$OUT"

$PY probe.py --repo "$OLD" --fillers 5 --runs 30 --out "$OUT/table1_old.json" > "$OUT/table1_old.log" 2>&1 &
$PY probe.py --repo "$NEW" --fillers 5 --runs 30 --out "$OUT/table1_new.json" > "$OUT/table1_new.log" 2>&1 &
$PY probe.py --repo "$OLD" --fillers 5 20 40 80 160 --runs 3 --out "$OUT/table14_old.json" > "$OUT/table14_old.log" 2>&1 &
$PY probe.py --repo "$NEW" --fillers 5 20 40 80 160 --runs 3 --out "$OUT/table14_new.json" > "$OUT/table14_new.log" 2>&1 &
wait

$PY summarize.py --dir "$OUT" | tee "$OUT/summary.txt"
echo "DONE $(date)" >> "$OUT/summary.txt"
