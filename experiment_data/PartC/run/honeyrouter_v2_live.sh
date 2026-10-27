#!/usr/bin/env bash
# experiment_data/PartC/run/honeyrouter_v2_live.sh — train the three phases,
# then let the Stage-3 network choose the agent and run it LIVE, next to the
# regex router on the same sessions, and score both the same way.
#
# This is the HoneyRouter v2 vs regex comparison. The two arms differ ONLY in
# who picks the agent:
#
#   honeyrouter   force_agent=None  -> core/router.py classify(), regex + FI
#   irt_router    force_agent=pick  -> Stage-3 policy (irt_router_live.py)
#
# Both run in the same invocation, over the same sessions, in the same order,
# against the real Cowrie / on-device / cloud agents. Nothing is replayed, so
# latency, tokens and cloud dollars are this run's own. The judge is then run
# fresh over both arms' responses -- no reuse of earlier judge files, because
# those scored different responses.
#
# Judge keys rotate: --api-key-env API_KEY makes KeyPool pick up API_KEY_1 ..
# API_KEY_7 from experiment_data/.env and move to the next one on a quota
# error, so a long judging pass is not lost to one exhausted key.
#
# Usage:
#   experiment_data/PartC/run/honeyrouter_v2_live.sh [OMEGA] [SESSIONS]
#
#     OMEGA     preference weight on -cost for the policy (default 0.5)
#     SESSIONS  dataset to run (default dataset/partC_stateful_sessions.json,
#               the 2179-command set the policy was trained on)
#
# COSTS REAL MONEY. Every command the policy sends to cloud is a billed call,
# and both arms run, so cloud is paid for twice over whatever each routes
# there. Start with a small SESSIONS file if that matters.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
source honeypot_new/bin/activate

OMEGA="${1:-0.5}"
SESSIONS="${2:-dataset/partC_stateful_sessions.json}"
TAG="v2_omega${OMEGA}"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG="experiment_data/results/partC/v2_${STAMP}.log"
mkdir -p "$(dirname "$LOG")"

# Written by train_ml_router.py; the hash covers the hyperparameters AND the
# data revision, so it is stable for a given config and printed below to be
# checked rather than assumed.
CONFIG_DIR=""

exec > >(tee -a "$LOG") 2>&1
echo "log      $LOG"
echo "omega    $OMEGA"
echo "sessions $SESSIONS"
echo

echo "############ 1/4  TRAIN phase 1 -> 2 -> 3 ############"
python -u experiment_data/PartC/run/train_ml_router.py

# The trainer prints "config <hash> -> <dir>/" as its first line. Read the dir
# back from disk rather than hardcoding a hash that changes whenever the
# config or the data revision does.
CONFIG_DIR="$(python -u - <<'PY'
import os, sys
sys.path.insert(0, "experiment_data/PartC/run")
import importlib.util as u
s = u.spec_from_file_location("t", "experiment_data/PartC/run/train_ml_router.py")
m = u.module_from_spec(s); s.loader.exec_module(m)
cfg = {k: m.DEFAULTS[k] for k in
       ("p1_epochs", "p2_steps", "p2_batch", "p3_steps", "run_rl", "mixup")}
cfg["data_rev"] = "unit-score-drop-unjudged"
print(os.path.join("experiment_data/results/partC_ml_router",
                   f"config_{m.config_hash(cfg)}"))
PY
)"
echo
echo "trained model: $CONFIG_DIR"
test -f "$CONFIG_DIR/routing_policy_rl.pt" || {
    echo "ERROR: no Stage-3 policy at $CONFIG_DIR/routing_policy_rl.pt"
    echo "       training did not finish, or ran with --no-rl"
    exit 1
}

echo
echo "############ 2/4  network picks the agent, runs LIVE ############"
echo "  irt_router  = Stage-3 policy decides   (HoneyRouter v2)"
echo "  honeyrouter = core/router.py regex     (baseline)"
python -u experiment_data/PartC/run/run_partC.py \
    --sessions "$SESSIONS" \
    --arms irt_router,honeyrouter \
    --irt-config-dir "$CONFIG_DIR" \
    --irt-policy rl \
    --irt-omega "$OMEGA" \
    --tag "$TAG"

RESULTS="experiment_data/results/partC/fidelity_${TAG}"
test -d "$RESULTS" || { echo "ERROR: no $RESULTS -- the live run wrote nothing"; exit 1; }

echo
echo "############ 3/4  LLM-as-a-judge, fresh, 7 rotating keys ############"
python -u experiment_data/PartC/judge/llm_judge_score.py score \
    --results-dir "$RESULTS" \
    --arms irt_router,honeyrouter \
    --api-key-env API_KEY

echo
echo "############ 4/4  semantic + judge + cost, side by side ############"
# Computed here with score_all_metrics._fast_metrics -- the same function every
# other Part C arm was scored with. Inline because score_all_metrics.py and
# cost_analysis.py take no arguments and read results/partC/fidelity/ only, so
# neither can be pointed at a tagged folder.
RESULTS="$RESULTS" python -u - <<'PY'
import json, os, sys, glob
from collections import defaultdict
sys.path.insert(0, ".")
sys.path.insert(0, "experiment_data/PartC/score")
from score_all_metrics import _fast_metrics

R = os.environ["RESULTS"]
ARMS = ("irt_router", "honeyrouter")
METRICS = ("cosine_score", "levenshtein_score", "jaro_winkler_score",
           "sequence_score", "bleu_score", "exact_match")


def judge_scores(arm):
    """Whatever the judge just wrote for this arm, keyed per command."""
    out = {}
    for p in glob.glob(os.path.join(R, "judge", arm, "judge_scored_*.jsonl")):
        for line in open(p, encoding="utf-8"):
            r = json.loads(line)
            if r.get("judge_score") is not None:
                out[(str(r["session_id"]), r["position_in_session"])] = r["judge_score"]
    return out


rows = {}
for arm in ARMS:
    path = os.path.join(R, f"{arm}.jsonl")
    if not os.path.isfile(path):
        print(f"  (no {arm}.jsonl)")
        continue
    rows[arm] = [json.loads(l) for l in open(path, encoding="utf-8")]

hdr = f"  {'arm':<14}{'judge':>7}" + "".join(f"{m.split('_')[0]:>9}" for m in METRICS) \
      + f"{'cloud $':>10}{'cloud':>7}{'on_dev':>8}{'cowrie':>8}"
print("=" * len(hdr))
print("  HoneyRouter v2 (neural) vs regex — live run, fresh judge")
print("=" * len(hdr))
print(hdr)

for arm, rs in rows.items():
    vals = defaultdict(list)
    for r in rs:
        fm = _fast_metrics(r.get("response"), r.get("ground_truth"))
        for m in METRICS:
            vals[m].append(fm[m])
    j = judge_scores(arm)
    js = [j[(str(r["session_id"]), r["position_in_session"])] for r in rs
          if (str(r["session_id"]), r["position_in_session"]) in j]
    cost = sum(float(r["cost"]) for r in rs
               if r.get("cost") not in (None, "None", ""))
    mix = defaultdict(int)
    for r in rs:
        mix[r.get("routed_to", "unknown")] += 1
    line = f"  {arm:<14}" + (f"{sum(js)/len(js):>7.3f}" if js else f"{'-':>7}")
    line += "".join(f"{sum(vals[m])/len(vals[m]):>9.3f}" for m in METRICS)
    line += f"{cost:>10.4f}{mix['cloud']:>7}{mix['on_device']:>8}{mix['cowrie']:>8}"
    print(line)

print()
print(f"  commands per arm: {len(next(iter(rows.values()))) if rows else 0}")
print(f"  results: {R}")
PY

echo
echo "done -> $LOG"
