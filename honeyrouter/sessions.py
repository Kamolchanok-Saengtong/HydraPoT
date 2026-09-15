"""
honeyrouter/sessions.py — loads real episodes for the RL HoneyRouter to
train on, from the Part C execution records.

THE THREE ARMS DO NOT ALL LIVE IN ONE DIRECTORY. cowrie and on_device come
from fidelity_full109_final; cloud comes from fidelity_cloud_new_20260728_131019,
a later re-run. fidelity_full109_final also contains a cloud.jsonl, and it is
the WRONG one: the judge scored the re-run, not that copy.

Verified by matching responses (session_id, position_in_session) against each
judge file:

    cowrie      full109_final/cowrie.jsonl          judge match 100%
    on_device   full109_final/on_device.jsonl       judge match 100%
    cloud       cloud_new_.../cloud.jsonl           judge match 100%
    cloud       full109_final/cloud.jsonl           judge match  64%   <- wrong file

That last line is why the paths are explicit here rather than derived from one
base directory. Pairing one execution's latency and cost with a DIFFERENT
execution's fidelity score produces a row that never happened -- and the two
cloud runs differ materially (11346s/$0.655 vs 9934s/$0.778), so the mistake
is not cosmetic.

Verified lockstep across all three files: same 2179 rows, same session_ids,
same (session_id, position_in_session, cmd) order in every file -- so per
command, we get the REAL measured latency/cost for all 3 agents at once
(the same command really was run through all three arms), not just one
flat per-agent average. trial is always 0, ok is always True in this data
-- no dedup/failure-filtering needed.

Each command also carries a real LLM-as-judge fidelity score per agent
(1-5, how convincing that agent's response was vs `ground_truth`), from
the judge_scored_*.jsonl files in the same results dir -- joined by
(session_id, position_in_session), NOT raw row order (those files are
sorted differently per agent, verified). A handful of rows have a null
judge_score (judge call failed/skipped) -- default to 0.0, below the real
1-5 range, so missing data never looks like a good score.
"""
import json
import os
import random

_RESULTS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "experiment_data", "PartC", "results")

# Kept for callers that want the judge/honeyrouter files, which all live here.
BASE_DIR = os.path.join(_RESULTS, "fidelity_full109_final")

AGENTS = ("cowrie", "on_device", "cloud")

# Execution record per arm. Explicit paths, NOT f"{agent}.jsonl" under one
# directory -- see the module docstring for why the cloud arm is elsewhere.
ARM_FILES = {
    "cowrie": os.path.join(BASE_DIR, "cowrie.jsonl"),
    "on_device": os.path.join(BASE_DIR, "on_device.jsonl"),
    "cloud": os.path.join(_RESULTS, "fidelity_cloud_new_20260728_131019",
                          "cloud.jsonl"),
}

# THE RULE-BASED ROUTER WAS ALSO RECORDED, TWICE, AND THE TWO RUNS ARE NOT THE
# SAME ROUTER:
#
#   full109_final/honeyrouter.jsonl       2026-07-14  cow 79.2  on 17.7  clo  3.1
#   honeyrouter_replay_latest/hr.jsonl    2026-07-28  cow 68.8  on  7.0  clo 24.1
#
# The 07-28 run is the baseline, because it is the one that PAIRS WITH THE
# CLOUD ARM ABOVE -- same day, and its cloud rows are lookups of that exact
# file: cloud token totals match to the token (3,198,344). Using the 07-14
# decisions against the 07-28 cloud arm is the same file-pairing mistake the
# docstring above warns about, one layer up.
ROUTER_FILE = os.path.join(_RESULTS, "honeyrouter_replay_latest",
                           "honeyrouter.jsonl")

# ...but the 07-28 run is a lookup replay and records NO timing at all
# (inference_ms is 0 on every one of its 2179 rows), so the only measured
# end-to-end latency for a rule-based router comes from the 07-14 run. It is
# reported as what it is -- a different run, with a different routing mix --
# and never summed into the 07-28 row.
ROUTER_MEASURED_FILE = os.path.join(BASE_DIR, "honeyrouter.jsonl")

# One judge run per agent (different judge model per arm -- whatever was
# actually used to score that arm's real responses, see results dir).
JUDGE_FILES = {
    "cowrie": "judge_scored_cowrie_z-ai_glm-5.jsonl",
    "on_device": "judge_scored_on_device_deepseek-v4-flash.jsonl",
    "cloud": "judge_scored_cloud_deepseek-v4-flash.jsonl",
}


def _load_judge_scores(base_dir: str) -> dict:
    """-> {agent: {(session_id, position_in_session): judge_score}}"""
    judge_maps = {}
    for agent, fname in JUDGE_FILES.items():
        with open(os.path.join(base_dir, fname), encoding="utf-8") as f:
            rows = [json.loads(line) for line in f]
        judge_maps[agent] = {
            (r["session_id"], r["position_in_session"]): r["judge_score"]
            for r in rows
        }
    return judge_maps


def load_sessions(base_dir: str = BASE_DIR) -> dict:
    """-> {session_id: [ {cmd, fi_score, agents: {...}}, ... ]}
    ordered by position_in_session within each session."""
    arms = {}
    for agent in AGENTS:
        with open(ARM_FILES[agent], encoding="utf-8") as f:
            arms[agent] = [json.loads(line) for line in f]
    judge_maps = _load_judge_scores(base_dir)

    sessions: dict[str, list[dict]] = {}
    n = len(arms["cowrie"])
    for i in range(n):
        c = arms["cowrie"][i]
        sid = c["session_id"]
        pos = c["position_in_session"]
        sessions.setdefault(sid, []).append({
            "position": pos,
            "cmd": c["cmd"],
            "fi_score": c["fi_score"],
            "agents": {
                agent: {
                    "latency_s": arms[agent][i]["inference_ms"] / 1000.0,
                    "cost_usd": arms[agent][i]["cost"] or 0.0,
                    "judge_score": judge_maps[agent].get((sid, pos)) or 0.0,
                    # Cowrie is not a model and records no tokens -- 0, not
                    # missing. on_device burns real tokens but is never billed;
                    # only cloud tokens cost money, which is why the two are
                    # reported separately downstream.
                    "prompt_tokens": arms[agent][i].get("prompt_tokens") or 0,
                    "completion_tokens": arms[agent][i].get("completion_tokens") or 0,
                    "total_tokens": arms[agent][i].get("total_tokens") or 0,
                }
                for agent in AGENTS
            },
        })

    # Sort by position_in_session explicitly rather than trusting file order.
    for sid in sessions:
        sessions[sid].sort(key=lambda c: c["position"])
    return sessions


def random_session(sessions: dict) -> list[dict]:
    """Returns one session's command list (already position-ordered)."""
    return random.choice(list(sessions.values()))
