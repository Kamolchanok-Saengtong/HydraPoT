"""
honeyrouter/sessions.py — loads real episodes for the RL HoneyRouter to
train on, from the fidelity_full109_final Part C execution records
(cowrie.jsonl / on_device.jsonl / cloud.jsonl).

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

BASE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "experiment_data", "PartC", "results", "fidelity_full109_final")

AGENTS = ("cowrie", "on_device", "cloud")

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
        with open(os.path.join(base_dir, f"{agent}.jsonl"), encoding="utf-8") as f:
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
