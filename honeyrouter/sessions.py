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
"""
import json
import os
import random

BASE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "experiment_data", "PartC", "results", "fidelity_full109_final")

AGENTS = ("cowrie", "on_device", "cloud")


def load_sessions(base_dir: str = BASE_DIR) -> dict:
    """-> {session_id: [ {cmd, fi_score, agents: {agent: {latency_s, cost_usd}}}, ... ]}
    ordered by position_in_session within each session."""
    arms = {}
    for agent in AGENTS:
        with open(os.path.join(base_dir, f"{agent}.jsonl"), encoding="utf-8") as f:
            arms[agent] = [json.loads(line) for line in f]

    sessions: dict[str, list[dict]] = {}
    n = len(arms["cowrie"])
    for i in range(n):
        c = arms["cowrie"][i]
        sid = c["session_id"]
        sessions.setdefault(sid, []).append({
            "position": c["position_in_session"],
            "cmd": c["cmd"],
            "fi_score": c["fi_score"],
            "agents": {
                agent: {
                    "latency_s": arms[agent][i]["inference_ms"] / 1000.0,
                    "cost_usd": arms[agent][i]["cost"] or 0.0,
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
