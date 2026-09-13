"""
honeyrouter/state.py — observation-building for the RL HoneyRouter.

fi_score + per-agent cost, latency, and LLM-as-judge fidelity score, all
real numbers from sessions.py's replay data. No SYSTEM_STATE features
(files/installed/services/cwd) -- removed, not used.

Bump OBS_SIZE (and extend build_observation) together whenever a new
feature is added — OBSERVATION_SPACE must always match what
build_observation actually returns.
"""
import numpy as np
from gymnasium import spaces

from honeyrouter.action import AGENTS

# fi_score + one cost value per agent + one latency value per agent
# + one LLM-as-judge fidelity value per agent
OBS_SIZE = 1 + len(AGENTS) + len(AGENTS) + len(AGENTS)

OBSERVATION_SPACE = spaces.Box(low=0.0, high=np.inf, shape=(OBS_SIZE,), dtype=np.float32)


def build_observation(fi_score: int, agent_costs: dict | None = None,
                       agent_latencies: dict | None = None,
                       agent_judge_scores: dict | None = None) -> np.ndarray:
    """fi_score (0-4) + this command's real cost ($), real latency (s), and
    real LLM-as-judge fidelity score (0-5) for EACH agent, shown upfront
    before the action is picked -- not just the picked agent's, since that
    isn't known yet at observation time.

    `agent_costs`: {agent_name: cost_usd} for all of AGENTS, current command.
    `agent_latencies`: {agent_name: latency_s} for all of AGENTS, current command.
    `agent_judge_scores`: {agent_name: judge_score} for all of AGENTS, current command.
    """
    if agent_costs is None:
        agent_costs = {a: 0.0 for a in AGENTS}
    if agent_latencies is None:
        agent_latencies = {a: 0.0 for a in AGENTS}
    if agent_judge_scores is None:
        agent_judge_scores = {a: 0.0 for a in AGENTS}
    return np.array(
        [fi_score]
        + [agent_costs[a] for a in AGENTS]
        + [agent_latencies[a] for a in AGENTS]
        + [agent_judge_scores[a] for a in AGENTS],
        dtype=np.float32,
    )
