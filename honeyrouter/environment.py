"""
honeyrouter/environment.py — Gymnasium environment for the RL-based HoneyRouter.

Isolated experiment. NOT wired into production main.py/router.py.

Action space:   see action.py -- Discrete(3) -> {cowrie, on_device, cloud}.
Observation:    see state.py -- fi_score + this command's real cost,
                latency, AND LLM-as-judge fidelity score for ALL 3 agents
                shown upfront (the agent sees the full menu before picking,
                not just the picked agent's).
Reward logic:   honeyrouter/reward.py -- wired into step() below. FI, cost,
                latency, and judge_score are all real per-command, per-agent
                numbers (see sessions.py) -- verified lockstep across the
                fidelity_full109_final execution-record and judge_scored_*
                files, so every step has the real measured numbers for
                whichever agent gets picked, not a flat average.
Session data:   honeyrouter/sessions.py -- real episodes replayed one
                command at a time.
This file only wires the pieces together into a gymnasium.Env.
"""
import gymnasium as gym

from honeyrouter.state import OBSERVATION_SPACE, build_observation
from honeyrouter.action import ACTION_SPACE, AGENTS, agent_for
from honeyrouter.reward import compute_reward
from honeyrouter.sessions import load_sessions, random_session


def _agent_costs(command: dict) -> dict:
    """This command's real cost ($) for every agent -- what the observation
    shows before an action is picked."""
    return {a: command["agents"][a]["cost_usd"] for a in AGENTS}


def _agent_latencies(command: dict) -> dict:
    """This command's real latency (s) for every agent -- shown before an
    action is picked, same reason as cost."""
    return {a: command["agents"][a]["latency_s"] for a in AGENTS}


def _agent_judge_scores(command: dict) -> dict:
    """This command's real LLM-as-judge fidelity score (0-5) for every
    agent -- shown before an action is picked, same reason as cost/latency."""
    return {a: command["agents"][a]["judge_score"] for a in AGENTS}


def _build_obs(env: "HoneyRouterEnv", command: dict):
    return build_observation(
        fi_score=env._fi_score,
        agent_costs=_agent_costs(command),
        agent_latencies=_agent_latencies(command),
        agent_judge_scores=_agent_judge_scores(command),
    )


class HoneyRouterEnv(gym.Env):
    metadata = {"render_modes": []}

    def __init__(self):
        super().__init__()
        self.action_space = ACTION_SPACE
        self.observation_space = OBSERVATION_SPACE
        self._sessions = load_sessions()
        self._commands: list[dict] = []
        self._idx = 0
        self._fi_score = 0

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._commands = random_session(self._sessions)
        self._idx = 0
        current = self._commands[self._idx]
        self._fi_score = current["fi_score"]
        obs = _build_obs(self, current)
        info = {"fi_score": self._fi_score}
        return obs, info

    def step(self, action):
        agent = agent_for(action)
        current = self._commands[self._idx]
        agent_data = current["agents"][agent]
        reward = compute_reward(
            fi_score=self._fi_score,
            cost=agent_data["cost_usd"],
            latency=agent_data["latency_s"],
            judge_score=agent_data["judge_score"],
        )
        info = {"agent": agent, "fi_score": self._fi_score,
                "cost": agent_data["cost_usd"], "latency": agent_data["latency_s"],
                "judge_score": agent_data["judge_score"]}

        self._idx += 1
        terminated = self._idx >= len(self._commands)
        if terminated:
            # Episode over -- next reset() starts a fresh session. Observation
            # value here doesn't matter (gymnasium convention: ignored once
            # terminated=True), reuse the current (last) command's values
            # rather than index out of range.
            obs = _build_obs(self, current)
        else:
            next_cmd = self._commands[self._idx]
            self._fi_score = next_cmd["fi_score"]
            obs = _build_obs(self, next_cmd)

        return obs, reward, terminated, False, info
