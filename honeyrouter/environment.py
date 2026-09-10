"""
honeyrouter/environment.py — Gymnasium environment for the RL-based HoneyRouter.

Isolated experiment. NOT wired into production main.py/router.py.

Action space:   see action.py -- Discrete(3) -> {cowrie, on_device, cloud}.
Observation:    see state.py -- FI-based first, SYSTEM_STATE fields stubbed
                for later, not wired to a live main.py session yet.
Reward logic:   honeyrouter/reward.py -- wired into step() below. FI, cost,
                and latency are all real per-command, per-agent numbers now
                (see sessions.py) -- verified lockstep across the three
                fidelity_full109_final execution-record files, so every
                step has the real measured cost/latency for whichever
                agent gets picked, not a flat average.
Session data:   honeyrouter/sessions.py -- real episodes replayed one
                command at a time.
This file only wires the pieces together into a gymnasium.Env.
"""
import gymnasium as gym

from honeyrouter.state import OBSERVATION_SPACE, build_observation
from honeyrouter.action import ACTION_SPACE, agent_for
from honeyrouter.reward import compute_reward
from honeyrouter.sessions import load_sessions, random_session


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
        self._fi_score = self._commands[self._idx]["fi_score"]
        obs = build_observation(fi_score=self._fi_score)
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
        )
        info = {"agent": agent, "fi_score": self._fi_score,
                "cost": agent_data["cost_usd"], "latency": agent_data["latency_s"]}

        self._idx += 1
        terminated = self._idx >= len(self._commands)
        if terminated:
            # Episode over -- next reset() starts a fresh session. Observation
            # value here doesn't matter (gymnasium convention: ignored once
            # terminated=True), reuse the last one rather than index out of range.
            obs = build_observation(fi_score=self._fi_score)
        else:
            self._fi_score = self._commands[self._idx]["fi_score"]
            obs = build_observation(fi_score=self._fi_score)

        return obs, reward, terminated, False, info
