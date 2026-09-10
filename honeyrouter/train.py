"""
honeyrouter/train.py — trains the DQN HoneyRouter on partC_stateful_sessions.json.

Reward's cost/latency are still mock per-agent constants (see environment.py),
weights still mock too (see reward.py). This trains against those
placeholders -- re-run once real values are wired in, don't treat this run's
policy as final.
"""
import os

from stable_baselines3 import DQN
from stable_baselines3.common.monitor import Monitor

from honeyrouter.environment import HoneyRouterEnv

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
MODEL_PATH = os.path.join(OUT_DIR, "dqn_honeyrouter")


def main(total_timesteps: int = 10_000):
    env = Monitor(HoneyRouterEnv())
    model = DQN("MlpPolicy", env, verbose=1)
    model.learn(total_timesteps=total_timesteps)

    os.makedirs(OUT_DIR, exist_ok=True)
    model.save(MODEL_PATH)
    print(f"[train] saved -> {MODEL_PATH}.zip")


if __name__ == "__main__":
    main()
