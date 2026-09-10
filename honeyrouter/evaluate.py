"""
honeyrouter/evaluate.py — run a trained DQN HoneyRouter over real sessions,
deterministic (no exploration), and report what it actually does.

Reward's cost/latency are still mock (see environment.py) -- numbers here
reflect that, not real-world cost/latency yet.
"""
import argparse
import os
from collections import Counter

from honeyrouter.environment import HoneyRouterEnv
from honeyrouter.action import AGENTS
from stable_baselines3 import DQN

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "dqn_honeyrouter")


def evaluate(model_path: str = MODEL_PATH, n_episodes: int = 20):
    env = HoneyRouterEnv()
    model = DQN.load(model_path, env=env)

    episode_rewards = []
    action_counts = Counter()

    for _ in range(n_episodes):
        obs, _ = env.reset()
        terminated = False
        ep_reward = 0.0
        while not terminated:
            action, _ = model.predict(obs, deterministic=True)
            action = int(action)
            action_counts[AGENTS[action]] += 1
            obs, reward, terminated, _truncated, _info = env.step(action)
            ep_reward += reward
        episode_rewards.append(ep_reward)

    total_actions = sum(action_counts.values())
    print(f"[eval] {n_episodes} episodes, model={model_path}")
    print(f"[eval] mean episode reward: {sum(episode_rewards) / len(episode_rewards):.3f}")
    print(f"[eval] min/max episode reward: {min(episode_rewards):.3f} / {max(episode_rewards):.3f}")
    print(f"[eval] action distribution ({total_actions} commands):")
    for agent in AGENTS:
        n = action_counts[agent]
        pct = 100 * n / total_actions if total_actions else 0
        print(f"  {agent:<10} {n:>5}  ({pct:5.1f}%)")

    return episode_rewards, action_counts


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=MODEL_PATH)
    ap.add_argument("--episodes", type=int, default=20)
    args = ap.parse_args()
    evaluate(args.model, args.episodes)
