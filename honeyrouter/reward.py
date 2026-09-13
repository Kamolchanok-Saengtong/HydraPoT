"""
honeyrouter/reward.py — reward calc for the RL HoneyRouter.

All weights/values below are MOCK placeholders -- not measured, not tuned.
Just enough to run end to end; real numbers TBD.
"""
W_FI = 0.15
W_COST = 0.50
W_LATENCY = 0.10
W_JUDGE = 0.25


def compute_reward(fi_score: float, cost: float, latency: float, judge_score: float) -> float:
    """reward = w_fi * fi_score  +  w_judge * judge_score
              -  w_cost * cost  -  w_latency * latency

    fi_score:    0-4, command complexity/impact
    cost:        $ or proxy unit, higher = worse (penalized)
    latency:     seconds, higher = worse (penalized)
    judge_score: 0-5, LLM-as-judge fidelity of the picked agent's actual
                 response -- higher = more convincing = rewarded
    """
    return (W_FI * fi_score) + (W_JUDGE * judge_score) - (W_COST * cost) - (W_LATENCY * latency)
