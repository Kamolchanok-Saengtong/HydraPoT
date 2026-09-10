"""
honeyrouter/reward.py — reward calc for the RL HoneyRouter.

All weights/values below are MOCK placeholders -- not measured, not tuned.
Just enough to run end to end; real numbers TBD.
"""

W_FI = 1.0        # reward per FI point (0-4) -- direction/magnitude unconfirmed
W_COST = 1.0      # subtracted per unit cost ($, cloud calls)
W_LATENCY = 1.0   # subtracted per unit latency (seconds)


def compute_reward(fi_score: float, cost: float, latency: float) -> float:
    """reward = w_fi * fi_score  -  w_cost * cost  -  w_latency * latency

    fi_score: 0-4, command complexity/impact
    cost:     $ or proxy unit, higher = worse (penalized)
    latency:  seconds, higher = worse (penalized)
    """
    return (W_FI * fi_score) - (W_COST * cost) - (W_LATENCY * latency)
