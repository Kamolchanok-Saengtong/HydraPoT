"""
honeyrouter/reward.py — what the RL router is trained to maximise.

TWO TERMS ONLY: cost and fidelity.

    reward = W_JUDGE * judge' - W_COST * cost'

FI and latency were dropped deliberately, and for different reasons:

  FI      is HydraPoT's ROUTING metric, not a goal. It describes a command
          (how much interaction it implies), not how well the router did.
          Rewarding it taught the agent to prefer commands with a certain FI
          band, which is not a decision the router should be making.

  LATENCY correlates almost perfectly with cost here -- the cloud arm is both
          the slowest and the only one billed -- so the term added weight
          without adding information, and made the trade-off harder to read.
          A router that is cheap is already fast in this dataset.

What remains is the real trade-off: a convincing answer costs money.

NORMALISED, so the weights mean something. Raw cost is ~1e-4 dollars and the
judge score is 1-5, so multiplying both by weights that sum to 1 let the cost
term contribute 0.00006 against the judge's 0.9 -- a weight of 0.50 that was
15,000x too small to matter. Dividing each by its own p99 reference puts them
on the same scale first, and the weights then express real priorities.

They do not have to sum to 1. Only their RATIO matters.
"""

# Scale references, from the Part C distribution (p99 across all three arms).
JUDGE_MAX = 5.0         # LLM-as-judge is 1-5; 0 means "no score"
COST_REF = 0.00083      # $/command, p99

W_COST = 0.45
W_JUDGE = 0.05


def compute_reward(cost: float, judge_score: float, **_ignored) -> float:
    """reward = w_judge*judge' - w_cost*cost',  where x' is x over its reference.

    cost:         $ actually charged for the picked agent's response
    judge_score:  0-5, LLM-as-judge fidelity of that agent's REAL response --
                  higher = more convincing = rewarded

    Both are real measurements of the arm the agent chose, not estimates.

    **_ignored accepts fi_score and latency from older callers without using
    them, so a stale call site cannot silently pass a value that does nothing
    while looking like it does.
    """
    return (W_JUDGE * (judge_score / JUDGE_MAX)) - (W_COST * (cost / COST_REF))
