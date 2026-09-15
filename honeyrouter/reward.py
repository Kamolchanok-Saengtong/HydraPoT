
# Scale references, from the Part C distribution (p99 across all three arms).
FI_MAX = 4.0            # FI is a 0-4 band by definition
JUDGE_MAX = 5.0         # LLM-as-judge is 1-5; 0 means "no score"
COST_REF = 0.00083      # $/command, p99
LATENCY_REF = 17.42     # seconds, p99

# Weights now express real priorities, because the terms they multiply are
# comparable. They do not have to sum to 1 -- what matters is their ratio.
W_FI = 0.05
W_COST = 0.45
W_LATENCY = 0.45
W_JUDGE = 0.05


def compute_reward(fi_score: float, cost: float, latency: float,
                   judge_score: float) -> float:
    """reward = w_fi*fi' + w_judge*judge' - w_cost*cost' - w_latency*latency'

    where x' is x divided by its reference (see module docstring).

    fi_score:    0-4, command complexity/impact
    cost:        $ actually charged for the picked agent's response
    latency:     seconds the picked agent actually took
    judge_score: 0-5, LLM-as-judge fidelity of the picked agent's real
                 response -- higher = more convincing = rewarded

    All four are REAL measurements of the arm the agent chose, not estimates.
    """
    fi = fi_score / FI_MAX
    judge = judge_score / JUDGE_MAX
    cost_n = cost / COST_REF
    latency_n = latency / LATENCY_REF

    return (W_FI * fi) + (W_JUDGE * judge) - (W_COST * cost_n) - (W_LATENCY * latency_n)
