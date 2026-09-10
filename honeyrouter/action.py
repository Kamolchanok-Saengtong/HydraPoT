"""
honeyrouter/action.py — action space for the RL HoneyRouter.

Mirrors state.py's role but for actions: environment.py only knows the
shape/size, not what an action means -- that lives here.
"""
from gymnasium import spaces

AGENTS = ("cowrie", "on_device", "cloud")

ACTION_SPACE = spaces.Discrete(len(AGENTS))


def agent_for(action: int) -> str:
    """Discrete action index -> agent name."""
    return AGENTS[action]
