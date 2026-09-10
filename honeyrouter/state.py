"""
honeyrouter/state.py — observation-building for the RL HoneyRouter.

FI-based first, per agreement: not wired to a live main.py session yet —
training should replay through production-realistic data (like
prepare_dataset.py / NSC PartC already do), not hook a live honeypot
session. This takes a plain fi_score in; SYSTEM_STATE-derived fields are
stubbed below for later extension once that wiring actually happens.

Bump OBS_SIZE (and extend build_observation) together whenever a new
feature is added — OBSERVATION_SPACE must always match what
build_observation actually returns.
"""
import numpy as np
from gymnasium import spaces

OBS_SIZE = 1

OBSERVATION_SPACE = spaces.Box(low=0.0, high=np.inf, shape=(OBS_SIZE,), dtype=np.float32)


def build_observation(fi_score: int, system_state: dict | None = None) -> np.ndarray:
    """fi_score (0-4) is the only real signal for now.

    `system_state` accepted but unused — kept in the signature so callers
    (environment.py) don't need to change when SYSTEM_STATE-derived
    features (files/installed/services/cwd, see the earlier placeholder
    design) get wired in for real later.
    """
    return np.array([fi_score], dtype=np.float32)
