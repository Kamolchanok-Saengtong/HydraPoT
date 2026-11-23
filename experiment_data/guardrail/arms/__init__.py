"""
experiment_data/guardrail/arms/ -- the guardrails compared against NeMo.

Experiment only. HydraPoT ships NeMo alone (guardrail/detector_arm/nemo.py); these
are the others it was measured against. Adding one means adding a module here with
NAME, ALIASES and build(cfg).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from arms import llama_guard3, prompt_guard2, protectai        # noqa: E402
from guardrail.detector_arm import nemo                         # noqa: E402  (the shipped one)

ARMS = (protectai, prompt_guard2, llama_guard3, nemo)


def names():
    return [a.NAME for a in ARMS]


def build(provider: str, cfg: dict):
    """The arm whose NAME or ALIASES matches `provider`."""
    want = (provider or "").strip().lower()
    for arm in ARMS:
        if want == arm.NAME or want in arm.ALIASES:
            return arm.build(cfg)
    raise ValueError(f"unknown guardrail arm: {provider!r}; choose from {names()}")
