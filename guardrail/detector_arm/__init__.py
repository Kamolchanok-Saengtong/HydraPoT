"""
guardrail/detector_arm/ — one module per guardrail under comparison.

Adding a guardrail means adding a module here with NAME, ALIASES and
build(cfg); nothing in detector.py or session.py changes. `provider` in
config.yaml selects the arm, so an experiment switches guardrail by editing
one line of config rather than any code.
"""
from guardrail.detector_arm import llama_guard3, nemo, prompt_guard2, protectai

ARMS = (protectai, prompt_guard2, llama_guard3, nemo)


def names():
    return [a.NAME for a in ARMS]


def build(provider: str, cfg: dict):
    """The arm whose NAME or ALIASES matches `provider`."""
    want = (provider or "").strip().lower()
    for arm in ARMS:
        if want == arm.NAME or want in arm.ALIASES:
            return arm.build(cfg)
    raise ValueError(f"unknown guardrail arm: {provider!r}; "
                     f"choose from {names()}")
