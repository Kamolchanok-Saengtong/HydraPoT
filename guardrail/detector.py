"""
guardrail/detector.py -- the injection detector HydraPoT ships.

One detector, fixed: NVIDIA NeMo Guardrails (guardrail/detector_arm/nemo.py). Nothing
about it is configurable, so every install runs the same guardrail. The other
detectors that were compared against it, and the harness that compared them, live in
experiment_data/guardrail/.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class Detection:
    """Result of one classification. `score` is P(injection) in [0,1]."""
    is_attack: bool
    score: float
    label: str          # "INJECTION" | "SAFE"
    model: str
    latency_ms: float = 0.0


class Detector(Protocol):
    """What the rest of HydraPoT needs from a detector."""
    def classify(self, text: str) -> Detection: ...


def make_detector(cfg: dict = None) -> Detector:
    """The shipped detector. `cfg` is accepted for the callers that pass one; it cannot
    select a different detector."""
    from guardrail.detector_arm import nemo
    return nemo.build(cfg or {})
