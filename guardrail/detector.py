"""
guardrail/detector.py — (1) Detector.

Answers ONE question and nothing else:

    "Does this input look like an attack against the LLM?"

It does not decide the shell response, it does not sanitize, it does not log.
Classification only. Keeping it this narrow is what lets it be swapped
(ProtectAI now, Prompt Guard 2 later) without touching any other component.
"""
from __future__ import annotations

import time
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
    """Any detector HydraPoT can use. Swap providers behind this."""
    def classify(self, text: str) -> Detection: ...


class ProtectAIDetector:
    """DeBERTa injection classifier, e.g.
    protectai/deberta-v3-base-prompt-injection-v2.

    Runs on CPU by default so it never competes with the responder model for
    the GPU. The model is loaded lazily (first classify), so importing this
    module is cheap and unit tests that don't classify pay nothing.

    `threshold` is applied to P(injection), not to the model's own top-label
    score, so raising/lowering it behaves intuitively and a threshold sweep is
    meaningful. Both class scores are read (top_k=None) to get a true
    P(injection) even when the model's top prediction is SAFE.
    """

    def __init__(self, model: str = "protectai/deberta-v3-base-prompt-injection-v2",
                 device: str = "cpu", threshold: float = 0.5):
        self.model = model
        self.device = device
        self.threshold = threshold
        self._pipe = None

    def _ensure_loaded(self):
        if self._pipe is not None:
            return
        from transformers import pipeline           # imported lazily on purpose
        dev = -1 if str(self.device).lower() == "cpu" else 0
        self._pipe = pipeline("text-classification", model=self.model,
                              device=dev, top_k=None, truncation=True, max_length=512)

    def _p_injection(self, text: str) -> float:
        scores = self._pipe(text)[0]               # list of {label, score}
        for s in scores:
            if s["label"].upper() in ("INJECTION", "LABEL_1", "JAILBREAK"):
                return float(s["score"])
        # fall back: 1 - P(safe) if the injection label was named unexpectedly
        for s in scores:
            if s["label"].upper() in ("SAFE", "LABEL_0", "BENIGN"):
                return 1.0 - float(s["score"])
        return 0.0

    def classify(self, text: str) -> Detection:
        self._ensure_loaded()
        t0 = time.time()
        p = self._p_injection(text or "")
        dt = (time.time() - t0) * 1000.0
        is_attack = p >= self.threshold
        return Detection(is_attack=is_attack, score=p,
                         label="INJECTION" if is_attack else "SAFE",
                         model=self.model, latency_ms=dt)


def make_detector(cfg: dict) -> Detector:
    """Build a detector from a config dict (guardrail.detector section).

    Provider-dispatched so config.yaml can name a different model or, later, a
    different provider without any code change here.
    """
    provider = (cfg or {}).get("provider", "protectai").lower()
    if provider in ("protectai", "promptguard", "hf", "transformers"):
        return ProtectAIDetector(
            model=(cfg or {}).get("model", "protectai/deberta-v3-base-prompt-injection-v2"),
            device=(cfg or {}).get("device", "cpu"),
            threshold=float((cfg or {}).get("threshold", 0.5)),
        )
    raise ValueError(f"unknown detector provider: {provider!r}")
