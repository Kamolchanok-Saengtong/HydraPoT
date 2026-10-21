"""
guardrail/detector_arm/protectai.py — ProtectAI DeBERTa arm.

protectai/deberta-v3-base-prompt-injection-v2. English-only, and its model
card states it does not detect jailbreak attacks; the project is archived.
Kept as the baseline arm because the earlier results were measured with it.
"""
from guardrail.detector_arm.hf_classifier import HFClassifierArm

NAME = "protectai"
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
ALIASES = ("protectai", "deberta", "hf", "transformers")


def build(cfg: dict):
    cfg = cfg or {}
    return HFClassifierArm(model=cfg.get("model") or DEFAULT_MODEL,
                           device=cfg.get("device", "cpu"),
                           threshold=float(cfg.get("threshold", 0.5)))
