"""
guardrail/detector_arm/prompt_guard2.py — Meta Llama Prompt Guard 2 arm.

meta-llama/Llama-Prompt-Guard-2-86M. Detects injection AND jailbreak, and its
base is multilingual (Thai included). Gated on HuggingFace, and its
config.json ships no id2label -- the arm measures which class means attack
rather than assuming a name or an index.
"""
from guardrail.detector_arm.hf_classifier import HFClassifierArm

NAME = "prompt_guard2"
DEFAULT_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"
ALIASES = ("prompt_guard2", "promptguard2", "llama", "llama_prompt_guard")


def build(cfg: dict):
    cfg = cfg or {}
    return HFClassifierArm(model=cfg.get("model") or DEFAULT_MODEL,
                           device=cfg.get("device", "cpu"),
                           threshold=float(cfg.get("threshold", 0.5)))
