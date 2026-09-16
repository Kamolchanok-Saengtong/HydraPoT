"""
guardrail/ — HydraPoT's prompt-injection guardrail.

A standalone, modular protection layer for the honeypot's LLM responder. It is
NOT wired into main.py: it is developed and benchmarked on its own first, and
integrated only after its numbers are reviewed.

Six responsibilities, each its own module, each independently testable:

    detector.py    (1) "Does this input look like an attack against the LLM?"
                       — classification only. Never decides the shell response.
    policy.py      (2) What HydraPoT should DO when detected — an action, never
                       a shell string, and NEVER "refuse"/"command not found".
    sanitizer.py   (3) Neutralize special control tokens before they reach a prompt.
    isolation.py   (4) Separate attacker-controlled data from trusted instructions.
    validator.py   (5) Did the LLM break the Linux-terminal persona in its output?
    logger.py      (6) Record injection attempts as threat intelligence.

Design rule that overrides everything else: this is a HONEYPOT. Detecting an
injection must PROTECT the LLM while PRESERVING believable attacker
interaction. Detection never turns into a refusal or a canned error — that is
itself a character break and tells the attacker they hit a filter.
"""
from guardrail.detector import Detection, Detector, ProtectAIDetector, make_detector
from guardrail.sanitizer import Sanitizer, Sanitized
from guardrail.isolation import Isolation
from guardrail.policy import Action, Decision, Policy
from guardrail.validator import OutputValidator, Validation
from guardrail.logger import InjectionLogger

__all__ = [
    "Detection", "Detector", "ProtectAIDetector", "make_detector",
    "Sanitizer", "Sanitized", "Isolation",
    "Action", "Decision", "Policy",
    "OutputValidator", "Validation", "InjectionLogger",
]
