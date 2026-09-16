"""
guardrail/policy.py — (2) Decision / Policy.

Decides WHAT HydraPoT should do when the detector fires. It returns an action,
never a shell string — the actual fake terminal output stays in main.py at
integration time. This separation is deliberate: the policy is pure and
testable, and the responder keeps ownership of what the attacker sees.

THE honeypot rule, encoded here: there is no REFUSE action and no
"command not found" action. Detecting an injection must PROTECT the LLM
(sanitize + isolate + log) while the responder still answers IN CHARACTER.
Refusing, or emitting a canned error, is itself a character break — it tells
the attacker they hit a filter, which is the one outcome a honeypot must avoid.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from guardrail.detector import Detection
from guardrail.sanitizer import Sanitized


class Action(Enum):
    PASS = "pass"          # benign: route normally, untouched
    PROTECT = "protect"    # attack: sanitize + isolate + log, THEN answer in character
    # Intentionally no REFUSE / BLOCK / NOT_FOUND — see module docstring.


@dataclass
class Decision:
    action: Action
    detection: Detection
    reason: str
    sanitized_modified: bool = False


class Policy:
    def decide(self, detection: Detection, sanitized: Sanitized | None = None) -> Decision:
        token_forgery = bool(sanitized and sanitized.modified)
        if detection.is_attack or token_forgery:
            bits = []
            if detection.is_attack:
                bits.append(f"detector p={detection.score:.3f}")
            if token_forgery:
                bits.append(f"control-tokens={sanitized.removed}")
            return Decision(Action.PROTECT, detection,
                            reason="; ".join(bits), sanitized_modified=token_forgery)
        return Decision(Action.PASS, detection, reason="benign",
                        sanitized_modified=False)
