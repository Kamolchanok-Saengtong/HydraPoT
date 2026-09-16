"""
guardrail/sanitizer.py — (3) Sanitizer.

Neutralizes chat-template / special control tokens in attacker-controlled text
BEFORE it is placed into an LLM prompt. This is the fix for the confirmed
bypass where a file containing `<|im_start|>system ... <|im_end|>` made the
responder treat attacker text as a new, trusted conversation turn.

Important honeypot boundary: sanitize the copy that goes INTO the prompt, never
the copy shown to or stored for the attacker. `cat file` must still display the
real bytes (including a literal `<|im_start|>` the attacker wrote), or the
honeypot becomes inconsistent. So callers sanitize at prompt-build time only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


# Known chat-template / special-token delimiters across common model families
# (ChatML / Qwen / Llama / GPT). Matched structurally, not by an exact allow
# list, so an unseen `<|whatever|>` is still neutralized.
_SPECIAL = re.compile(r"<\|[^|>\n]{0,64}\|>")
# Llama-3 style [INST] / <<SYS>> markers and OpenAI-ish role headers on their
# own line.
_ROLE_MARKERS = re.compile(
    r"(<<SYS>>|<</SYS>>|\[/?INST\]|\[/?SYS\])", re.IGNORECASE)


@dataclass
class Sanitized:
    text: str                       # safe to place in a prompt
    removed: list[str] = field(default_factory=list)
    modified: bool = False


class Sanitizer:
    """Strip control tokens so they cannot forge a role boundary.

    Replacement rather than deletion would still leave a suspicious residue in
    the prompt; deletion is cleaner and the removed tokens are returned so the
    logger can record exactly what an attacker tried to inject.
    """

    def sanitize(self, text: str) -> Sanitized:
        if not text:
            return Sanitized(text=text or "", removed=[], modified=False)
        removed: list[str] = []

        def _grab(m):
            removed.append(m.group(0))
            return ""

        out = _SPECIAL.sub(_grab, text)
        out = _ROLE_MARKERS.sub(_grab, out)
        return Sanitized(text=out, removed=removed, modified=bool(removed))
