"""
guardrail/validator.py — (5) Output Validator.

Checks whether the LLM's OUTPUT broke the Linux-terminal persona: chatbot
voice, first-person refusal, self-identification as an AI/model, or meta-talk
about instructions. It REPORTS only — it does not rewrite the output. What to
do about a break (scrub, replace with plausible terminal noise, re-roll) is the
caller's decision at integration time, keeping this component pure.

This is the last line of defense: it catches breaks that slipped past the
input-side guards (detector/sanitizer/isolation), including the confirmed
base64 case where the responder answered "I don't know who you are, but I can
help with that." — correct output for a terminal is never conversational.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# First-person / assistant / refusal / self-ID patterns a real shell never emits.
_BREAK = re.compile(
    r"\b("
    r"as an ai|i am an ai|i'?m an ai|language model|i am a language model|"
    r"i cannot|i can'?t (help|assist|do that)|i'?m sorry|i am unable|"
    r"cannot assist|can'?t help|cannot help|i'?m not able|"
    r"my (instructions|system prompt|guidelines|training)|"
    r"i'?m (an assistant|a helpful|a chatbot)|as a (helpful|responsible|language)|"
    r"underlying model|i don'?t know who you are|how can i help|"
    r"i'?m here to help|chatgpt|qwen|as a large language"
    r")\b",
    re.IGNORECASE,
)


@dataclass
class Validation:
    broke_persona: bool
    reasons: list[str] = field(default_factory=list)


class OutputValidator:
    def validate(self, llm_output: str) -> Validation:
        if not llm_output:
            return Validation(broke_persona=False, reasons=[])
        hits = sorted({m.group(0).lower() for m in _BREAK.finditer(llm_output)})
        return Validation(broke_persona=bool(hits), reasons=hits)
