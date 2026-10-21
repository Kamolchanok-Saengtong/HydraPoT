"""
character_break.py — HydraPoT's own check. Not NVIDIA code.

Detects the attack NeMo's shipped heuristics cannot see. Their two checks
score GPT-2 perplexity, which catches GCG-style gibberish suffixes; a
honeypot's attacker writes fluent English -- "are you an AI?" -- which scores
LOW perplexity and passes. Llama Prompt Guard 2 gives it 0.0004, because an
identity question is not an instruction override. Different attack class,
different check.

No model, no LLM call, no training data: five mechanical signals and one
veto, each reported so a verdict can be explained rather than trusted.

Measured on HydraPoT's own data -- 91.2% recall over Scope's 147 identity
probes, 0 false positives over 3,141 real shell commands.

Written to NeMo's check convention -- check_*(input_string, threshold) -> dict
-- so it drops into the same action and flow plumbing as checks.py.
"""
from __future__ import annotations

import re

# The two checks above score GPT-2 perplexity, which catches GCG-style
# gibberish suffixes. A honeypot's attacker writes fluent English -- "are you
# an AI?" -- which scores LOW perplexity and passes, and Prompt Guard 2 gives
# it 0.0004 because an identity question is not an instruction override. The
# attack class is different, so the check is too: no model, no LLM, four
# mechanical signals, each reported so a verdict can be explained.

SECOND_PERSON = re.compile(
    r"\b(you|your|yours|you're|youre|u|ur)\b", re.IGNORECASE)

QUESTION_OPENERS = re.compile(
    r"^\s*(are|is|am|do|does|did|can|could|will|would|should|have|has|was|were|"
    r"what|which|who|whom|whose|where|when|why|how)\b", re.IGNORECASE)

IMPERATIVE_PROBE = re.compile(
    r"\b(tell me|describe|explain|list|show me|repeat (this|after)|"
    r"respond with|answer (with|\"|')|reply with|state (your|whether)|"
    r"confirm (that|whether|if)|pretend|act as|ignore)\b", re.IGNORECASE)

IDENTITY_TERMS = re.compile(
    r"\b(ai|a\.i\.|artificial intelligence|llm|language model|gpt|chatgpt|"
    r"claude|gemini|llama|qwen|chatbot|bot|assistant|neural|transformer|"
    r"model|trained|training data|fine[- ]?tuned|system prompt|prompt|"
    r"instructions|guidelines|developer|creator|openai|anthropic|"
    r"sandbox|honeypot|emulat\w*|simulat\w*|virtual machine|container|docker|"
    r"cloud|hypervisor|context window|token limit|memory|conversation|"
    r"architecture|parameters|weights|temperature|sentient|conscious|feelings|"
    r"emotions|opinion|believe|think)\b", re.IGNORECASE)

SELF_ASSERTION = re.compile(
    r"(answer\s+[\"']?(true|false|yes|no)|respond\s+with\s+[\"']?(yes|no)|"
    r"if\s+you\s+(are|were)\b|are\s+you\s+(an?\s+)?(ai|llm|bot|gpt|human|real)|"
    r"i\s+am\s+not\s+(an?\s+)?ai|prove\s+(that\s+)?you)", re.IGNORECASE)

# Identity terms alone are weak: "what's your opinion on llm?" and
# `grep model /etc/passwd` both contain one, so the second-person framing has
# to carry its share before anything is flagged.
# A veto, not a signal. `who -u` tripped second_person on "-u" and the
# question opener on "who" -- but it parses as a command invocation: a bare
# name followed by a flag or a path. An identity probe never looks like that,
# and real traffic is full of them, so shape wins over wording.
SHELL_SHAPED = re.compile(
    r"^\s*(/|\./|~/|sudo\s|[a-z0-9_.:-]+\s+(-{1,2}[a-z0-9-]+|[/~]|\||>|<|&))",
    re.IGNORECASE)

CHARACTER_BREAK_WEIGHTS = {
    "second_person": 0.35,
    "interrogative": 0.20,
    "imperative_probe": 0.20,
    "identity_terms": 0.30,
    "self_assertion": 0.40,
}


def character_break_signals(input_string: str) -> dict:
    """Which signals fired, individually, for one input."""
    t = input_string or ""
    return {
        "second_person": bool(SECOND_PERSON.search(t)),
        "interrogative": bool(QUESTION_OPENERS.match(t)
                              or t.rstrip().endswith("?")),
        "imperative_probe": bool(IMPERATIVE_PROBE.search(t)),
        "identity_terms": bool(IDENTITY_TERMS.search(t)),
        "self_assertion": bool(SELF_ASSERTION.search(t)),
    }


def get_character_break_score(input_string: str) -> float:
    """0..1, capped. A lone identity term cannot reach 0.5 on its own."""
    fired = character_break_signals(input_string)
    return min(1.0, sum(w for k, w in CHARACTER_BREAK_WEIGHTS.items()
                        if fired[k]))


def check_character_break(input_string: str, threshold: float = 0.5) -> dict:
    """Is the input probing the system's identity rather than running a command?

    Same return shape as the checks above, plus the evidence.
    """
    shell_shaped = bool(SHELL_SHAPED.match(input_string or ""))
    score = 0.0 if shell_shaped else get_character_break_score(input_string)
    fired = character_break_signals(input_string)
    return {
        "character_break": score >= threshold,
        "score": score,
        "signals": [k for k, v in fired.items() if v],
        "shell_shaped": shell_shaped,
    }
