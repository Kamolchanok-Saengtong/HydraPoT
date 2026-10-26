"""
guardrail/detector_arm/nemo.py — NeMo Guardrails arm.

NeMo's OWN regex rail, configured NeMo's way. nemo_config/config.yml declares
the patterns under their documented rails.config.regex_detection schema, and
classify() executes THEIR detect_regex_pattern action
(nemoguardrails/library/regex/actions.py) through LLMRails' dispatcher. The
matching is entirely theirs; we supply patterns and read the verdict.

The flow named in config.yml is theirs too (`regex check input`), and it
never runs: classify() calls the action straight through the dispatcher,
while Colang flows only execute under rails.generate(), which drives NeMo's
own conversation. HydraPoT's agents generate the answer, so this arm uses
NeMo as a CLASSIFIER rather than as a conversational rail. Their subflow
would end in `bot refuse to respond` -- the one answer a honeypot must never
give -- so moving this onto rails.generate() means replacing that flow first.

NOT their perplexity checks. Those need gpt2-large and score GCG-style
gibberish; fluent English like "are you an AI?" scores low and passes.

The nine patterns replace a weighted five-signal scorer
(detector_arm/character_break.py) and are its exact equivalent at threshold
0.5 -- every minimal pair of signals that reached it, as lookahead
conjunctions, each vetoed by a negative lookahead for shell-shaped input.
Verified on all 247 guardrail/eval_datasets prompts plus real shell commands:
0 disagreements. See config.yml for the derivation.

character_break.py stays as the fallback for a machine without
nemoguardrails installed, so the arm still reports without it -- same
verdicts, different plumbing. `engine` says which ran, and a fallback is
printed, never silent: an arm that quietly stopped being NeMo would make the
comparison a lie.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

from guardrail.detector import Detection

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

CONFIG_PATH = os.path.join(_HERE, "nemo_config")
# NeMo's OWN regex action (nemoguardrails/library/regex/actions.py). The
# patterns live in nemo_config/config.yml under their documented
# rails.config.regex_detection schema, so the matching is entirely theirs.
ACTION = "detect_regex_pattern"

NAME = "nemo"
DEFAULT_MODEL = "nemo:character_break"
ALIASES = ("nemo", "nemoguardrails", "character_break", "nemo_character")


class NemoCharacterBreakArm:
    """A rail, not a model: no weights, no download, no GPU."""

    def __init__(self, model: str = "", device: str = "cpu",
                 threshold: float = 0.5):
        self.model = model or DEFAULT_MODEL
        self.device = device
        self.threshold = threshold
        # The model arms resolve their attack class by probing. This one's
        # classes are defined by the rule, so there is nothing to measure --
        # reported as "rule" rather than left looking unresolved.
        self.label_source = "rule"
        self.probe_scores = {}
        self.engine = None
        self._rails = None
        self._loop = None

    def _ensure_engine(self):
        if self.engine is not None:
            return
        try:
            from nemoguardrails import LLMRails, RailsConfig
            os.environ.setdefault("CHARACTER_BREAK_THRESHOLD",
                                  str(self.threshold))
            self._rails = LLMRails(RailsConfig.from_path(CONFIG_PATH))
            reg = self._rails.runtime.action_dispatcher.registered_actions
            if ACTION not in reg:
                raise RuntimeError(f"{ACTION} not registered by {CONFIG_PATH}")
            self._loop = asyncio.new_event_loop()
            self.engine = "nemoguardrails"
        except Exception as e:
            print(f"[nemo] engine unavailable ({type(e).__name__}: {e}); "
                  f"calling the check directly")
            self.engine = "direct"

    def _via_engine(self, text):
        """NeMo's detect_regex_pattern, through NeMo's dispatcher.

        `config` is passed explicitly: the dispatcher calls the action as
        fn(**params) and injects nothing, and this action takes the
        RailsConfig it reads the patterns from.

        It returns a RailOutcome, not a dict -- BLOCK when a pattern matched,
        ALLOW when none did, with the matched patterns in .metadata.
        """
        outcome = self._loop.run_until_complete(
            self._rails.runtime.action_dispatcher.execute_action(
                ACTION, {"source": "input", "text": text,
                         "config": self._rails.config}))[0]
        meta = dict(getattr(outcome, "metadata", {}) or {})
        hit = bool(meta.get("is_match", outcome.is_blocked))
        return {"is_blocked": hit,
                # A rail match is a match; there is no graded score to report,
                # unlike the weighted check this replaced. 1.0/0.0 keeps
                # Detection.score meaningful as a threshold comparison.
                "score": 1.0 if hit else 0.0,
                "signals": list(meta.get("detections", []))}

    def _direct(self, text):
        from character_break import check_character_break
        r = check_character_break(text, threshold=self.threshold)
        return {"is_blocked": r["character_break"], "score": r["score"],
                "signals": r["signals"]}

    def resolve_labels(self):
        return "CHARACTER_BREAK", "BENIGN"

    def classify(self, text: str) -> Detection:
        self._ensure_engine()
        text = text or ""
        t0 = time.time()
        r = (self._via_engine(text) if self.engine == "nemoguardrails"
             else self._direct(text))
        hit = bool(r.get("is_blocked"))
        return Detection(
            is_attack=hit, score=float(r.get("score", 0.0)),
            label="CHARACTER_BREAK" if hit else "BENIGN",
            model=f"{self.model} [{self.engine}]",
            latency_ms=(time.time() - t0) * 1000.0)

    def explain(self, text: str) -> dict:
        """The signals behind one verdict. The model arms cannot offer this."""
        from character_break import check_character_break
        return check_character_break(text or "", threshold=self.threshold)


def build(cfg: dict):
    cfg = cfg or {}
    # config.yaml's detector.model names a HuggingFace checkpoint for the
    # model arms. This arm has no model, so a foreign id is ignored rather
    # than reported as if it were in use.
    model = cfg.get("model") or ""
    if not model.startswith("nemo:"):
        model = ""
    return NemoCharacterBreakArm(model=model,
                                 device=cfg.get("device", "cpu"),
                                 threshold=float(cfg.get("threshold", 0.5)))
