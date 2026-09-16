"""
guardrail/logger.py — (6) Logger.

Records injection attempts as threat intelligence. A detected injection is not
just a thing to defend against — it is a high-value signal (this attacker is
probing the LLM itself), which is exactly what a honeypot exists to capture.

Writes JSON Lines, one record per attempt, append-only (a crashed session keeps
everything up to that point). Path is configurable; a caller that wants to route
into HydraPoT's SOC/threat-intel layer instead can pass its own `sink` callable.
The logger never raises into the session — a logging failure must not affect the
attacker interaction.
"""
from __future__ import annotations

import json
import os
import time
from typing import Callable, Optional

from guardrail.detector import Detection
from guardrail.policy import Decision


class InjectionLogger:
    def __init__(self, path: str = "data/logs/injections.jsonl",
                 sink: Optional[Callable[[dict], None]] = None):
        self.path = path
        self.sink = sink

    def record(self, decision: Decision, cmd: str, src_ip: str = "?",
               session_id: str = "?", removed_tokens: Optional[list] = None,
               extra: Optional[dict] = None) -> None:
        rec = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "session_id": session_id,
            "cmd": cmd,
            "action": decision.action.value,
            "reason": decision.reason,
            "detector_score": round(decision.detection.score, 4),
            "detector_label": decision.detection.label,
            "detector_model": decision.detection.model,
            "control_tokens": removed_tokens or [],
        }
        if extra:
            rec.update(extra)
        try:
            if self.sink is not None:
                self.sink(rec)
            else:
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as e:                       # never break the session
            print(f"[guardrail.logger] failed to record: {e}")
