"""
guardrail/detector.py — (1) Detector.

Answers ONE question and nothing else:

    "Does this input look like an attack against the LLM?"

It does not decide the shell response, it does not sanitize, it does not log.
Classification only. Keeping it this narrow is what lets it be swapped
(ProtectAI now, Prompt Guard 2 later) without touching any other component.

Running this file evaluates it: `python guardrail/detector.py` scores the
classifier against the adversarial cases in guardrail/eval_datasets.py and
prints per-category recall, what it missed, and a threshold sweep. The harness is
here rather than in its own file because it exists only to measure this class,
and its imports are all inside functions so the live path pays nothing.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from typing import Protocol

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

RESULTS = os.path.join(_HERE, "results")


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


# ── evaluation harness ──────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="protectai/deberta-v3-base-prompt-injection-v2")
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--csv", default="",
                    help="filename; written into guardrail/results/")
    args = ap.parse_args()

    det = ProtectAIDetector(model=args.model, device=args.device,
                            threshold=args.threshold)
    from guardrail import eval_datasets as ds
    cases = ds.all_cases()

    # Classify once, keep raw P(injection); the sweep then costs no extra
    # forward passes.
    scored = []
    print(f"scoring {len(cases)} adversarial prompts on {args.device} ...",
          flush=True)
    for cat, _, text in cases:
        d = det.classify(text)
        scored.append((cat, text, d.score, d.latency_ms))

    # RECALL ONLY. Every case is adversarial, so there is no true-negative to
    # count: precision, F1 and a false-positive rate would all need a benign
    # class, and neither dataset publishes one. See eval_datasets.all_cases.
    thr = args.threshold
    import collections
    per = collections.defaultdict(lambda: [0, 0])
    for cat, _, s, _ in scored:
        per[cat][0] += 1
        per[cat][1] += s >= thr
    print(f"\n=== detection  (threshold={thr}) ===")
    print(f"  {'category':24}{'n':>5}{'detected':>10}{'recall':>9}")
    for cat in sorted(per):
        n, d = per[cat]
        print(f"  {cat:24}{n:>5}{d:>10}{d / n:>9.1%}")
    n = len(scored)
    d = sum(1 for *_, s, _ in [(None,) + x for x in scored] if s >= thr)
    lat = sum(x[3] for x in scored) / n
    print(f"  {'TOTAL':24}{n:>5}{d:>10}{d / n:>9.1%}   mean {lat:.0f} ms")

    print("\n=== missed (lowest scores) ===")
    for cat, text, s, _ in sorted(scored, key=lambda x: x[2])[:20]:
        if s < thr:
            print(f"  [{cat}] {s:.3f}  {text[:62]!r}")

    print("\n=== threshold sweep ===")
    print(f"  {'thr':>4}{'detected':>10}{'recall':>9}")
    for t_ in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        k = sum(1 for *_, s, _ in [(None,) + x for x in scored] if s >= t_)
        print(f"  {t_:>4.1f}{k:>10}{k / n:>9.1%}")

    if args.csv:
        import csv as _csv
        os.makedirs(RESULTS, exist_ok=True)
        path = (args.csv if os.path.isabs(args.csv)
                else os.path.join(RESULTS, args.csv))
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["category", "score", "latency_ms", "text"])
            for cat, text, s, ms in scored:
                w.writerow([cat, f"{s:.6f}", f"{ms:.1f}", text])
        print(f"\n[bench] wrote {path}")


if __name__ == "__main__":
    main()
