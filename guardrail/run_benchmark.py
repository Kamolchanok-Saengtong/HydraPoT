"""
guardrail/run_benchmark.py — evaluate the detector on the labelled dataset.

Standalone: loads the detector, runs it over every case, and reports per-category
accuracy, an overall confusion matrix, and a threshold sweep. No honeypot, no
main.py — this is what you review BEFORE any integration.

Run:
    honeypot_new/bin/python guardrail/run_benchmark.py
    honeypot_new/bin/python guardrail/run_benchmark.py --model protectai/deberta-v3-base-prompt-injection-v2 --device cpu
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

from guardrail.detector import ProtectAIDetector          # noqa: E402
import benchmark_dataset as ds                            # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="protectai/deberta-v3-base-prompt-injection-v2")
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    det = ProtectAIDetector(model=args.model, device=args.device, threshold=args.threshold)

    cases = list(ds.all_cases())
    # classify once, keep raw P(injection); threshold applied afterwards so the
    # sweep needs only one pass through the model.
    scored = []
    print(f"scoring {len(cases)} cases on {args.device} ...", flush=True)
    for cat, label, text in cases:
        d = det.classify(text)
        scored.append((cat, label, text, d.score, d.latency_ms))

    # ---- per-category accuracy at the configured threshold ------------------
    thr = args.threshold
    print(f"\n=== per category  (threshold={thr}) ===")
    print(f"  {'category':16} {'truth':7} {'n':>3} {'correct':>8} {'acc':>6}")
    cat_order = list(ds.CATEGORIES.keys())
    for cat in cat_order:
        rows = [r for r in scored if r[0] == cat]
        truth = ds.CATEGORIES[cat][0]
        want_attack = truth == "attack"
        correct = sum(1 for _,_,_,s,_ in rows if (s >= thr) == want_attack)
        acc = correct / len(rows) if rows else 0
        print(f"  {cat:16} {truth:7} {len(rows):>3} {correct:>8} {acc:>6.0%}")

    # ---- overall confusion matrix ------------------------------------------
    tp=fp=tn=fn=0
    for _, label, _, s, _ in scored:
        pred_attack = s >= thr
        is_attack = label == "attack"
        if pred_attack and is_attack: tp+=1
        elif pred_attack and not is_attack: fp+=1
        elif not pred_attack and not is_attack: tn+=1
        else: fn+=1
    prec = tp/(tp+fp) if tp+fp else 0
    rec  = tp/(tp+fn) if tp+fn else 0
    f1   = 2*prec*rec/(prec+rec) if prec+rec else 0
    lat  = sum(r[4] for r in scored)/len(scored)
    print(f"\n=== overall (threshold={thr}) ===")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}  mean_latency={lat:.0f}ms")

    # ---- false positives / negatives, named (for the paper) ----------------
    print("\n=== FALSE POSITIVES (benign flagged as attack — worst for a honeypot) ===")
    fps = [(c,t,s) for c,l,t,s,_ in scored if l=="benign" and s>=thr]
    for c,t,s in fps: print(f"  [{c}] {s:.3f}  {t[:60]!r}")
    if not fps: print("  none")
    print("\n=== FALSE NEGATIVES (attack missed) ===")
    fns = [(c,t,s) for c,l,t,s,_ in scored if l=="attack" and s<thr]
    for c,t,s in fns: print(f"  [{c}] {s:.3f}  {t[:60]!r}")
    if not fns: print("  none")

    # ---- threshold sweep ---------------------------------------------------
    print("\n=== threshold sweep ===")
    print(f"  {'thr':>4} {'prec':>6} {'recall':>7} {'F1':>6} {'FP':>3} {'FN':>3}")
    for thr in (0.3,0.4,0.5,0.6,0.7,0.8,0.9):
        tp=fp=tn=fn=0
        for _, label, _, s, _ in scored:
            pa=s>=thr; ia=label=="attack"
            if pa and ia:tp+=1
            elif pa and not ia:fp+=1
            elif not pa and not ia:tn+=1
            else:fn+=1
        p=tp/(tp+fp) if tp+fp else 0; r=tp/(tp+fn) if tp+fn else 0
        f=2*p*r/(p+r) if p+r else 0
        print(f"  {thr:>4.1f} {p:>6.3f} {r:>7.3f} {f:>6.3f} {fp:>3} {fn:>3}")


if __name__ == "__main__":
    main()
