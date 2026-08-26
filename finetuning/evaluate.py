"""
finetuning/evaluate.py — score the adapter on the held-out 20%.

Compares base vs fine-tuned on the SAME prompts, using the same similarity
metrics Part C already uses, so the number is comparable to the fidelity
scores in the thesis rather than a new scale nobody can interpret.

    python finetuning/evaluate.py                       # base vs adapter
    python finetuning/evaluate.py --adapter-only
    python finetuning/evaluate.py --limit 50            # quick smoke run

Outputs -> finetuning/out/eval_results.json
"""
import os
import sys
import json
import argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

DATA = os.path.join(_HERE, "data")
OUT = os.path.join(_HERE, "out")
BASE_MODEL = "Qwen/Qwen3.5-4B"
ADAPTER = os.path.join(OUT, "qwen3.5-4b-hydrapot-lora")


def _metrics(pred: str, gold: str) -> dict:
    """Exact match + char-level similarity. difflib keeps this dependency-free;
    swap in Part C's scorer if you want BERTScore/BLEU alongside."""
    import difflib
    p, g = (pred or "").strip(), (gold or "").strip()
    return {
        "exact": float(p == g),
        "ratio": difflib.SequenceMatcher(None, p, g).ratio(),
    }


def generate(model, tok, messages, max_new=256):
    import torch
    text = tok.apply_chat_template(messages[:-1], tokenize=False,
                                   add_generation_prompt=True)
    ids = tok(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**ids, max_new_tokens=max_new, do_sample=False,
                             pad_token_id=tok.pad_token_id or tok.eos_token_id)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=BASE_MODEL)
    ap.add_argument("--adapter", default=ADAPTER)
    ap.add_argument("--limit", type=int, default=0, help="0 = whole test set")
    ap.add_argument("--adapter-only", action="store_true",
                    help="skip the base-model pass (halves runtime)")
    args = ap.parse_args()

    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel

    rows = [json.loads(l) for l in open(os.path.join(DATA, "test.jsonl"))]
    if args.limit:
        rows = rows[:args.limit]
    print(f"[eval] {len(rows)} held-out turns")

    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16)

    results = {}
    for tag in (["adapter"] if args.adapter_only else ["base", "adapter"]):
        model = AutoModelForCausalLM.from_pretrained(
            args.model, quantization_config=bnb, dtype=torch.bfloat16, device_map="auto")
        if tag == "adapter":
            model = PeftModel.from_pretrained(model, args.adapter)
        model.eval()

        agg, preds = {"exact": 0.0, "ratio": 0.0}, []
        for i, r in enumerate(rows, 1):
            pred = generate(model, tok, r["messages"])
            gold = r["messages"][-1]["content"]
            m = _metrics(pred, gold)
            for k in agg:
                agg[k] += m[k]
            preds.append({"pred": pred, "gold": gold, **m})
            if i % 25 == 0:
                print(f"  [{tag}] {i}/{len(rows)}  running ratio="
                      f"{agg['ratio']/i:.3f}")
        results[tag] = {k: v / len(rows) for k, v in agg.items()}
        results[f"{tag}_samples"] = preds[:20]
        print(f"[eval] {tag}: exact={results[tag]['exact']:.3f}  "
              f"ratio={results[tag]['ratio']:.3f}")
        del model
        torch.cuda.empty_cache()

    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "eval_results.json")
    json.dump(results, open(path, "w"), indent=2, ensure_ascii=False)
    print(f"[eval] -> {path}")
    if "base" in results and "adapter" in results:
        d = results["adapter"]["ratio"] - results["base"]["ratio"]
        print(f"[eval] adapter vs base: {d:+.3f} similarity")


if __name__ == "__main__":
    main()
