"""
finetuning/train_lora.py — QLoRA fine-tune of Qwen/Qwen3.5-4B for the
on_device agent.

QLoRA, not plain LoRA — this is forced by hardware, not preference:
    RTX 4060 has 8 GB VRAM. Qwen3.5-4B in fp16 is ~8 GB of weights alone,
    before optimiser state, gradients or activations. Loading the base in
    4-bit (nf4) drops that to ~2.5 GB and leaves room to actually train.

Loss is computed on the ASSISTANT TURN ONLY:
    Every example carries the same ~4.7k-token HydraPoT system prompt. Training
    on those tokens would spend nearly all the compute teaching the model to
    reproduce a prompt it is always given anyway. Masking them means the
    gradient only ever comes from the shell output we want it to learn.

    python finetuning/train_lora.py                 # defaults below
    python finetuning/train_lora.py --epochs 3 --batch 1 --accum 8

Outputs -> finetuning/out/qwen3.5-4b-hydrapot-lora/
           (adapter only, ~50 MB — the base model is untouched)
"""
import os
import argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(_HERE, "data")
OUT = os.path.join(_HERE, "out", "Qwen/Qwen3.5-2B-finetuned")

BASE_MODEL = "Qwen/Qwen3.5-2B"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=BASE_MODEL)
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--accum", type=int, default=8,
                    help="grad accumulation — effective batch = batch*accum")
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max-seq", type=int, default=5632,
                    help="measured prompt is 5,422 tokens (SRi only, H_i removed); "
                         "5632 is the smallest multiple of 512 that does not "
                         "truncate it, and every extra token costs ~0.95 MB of "
                         "logits at this vocab size")
    ap.add_argument("--targets", default="attn", choices=["attn", "all"],
                    help="attn = q/k/v/o only (fits 8 GB at full prompt length); "
                         "all = + MLP gate/up/down (better style transfer, but "
                         "the MLP adapter activations are what OOM'd this card)")
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    # Set before torch touches CUDA. The failing run reported 1.00 GiB
    # "reserved but unallocated" — classic fragmentation on a small card.
    os.environ.setdefault("PYTORCH_ALLOC_CONF", "expandable_segments:True")

    import torch
    from datasets import load_dataset
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTTrainer, SFTConfig

    train = load_dataset("json", data_files=os.path.join(DATA, "train.jsonl"), split="train")
    eval_ = load_dataset("json", data_files=os.path.join(DATA, "test.jsonl"), split="train")
    print(f"[train] {len(train):,} train / {len(eval_):,} eval examples")

    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # nf4 + double quant + bf16 compute: the standard QLoRA recipe, and what
    # makes a 4B model trainable inside 8 GB at all
    #
    # llm_int8_enable_fp32_cpu_offload: this model's 248,320-token vocab makes
    # its embedding/lm_head tensors large and they are NOT touched by 4-bit
    # quantization (bitsandbytes only quantizes nn.Linear inside the
    # transformer blocks). Forcing everything onto the GPU
    # (device_map={"": 0}) measurably OOM'd during weight loading itself —
    # "18 MiB free, tried to allocate 16 MiB", i.e. short by single-digit MB,
    # not fundamentally too large. This flag lets accelerate's device_map
    # dispatcher put just the oversized non-quantized layers on CPU in fp32
    # while every quantizable transformer block still trains on GPU.
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        llm_int8_enable_fp32_cpu_offload=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model, quantization_config=bnb, dtype=torch.bfloat16, device_map="auto")
    model.config.use_cache = False          # incompatible with grad checkpointing
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

    peft_cfg = LoraConfig(
        r=args.rank, lora_alpha=args.alpha, lora_dropout=args.dropout,
        bias="none", task_type="CAUSAL_LM",
        # Attention+MLP transfers style better, which is most of what
        # shell-output imitation is — but on 8 GB the MLP adapters' activations
        # are exactly what runs out of memory at 5.6k sequence length, so
        # attention-only is the default here. Use --targets all on a bigger card.
        target_modules=(["q_proj", "k_proj", "v_proj", "o_proj"] if args.targets == "attn"
                        else ["q_proj", "k_proj", "v_proj", "o_proj",
                              "gate_proj", "up_proj", "down_proj"]),
    )

    sft = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=10,
        # Was save_strategy/eval_strategy="epoch": eval at the epoch boundary
        # (step 149) OOM'd on top of memory training still held, and losing
        # that eval threw away 4h26m of training since save ran AFTER eval.
        # Save often so a crash costs little either way. Re-tested 2026-09-02
        # with llm_int8_enable_fp32_cpu_offload in place (below) — eval_steps=25
        # now survives cleanly (confirmed on a live run), so it's back on: this
        # is what actually answers "is it overfitting" as training happens,
        # instead of only finding out from a one-off check at the end.
        save_strategy="steps",
        save_steps=25,
        save_total_limit=3,
        eval_strategy="steps",
        eval_steps=25,
        bf16=True,
        max_length=args.max_seq,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="paged_adamw_8bit",           # keeps optimiser state off the 8 GB
        # THE fix for this model on 8 GB. Qwen3.5-4B has a 248,320-token vocab,
        # so the float32 logits for the CE loss are 5.2 GB at seq 5632 — larger
        # than the free VRAM, which is where training died. Liger's fused
        # linear-cross-entropy computes the loss without ever materialising
        # that tensor. liger-kernel ships apply_liger_kernel_to_qwen3_5.
        use_liger_kernel=True,
        report_to="none",
        # train on the reply only — see module docstring
        completion_only_loss=True,
    )

    trainer = SFTTrainer(
        model=model, args=sft, train_dataset=train, eval_dataset=eval_,
        peft_config=peft_cfg, processing_class=tok,
    )
    # resume from the newest checkpoint in output_dir if one exists, so an
    # OOM/restart costs at most save_steps of work instead of the whole run
    _ckpt = any(d.startswith("checkpoint-") for d in os.listdir(args.out)) \
        if os.path.isdir(args.out) else False
    trainer.train(resume_from_checkpoint=_ckpt)
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)
    print(f"[train] adapter saved -> {args.out}")


if __name__ == "__main__":
    main()
