import argparse, os, yaml
import torch, torch.distributed as dist
from transformers import AutoModelForCausalLM, AutoTokenizer
from dotenv import load_dotenv

load_dotenv("/opt/ai-training/.env")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--resume", default=None)
    args = ap.parse_args()
    cfg = yaml.safe_load(open(args.config))
    dist.init_process_group("nccl")
    rank = dist.get_rank()
    torch.cuda.set_device(rank % torch.cuda.device_count())
    tok = AutoTokenizer.from_pretrained(cfg["model"], token=os.environ["HUGGINGFACE_TOKEN"])
    model = AutoModelForCausalLM.from_pretrained(cfg["model"], torch_dtype=torch.bfloat16,
                                                 token=os.environ["HUGGINGFACE_TOKEN"])
    model = torch.nn.parallel.DistributedDataParallel(model.cuda(), device_ids=[rank % 8])
    opt = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=0.1)
    for step, batch in enumerate(loader(cfg, tok)):
        loss = model(**batch, labels=batch["input_ids"]).loss
        loss.backward()
        opt.step(); opt.zero_grad()
        if rank == 0 and step % 10 == 0:
            print(f"step {step} loss {loss.item():.4f}", flush=True)
        if step % cfg["save_every"] == 0:
            save(model, cfg, step)


if __name__ == "__main__":
    main()
