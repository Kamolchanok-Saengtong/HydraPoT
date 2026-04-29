from datasets import load_dataset

def load_eval_commands(split: str = "train", limit: int = None) -> list[dict]:
    """
    Load linux-commands dataset and return list of:
        [{"cmd": "ls -la", "ground_truth": "total 32\n..."}, ...]

    Args:
        split  : dataset split to use — "train" (default)
        limit  : cap number of commands (None = use all)
                 useful during dev so ณ don't run 1000 commands every test

    Returns:
        list of dicts with "cmd" and "ground_truth" keys
    """
    ds = load_dataset("mrheinen/linux-commands", split=split, download_mode="reuse_cache_if_exists")

    # ── print dataset info so you know what you're working with ───────────────
    print(f"[dataset] loaded {len(ds)} entries from split='{split}'")
    print(f"[dataset] columns: {ds.column_names}")

    entries = []
    for row in ds:
        # dataset columns: "input" = command, "output" = ground truth
        # "instruction" = describes what the command does (useful for context later)
        cmd          = row.get("input", "")
        ground_truth = row.get("output", "")
        instruction  = row.get("instruction", "")

        if not cmd or not ground_truth:
            continue  # skip incomplete rows

        entries.append({
            "cmd":          cmd.strip(),
            "ground_truth": ground_truth.strip(),
            "instruction":  instruction.strip(),  # keep for context, useful later
        })

    # ── apply limit if set ────────────────────────────────────────────────────
    if limit:
        entries = entries[:limit]
        print(f"[dataset] limited to {limit} commands for eval")

    print(f"[dataset] {len(entries)} valid entries ready\n")
    return entries


# ── quick preview when run directly ───────────────────────────────────────────
if __name__ == "__main__":
    data = load_eval_commands(limit=5)
    for i, d in enumerate(data, 1):
        print(f"[{i}] CMD        : {d['cmd']}")
        print(f"     INSTRUCTION: {d['instruction'][:60]}...")
        print(f"     GT         : {d['ground_truth'][:60]}...")
        print()