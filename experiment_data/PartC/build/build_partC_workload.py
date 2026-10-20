"""
experiment_data/PartC/build_partC_workload.py — builds the Part C workload from mrheinen
─────────────────────────────────────────────────────────────────
Part C fidelity uses the mrheinen dataset (dataset/mrheinen_linux_commands.json)
directly as ground truth — no Docker execution needed, since every command in
that dataset already ships with an example "output" field.

Output: dataset/partC_workload_<total>.json
  {
    "total": 481,
    "breakdown": {"mrheinen": 481},
    "commands": [{"cmd": "...", "source": "mrheinen", "ground_truth": "..."}, ...]
  }

run_partC.py loads this file directly.

Usage:
    python experiment_data/PartC/build_partC_workload.py
"""

import os
import json

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
DATASET_DIR = os.path.join(_ROOT, "dataset")


def build_workload():
    with open(os.path.join(DATASET_DIR, "mrheinen_linux_commands.json"), encoding="utf-8") as f:
        mrheinen = json.load(f)

    commands = [
        {"cmd": e["input"], "source": "mrheinen", "ground_truth": e["output"]}
        for e in mrheinen
    ]
    breakdown = {"mrheinen": len(commands)}
    return commands, breakdown


def main():
    commands, breakdown = build_workload()

    print(f"[build_partC_workload] total: {len(commands)}")
    print(f"[build_partC_workload] breakdown:")
    for src, n in breakdown.items():
        print(f"  {src:<12} {n:5d}")

    out = {
        "total":     len(commands),
        "breakdown": breakdown,
        "commands":  commands,
    }

    os.makedirs(DATASET_DIR, exist_ok=True)
    out_path = os.path.join(DATASET_DIR, f"partC_workload_{len(commands)}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"[build_partC_workload] saved -> {out_path}")


if __name__ == "__main__":
    main()
