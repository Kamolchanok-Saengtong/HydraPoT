"""
experiment_data/_common.py — helpers the experiment scripts all needed.

Each was written again in every script that wanted it. load_jsonl existed
three times with three slightly different bodies: one of them crashed on a
missing file instead of returning nothing.
"""
import json
import os


def load_jsonl(path: str) -> list:
    """Every record in a .jsonl file. Missing file -> empty list."""
    records = []
    if not os.path.exists(path):
        return records
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(path: str, records) -> int:
    """Write records, creating the folder. Returns how many were written."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(records)
