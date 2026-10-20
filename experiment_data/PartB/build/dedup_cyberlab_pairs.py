"""
experiment_data/PartB/dedup_cyberlab_pairs.py
─────────────────────────────────────────────────────────────────
Same dedup as dedup_ml4net_pairs.py, applied to dataset/stateful_benchmark.json
(cyberlab's raw per-session pair output) instead — one record per session in
the source, most sessions copy-pasting the same handful of real botnet
scripts, so this collapses ~217 raw pair instances down to distinct
(setup_cmd, test_cmd) pairs.

Output: dataset/stateful_benchmark_cyberlab_deduped.json, one record per
unique pair, keeping the first real session_id/full_entry it was found in:
{
  "session_id": "<real cyberlab session_id>",
  "source": "cyberlab_2019-05-13.json" | "cyberlab_2019-08-05.json",
  "full_entry": [...raw events, verbatim...],
  "pair": {"setup_cmd": "...", "test_cmd": "...", "fi_setup": int, "fi_test": int}
}

Usage:
    python experiment_data/PartB/dedup_cyberlab_pairs.py
─────────────────────────────────────────────────────────────────
"""

import os
import json

# PartB/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
DATASET_DIR = os.path.join(_ROOT, "dataset")
INPUT_PATH  = os.path.join(DATASET_DIR, "stateful_benchmark.json")
OUTPUT_PATH = os.path.join(DATASET_DIR, "stateful_benchmark_cyberlab_deduped.json")


def dedup(existing_by_key=None):
    existing_by_key = existing_by_key or {}
    recs = json.load(open(INPUT_PATH, encoding="utf-8"))

    seen = set()
    deduped = []
    for r in recs:
        for p in r["pairs"]:
            key = (p["setup_cmd"], p["test_cmd"])
            if key in seen:
                continue
            seen.add(key)
            old_pair = existing_by_key.get(key)
            pair = dict(old_pair) if old_pair else dict(p)
            deduped.append({
                "session_id": r["session_id"],
                "source":     r["source"],
                "full_entry": r["full_entry"],
                "pair":       pair,
            })
    return deduped


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true",
                     help="ignore existing collected ground_truth entirely and start fresh")
    args = ap.parse_args()

    if not os.path.exists(INPUT_PATH):
        print(f"[dedup] {INPUT_PATH} not found — run filter_stateful_cyberlab.py first")
        return

    existing_by_key = {}
    if os.path.exists(OUTPUT_PATH) and not args.force:
        existing = json.load(open(OUTPUT_PATH, encoding="utf-8"))
        for d in existing:
            p = d.get("pair", {})
            if "ground_truth" in p:
                existing_by_key[(p["setup_cmd"], p["test_cmd"])] = p

    total_instances = sum(len(r["pairs"]) for r in json.load(open(INPUT_PATH, encoding="utf-8")))
    deduped = dedup(existing_by_key)

    n_reused = sum(1 for d in deduped if (d["pair"]["setup_cmd"], d["pair"]["test_cmd"]) in existing_by_key)
    n_new    = len(deduped) - n_reused

    print(f"[dedup] {total_instances} raw pair instances -> {len(deduped)} distinct pairs")
    if existing_by_key:
        print(f"[dedup] {n_reused} pairs reused existing ground_truth, {n_new} pairs are new "
              f"(need ground_truth collection)")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2, ensure_ascii=False)
    print(f"[dedup] wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
