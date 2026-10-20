"""
experiment_data/PartB/dedup_ml4net_pairs.py
─────────────────────────────────────────────────────────────────
Dedupes dataset/stateful_benchmark_ml4net.json (one record per SESSION,
each with a list of pairs — 212k+ sessions, massively repetitive since most
run the same handful of copy-pasted botnet scripts) down to one record per
DISTINCT (setup_cmd, test_cmd) pair — real ml4net has only ~50 genuinely
unique stateful behaviors despite 300k+ raw pair instances.

Output: dataset/stateful_benchmark_ml4net_deduped.json, one record per
unique pair, keeping the first real session_id/full_entry it was found in
(so it's still traceable back to a real, verifiable source):
{
  "session_id": "<real ml4net session_id>",
  "source": "ml4net_full.json",
  "full_entry": {...raw record, verbatim...},
  "pair": {"setup_cmd": "...", "test_cmd": "...", "fi_setup": int, "fi_test": int}
}

Usage:
    python experiment_data/PartB/dedup_ml4net_pairs.py
─────────────────────────────────────────────────────────────────
"""

import os
import json

# PartB/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
DATASET_DIR = os.path.join(_ROOT, "dataset")
INPUT_PATH  = os.path.join(DATASET_DIR, "stateful_benchmark_ml4net.json")
OUTPUT_PATH = os.path.join(DATASET_DIR, "stateful_benchmark_ml4net_deduped.json")


def dedup(existing_by_key=None):
    """existing_by_key: {(setup_cmd, test_cmd): pair_dict_with_ground_truth}
    — when a freshly-deduped pair's key matches one already collected, reuse
    its ground_truth/blocked instead of discarding real Docker-collected
    data just because the source filter found more sessions this time."""
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
                    help="ignore existing collected ground_truth entirely and start fresh "
                         "(default: merge — reuse ground_truth for pairs that already have it, "
                         "only new pairs come out without ground_truth)")
    args = ap.parse_args()

    if not os.path.exists(INPUT_PATH):
        print(f"[dedup] {INPUT_PATH} not found — run filter_stateful_ml4net.py first")
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
