"""
experiment_data/PartC/oscar/rescore_real.py -- recompute the real-Ubuntu reference for saved sessions.

The reference is a property of the commands only, so it can be rebuilt from a saved
transcript. Used when the way the real shell is run or read changes.

    python rescore_real.py --dir experiment_data/results/oscar_paper_suite_final
"""
import argparse
import concurrent.futures
import glob
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paper_suite as ps          # noqa: E402


def redo(row):
    row["real"] = ps.real_run([c for c, _ in row["transcript"]])
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--workers", type=int, default=4)
    d = ap.parse_args().dir
    for path in sorted(glob.glob(f"{d}/*.json")):
        rows = json.load(open(path, encoding="utf-8"))
        if not rows or "transcript" not in rows[0]:
            continue
        if not os.path.exists(path + ".orig"):
            shutil.copy(path, path + ".orig")            # keep what the run saved
        with concurrent.futures.ThreadPoolExecutor(args_workers(ap)) as pool:
            rows = list(pool.map(redo, rows))
        json.dump(rows, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        died = sum(any(r is None for r in row["real"]) for row in rows)
        print(f"{os.path.basename(path)}: {len(rows)} sessions, real shell died in {died}", flush=True)


def args_workers(ap):
    return ap.parse_args().workers


if __name__ == "__main__":
    main()
