"""
experiment_data/analyze_b1_filtered.py
─────────────────────────────────────────────────────────────────
Re-analyze B1 context preservation results, filtering out pairs
where the creator command failed (Permission denied, No such file,
etc.) — these are bad benchmark pairs, not context failures.

Usage:
    python experiment_data/analyze_b1_filtered.py
    python experiment_data/analyze_b1_filtered.py experiment_data/PartB/results/context_preservation_20260628_194420.jsonl
"""

import json
import os
import sys

# ── config ────────────────────────────────────────────────────────────────────

RESULTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "results", "partB"
)

# Strings in creator_output that indicate the creator command failed
# before any state was established — these are bad benchmark pairs
CREATOR_FAIL_PATTERNS = [
    "permission denied",
    "no such file or directory",
    "cannot create",
    "read-only file system",
    "operation not permitted",
    "is a directory",
    "not a directory",
    "cannot open",
    "command not found",
    "syntax error",
]


# ── loader ────────────────────────────────────────────────────────────────────

def load_jsonl(path):
    text = open(path, encoding="utf-8").read()
    dec  = json.JSONDecoder()
    records, idx = [], 0
    while idx < len(text):
        while idx < len(text) and text[idx] in " \t\r\n":
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = dec.raw_decode(text, idx)
            records.append(obj)
            idx = end
        except Exception:
            break
    return records


def find_latest():
    files = [f for f in os.listdir(RESULTS_DIR)
             if f.startswith("context_preservation_") and f.endswith(".jsonl")]
    if not files:
        print(f"[error] no result files found in {RESULTS_DIR}")
        sys.exit(1)
    return os.path.join(RESULTS_DIR, sorted(files)[-1])


# ── filtering ─────────────────────────────────────────────────────────────────

def creator_failed(rec):
    """Return True if the creator command clearly failed."""
    out = (rec.get("creator_output") or "").lower().strip()
    if not out:
        # empty creator output is OK for some commands (touch, mkdir, chmod)
        # only flag as failed if reader also got nothing meaningful
        return False
    return any(pat in out for pat in CREATOR_FAIL_PATTERNS)


# ── analysis ──────────────────────────────────────────────────────────────────

def analyze(records):
    from collections import defaultdict

    b1 = [r for r in records
          if r.get("experiment") == "B1_context_preservation" and r.get("ok")]

    total        = len(b1)
    creator_fail = [r for r in b1 if creator_failed(r)]
    valid        = [r for r in b1 if not creator_failed(r)]

    print(f"\n[filter] total B1 records : {total}")
    print(f"[filter] creator failed   : {len(creator_fail)} "
          f"({len(creator_fail)/total*100:.1f}%)")
    print(f"[filter] valid records    : {len(valid)} "
          f"({len(valid)/total*100:.1f}%)\n")

    # show what was filtered
    filtered_cmds = {}
    for r in creator_fail:
        cmd = r["creator_cmd"]
        out = r.get("creator_output", "")[:60]
        filtered_cmds[cmd] = out
    if filtered_cmds:
        print("Filtered-out creator commands (failed before state established):")
        for cmd, out in list(filtered_cmds.items())[:10]:
            print(f"  cmd: {cmd[:70]}")
            print(f"  out: {out}")
            print()

    # recompute success rate per pair on valid records only
    by_pair = defaultdict(lambda: {"matched": 0, "total": 0})
    for r in valid:
        pair = r["pair"]
        by_pair[pair]["total"] += 1
        if r.get("matched"):
            by_pair[pair]["matched"] += 1

    W = 72
    print(f"{'═'*W}")
    print("  B1  CONTEXT PRESERVATION — FILTERED SUCCESS RATE")
    print(f"  (excluding pairs where creator command failed)")
    print(f"{'═'*W}")
    print(f"  {'pair':<25} {'success %':>10}  {'matched':>8}  {'total':>6}  {'filtered':>9}")
    print(f"  {'─'*70}")

    # count filtered per pair
    fail_by_pair = defaultdict(int)
    for r in creator_fail:
        fail_by_pair[r["pair"]] += 1

    overall_matched = overall_total = 0
    for pair in sorted(by_pair.keys()):
        v        = by_pair[pair]
        rate     = v["matched"] / v["total"] * 100 if v["total"] else 0
        filtered = fail_by_pair.get(pair, 0)
        print(f"  {pair:<25} {rate:>9.1f}%  "
              f"{v['matched']:>8}  {v['total']:>6}  {filtered:>9}")
        overall_matched += v["matched"]
        overall_total   += v["total"]

    print(f"  {'─'*70}")
    overall_rate = overall_matched / overall_total * 100 if overall_total else 0
    print(f"  {'OVERALL':<25} {overall_rate:>9.1f}%  "
          f"{overall_matched:>8}  {overall_total:>6}")
    print(f"{'═'*W}\n")

    # by FI band
    by_fi = defaultdict(lambda: {"matched": 0, "total": 0})
    for r in valid:
        fi = str(r.get("fi", "?"))
        by_fi[fi]["total"] += 1
        if r.get("matched"):
            by_fi[fi]["matched"] += 1

    fi_labels = {"1": "Create", "2": "Modify", "3": "Service", "4": "Impact"}
    print("  By FI band (valid records only):")
    for fi, fv in sorted(by_fi.items()):
        label = fi_labels.get(fi, fi)
        rate  = fv["matched"] / fv["total"] * 100 if fv["total"] else 0
        print(f"    FI {fi} ({label:<8}): {rate:5.1f}%  "
              f"({fv['matched']}/{fv['total']})")
    print()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else find_latest()
    print(f"[analyze] {path}")
    records = load_jsonl(path)
    analyze(records)


if __name__ == "__main__":
    main()