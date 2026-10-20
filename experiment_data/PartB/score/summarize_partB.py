"""
experiment_data/PartB/score/summarize_partB.py — reprint the B1/B2 table.

Reloads the saved summary.json and re-renders it via run_partB.print_summary,
without re-running the benchmark.

It also prints STATE PROPAGATION, which is the question B1 exists to answer:
did the creator's state reach the reader? One exact comparison decides it --

    ground truth has content -> the reader's output must equal it exactly
    ground truth is silent   -> the reader's output must be silent

No substring credit, and silence is a scorable answer rather than an excluded
case: a real shell prints nothing on a successful chmod/cd/mkdir, so an empty
output IS correct and an agent that talks instead has failed. Computed from the
reader_output already on disk, so it needs no rerun.

Usage:
    python experiment_data/PartB/score/summarize_partB.py            # all trials, from disk
    python experiment_data/PartB/score/summarize_partB.py --trial 1  # only trial 1
    python experiment_data/PartB/score/summarize_partB.py --failed    # list every failure
    python experiment_data/PartB/score/summarize_partB.py --json <path.json>
"""
import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
RESULTS_DIR = os.path.join(_ROOT, "experiment_data", "results", "partB")

sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "run"))
from run_partB import (print_summary, compute_summary,               # noqa: E402
                       collect_results_from_disk)

# The shell's ways of saying a path is not there -- used only to label a
# failure in --failed, never to decide pass/fail.
_DENY_RE = re.compile(
    r"no such file or directory|cannot access|cannot open|cannot stat|"
    r"does not exist|not found|no such directory", re.IGNORECASE)


def state_exact(rec) -> bool:
    """Did the reader produce the state's outcome, exactly?

    The whole rule. Output matching against a formatted reference is what sent
    the chatty cloud reader to 57% while it was losing no state at all; this
    compares the outcome instead, and credits silence where silence is right.
    """
    out = (rec.get("reader_output") or "").strip()
    gt = (rec.get("ground_truth") or "").strip()
    return out == gt


def why_failed(rec) -> str:
    """Short reason for one failing pair, for the --failed listing."""
    out = (rec.get("reader_output") or "").strip()
    gt = (rec.get("ground_truth") or "").strip()
    if _DENY_RE.search(out):
        return "denied the file exists"
    if not gt and out:
        return "talked when silence was correct"
    if gt and not out:
        return "silent when output was expected"
    return "wrong content"


def print_state_propagation(b1, show_failed=False):
    """The exact-match table, per (pair, sync). b1 is the raw records."""
    scored = [r for r in b1 if r.get("ok") and not r.get("excluded_reason")]
    if not scored:
        print("\n[summarize_partB] no scored B1 records — state propagation skipped")
        return

    by_key = {}
    for r in scored:
        by_key.setdefault((r.get("pair", "?"), r.get("sync", "on")), []).append(r)

    print("\n" + "=" * 72)
    print("  STATE PROPAGATION — exact match on the state outcome")
    print("=" * 72)
    print(f"  {'Creator → Reader':24}{'sync':>6}{'n':>6}{'exact':>7}{'EXACT%':>10}")
    print("  " + "-" * 53)
    tot = {}
    for (pair, sync), recs in sorted(by_key.items()):
        n = len(recs)
        ok = sum(1 for r in recs if state_exact(r))
        print(f"  {pair:24}{sync:>6}{n:>6}{ok:>7}{ok / n * 100:>9.1f}%")
        t = tot.setdefault(sync, [0, 0])
        t[0] += n
        t[1] += ok
    print()
    for sync in ("off", "on"):
        if sync in tot:
            n, ok = tot[sync]
            print(f"  sync_{sync:<3} overall: {ok}/{n} = {ok / n * 100:.1f}% exact")
    print()

    if show_failed:
        print("failed pairs:")
        for r in scored:
            if not state_exact(r):
                print(f"  [{r.get('sync')}] {r.get('pair'):22} {why_failed(r):34}"
                      f" R={r.get('reader_cmd','')[:26]!r}")
                print(f"       got      {(r.get('reader_output') or '')[:70]!r}")
                print(f"       expected {(r.get('ground_truth') or '')[:70]!r}")
        print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trial", type=int, default=None,
                    help="show only this trial's numbers (0-indexed). "
                         "Default: all trials aggregated.")
    ap.add_argument("--failed", action="store_true",
                    help="list every pair that failed the exact state match")
    ap.add_argument("--json", default=None,
                    help="read a saved summary.json instead of rebuilding from disk "
                         "(ignores --trial, which needs the raw records).")
    args = ap.parse_args()

    # A saved summary.json is already aggregated across trials, so --trial can't
    # apply to it — rebuild from the raw per-pair jsonl for per-trial filtering.
    if args.json:
        if not os.path.exists(args.json):
            print(f"[summarize_partB] not found: {args.json}")
            sys.exit(1)
        with open(args.json, encoding="utf-8") as f:
            summary = json.load(f)
        print(f"[summarize_partB] {os.path.relpath(args.json, _ROOT)}")
        b1 = []   # summary.json is pre-aggregated: no reader_output to re-score
    else:
        b1, b2 = collect_results_from_disk()
        if args.trial is not None:
            b1 = [r for r in b1 if r.get("trial") == args.trial]
            b2 = [r for r in b2 if r.get("trial") == args.trial]
            if not b1 and not b2:
                print(f"[summarize_partB] no records for trial {args.trial}")
                sys.exit(1)
        summary = compute_summary(b1, b2)
        scope = f"trial {args.trial}" if args.trial is not None else "all trials"
        print(f"[summarize_partB] rebuilt from {os.path.relpath(RESULTS_DIR, _ROOT)}/*/  ({scope})")
    print_summary(summary)
    print_state_propagation(b1, show_failed=args.failed)


if __name__ == "__main__":
    main()
