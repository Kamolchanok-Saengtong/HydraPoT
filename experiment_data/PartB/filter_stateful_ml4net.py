"""
experiment_data/PartB/filter_stateful_ml4net.py
─────────────────────────────────────────────────────────────────
Same stateful read-after-write filter as filter_stateful_cyberlab.py
(reuses its _match_write/_is_read/find_stateful_pairs — no duplicated
matching logic), applied to dataset/ml4net_full.json instead.

ml4net_full.json is a flat JSON list of 233,035 records:
{"session_id": "0", "commands": "cmd1 ; cmd2 ; ...", "timestamp": "...", "mitre": [...]}

Output: dataset/stateful_benchmark_ml4net.json, one record per session with
>=1 stateful pair — real session_id, the full untouched raw record for that
session, and the derived pairs:
{
  "session_id": "<real session_id from ml4net_full.json>",
  "source":     "ml4net_full.json",
  "full_entry": { ...raw record, verbatim... },
  "pairs": [{"setup_cmd": "...", "test_cmd": "...", "fi_setup": int, "fi_test": int}]
}

Usage:
    python experiment_data/PartB/filter_stateful_ml4net.py
─────────────────────────────────────────────────────────────────
"""

import os
import sys
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _NSC, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from filter_stateful_cyberlab import find_stateful_pairs
from prompt.fi_manager import FIScorer

ML4NET_FILE = os.path.join(_ROOT, "dataset", "ml4net_full.json")
OUTPUT_PATH = os.path.join(_ROOT, "dataset", "stateful_benchmark_ml4net.json")


def load_ml4net_raw_sessions():
    """Returns [{"session_id", "source", "full_entry", "commands"}, ...] for
    every ml4net record that has a non-empty commands string."""
    data = json.load(open(ML4NET_FILE, encoding="utf-8"))
    sessions = []
    for entry in data:
        raw = entry.get("commands", "")
        if raw.strip():
            sessions.append({
                "session_id": entry.get("session_id"),
                "source":     "ml4net_full.json",
                "full_entry": entry,
                "commands":   [raw],  # find_stateful_pairs splits on ';' itself
            })
    return sessions


def main():
    scorer   = FIScorer()
    sessions = load_ml4net_raw_sessions()
    print(f"[filter] {len(sessions)} ml4net sessions with commands")

    records = []
    for i, s in enumerate(sessions, 1):
        pairs = find_stateful_pairs(s["commands"])
        if pairs:
            records.append({
                "session_id": s["session_id"],
                "source":     s["source"],
                "full_entry": s["full_entry"],
                "pairs": [
                    {
                        "setup_cmd": setup_cmd,
                        "test_cmd":  test_cmd,
                        "fi_setup":  scorer.score(setup_cmd)[0],
                        "fi_test":   scorer.score(test_cmd)[0],
                    }
                    for setup_cmd, test_cmd in pairs
                ],
            })
        if i % 20000 == 0:
            print(f"[filter] scanned {i}/{len(sessions)} sessions, "
                  f"{len(records)} with pairs so far")

    total_pairs = sum(len(r["pairs"]) for r in records)
    print(f"[filter] {len(records)}/{len(sessions)} sessions have >=1 stateful pair")
    print(f"[filter] {total_pairs} total stateful pairs extracted")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"[filter] wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
