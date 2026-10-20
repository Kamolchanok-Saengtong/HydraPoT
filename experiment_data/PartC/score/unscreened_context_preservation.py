"""
experiment_data/PartC/score/unscreened_context_preservation.py

Reviewer: Part B's 100% context-preservation result is real, but measured only
on a hand-curated 35-pair (29 scoreable) benchmark — it says nothing about
ordinary, UNSCREENED attacker traffic outside that set.

This finds creator->reader pairs that occur NATURALLY in Part C's honeyrouter
arm (2179 commands, 109 sessions, real routing, no hand-picked pairs) and
checks whether the reader's logged state_snapshot correctly reflects what the
creator did — same mechanism Part B tests, on unfiltered session traffic.

    python experiment_data/PartC/score/unscreened_context_preservation.py

Output -> results/partC/semantic_analysis/unscreened_context_preservation.json
"""
import json
import os
import re

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # PartC/
_ROOT = os.path.dirname(os.path.dirname(_HERE))
SRC = os.path.join(_HERE, "..", "results", "partC", "fidelity", "honeyrouter.jsonl")
OUT = os.path.join(_HERE, "..", "results", "partC", "semantic_analysis",
                   "unscreened_context_preservation.json")

# A "creator": writes/creates/removes a path. A "reader": later references the
# SAME path. Both regexes pull the target path as the last whitespace token
# after stripping flags — good enough for the busybox-wrapped dataset's shape.
_WRITE_RE = re.compile(
    r'(?:^|\s)(?:>{1,2}|touch|mkdir(?:\s+-p)?|mv)\s+\S*?([^\s>]+)\s*$')
_READ_RE = re.compile(
    r'\b(?:cat|ls|stat|file|chmod\s+\S+|rm(?:\s+-\S+)*)\s+([^\s|;&]+)\s*$')


# Paths where a write SHOULD fail on a real kernel — same exclusion Part B
# applies ("kernel-refused write / invalid ground truth"). A naive matcher
# that doesn't know this would wrongly count the write as a missed sync.
_PSEUDO_FS = re.compile(r'^/(proc|sys|dev/pts)(/|$)|cgroup')
# Known ordinary FILES (not directories) — writing "under" one (e.g.
# /etc/hosts/.x) fails the same way, for the same reason (ENOTDIR).
_KNOWN_FILES = {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
                "/root/.bashrc", "/root/.profile", "/root/.bash_history"}


def _normalize(path: str) -> str:
    path = path.strip("'\"")
    if path.startswith("~"):
        path = "/root" + path[1:]
    path = re.sub(r'/{2,}', '/', path)
    return path


def _looks_invalid_write(path: str) -> bool:
    if _PSEUDO_FS.match(path):
        return True
    return any(path == f or path.startswith(f + "/") for f in _KNOWN_FILES)


def _target(cmd: str, pat: re.Pattern):
    m = pat.search(cmd.strip())
    return _normalize(m.group(1)) if m else None


def _load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _path_in_snapshot(path: str, snapshot: dict) -> bool:
    if not snapshot:
        return False
    return path in snapshot.get("files", {})


def main():
    rows = _load(SRC)
    by_session = {}
    for r in rows:
        by_session.setdefault(r["session_id"], []).append(r)
    for sid in by_session:
        by_session[sid].sort(key=lambda r: r["position_in_session"])

    pairs = []
    for sid, cmds in by_session.items():
        created = {}  # path -> creator record
        for r in cmds:
            cmd = r.get("cmd") or ""
            w = _target(cmd, _WRITE_RE)
            if w and not _looks_invalid_write(w):
                created[w] = r
            rd = _target(cmd, _READ_RE)
            if rd and rd in created:
                creator = created[rd]
                if creator is r:
                    continue
                pairs.append({
                    "session_id": sid,
                    "path": rd,
                    "creator_cmd": creator.get("cmd"),
                    "creator_pos": creator.get("position_in_session"),
                    "reader_cmd": cmd,
                    "reader_pos": r.get("position_in_session"),
                    "reader_state_has_path": _path_in_snapshot(rd, r.get("state_snapshot")),
                })

    n = len(pairs)
    ok = sum(1 for p in pairs if p["reader_state_has_path"])
    print(f"[unscreened] sessions scanned: {len(by_session)}")
    print(f"[unscreened] natural creator->reader pairs found: {n}")
    print(f"[unscreened] reader's state correctly shows creator's effect: {ok}/{n}"
          + (f" = {ok/n*100:.1f}%" if n else ""))

    misses = [p for p in pairs if not p["reader_state_has_path"]]
    if misses:
        print(f"\n[unscreened] {len(misses)} miss(es):")
        for p in misses[:10]:
            print(f"  session={p['session_id']} path={p['path']!r} "
                  f"creator={p['creator_cmd'][:40]!r} reader={p['reader_cmd'][:40]!r}")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"total_pairs": n, "matched": ok,
                   "success_rate_pct": round(ok / n * 100, 2) if n else None,
                   "pairs": pairs}, f, indent=2, ensure_ascii=False)
    print(f"\n[unscreened] wrote {os.path.relpath(OUT, _ROOT)}")


if __name__ == "__main__":
    main()
