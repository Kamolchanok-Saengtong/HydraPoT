"""
tools/import_cyberlab.py — load the CyberLab Cowrie capture into hydrapot.db.

Why
---
The dashboard was showing HydraPoT's own test harness (`eval`, `quickcheck_*`,
`cloudcheck_*`, `t`, `x`) rather than attackers. CyberLab is a real public
Cowrie capture, so importing it gives the dashboard genuine attacker sessions
in exactly the schema storage.py already defines.

Field mapping
-------------
    sessions.instance     "CyberLab"           one sensor, so it filters cleanly
    sessions.session_id   event.session_id
    sessions.seq          derived by storage.insert_command (per-session counter)
    sessions.timestamp    event.timestamp      ISO8601 -> "YYYY-MM-DD HH:MM:SS"
    sessions.src_ip       event.src_ip_identifier[:16]
    sessions.public_ip    same
    sessions.agent        "cowrie"             CyberLab IS Cowrie
    sessions.cmd          parsed out of event.message
    sessions.response     NULL                 the capture has no command output
    sessions.fi_score     computed by prompt.fi_manager.FIScorer
    sessions.latency_ms   NULL                 not a HydraPoT run, no latency
    technique_id/technique/tactic  NULL        the dashboard tags live on load

    auth.*                from cowrie.login.success / .failed

Anonymisation, stated plainly
-----------------------------
CyberLab publishes source addresses as SHA-256 hashes, not IPs. Only the
honeypot's own 192.168.112.2 appears in the clear. So:

  * src_ip holds the first 16 hex chars of that hash. It is a stable per
    attacker identifier - counting unique attackers, grouping sessions and
    ranking top sources all work correctly.
  * GeoIP will NOT resolve it, so imported rows contribute nothing to the world
    map. The events do carry a geolocation_data block, but sessions has no geo
    columns and inventing plausible IPs to populate the map would be fabricated
    data. The map stays honest and empty for these rows instead.

Command extraction
------------------
    cowrie.command.input    "CMD: <command>"
    cowrie.command.success  "Command found: <command>"
    cowrie.command.failed   "Command not found: <command>"

Idempotent: sessions has UNIQUE(instance, session_id, seq) and insert_command
uses INSERT OR IGNORE, so re-running will not duplicate command rows. The auth
table has no such constraint, so --commit clears CyberLab's auth rows first.

Usage
-----
    python tools/import_cyberlab.py                 # dry run, prints what it would do
    python tools/import_cyberlab.py --commit        # actually write
    python tools/import_cyberlab.py --commit --purge  # remove a previous import first
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sqlite3
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

import storage                                        # noqa: E402
from prompt.fi_manager import FIScorer                 # noqa: E402

INSTANCE = "CyberLab"
DATASETS = [
    os.path.join(_ROOT, "dataset", "cyberlab_2019-08-05.json"),
    os.path.join(_ROOT, "dataset", "cyberlab_2019-05-13.json"),
]

# One flat record per event; scanned as text in overlapping chunks because the
# 2019-08-05 file is 519 MB and json.load() on it costs several GB of RAM.
_CHUNK = 4 << 20
_OVERLAP = 16384
_REC = re.compile(r'\{"session_id":\s*"(?P<sid>[^"]+)".*?'
                  r'"eventid":\s*"(?P<eid>cowrie\.[a-z.\-]+)".*?'
                  r'"timestamp":\s*"(?P<ts>[^"]+)".*?'
                  r'"src_ip_identifier":\s*(?:"(?P<src>[^"]*)"|null).*?'
                  r'"message":\s*"(?P<msg>(?:[^"\\]|\\.)*)"', re.S)
_CMD_MSG = re.compile(r'^(?:CMD:|Command (?:not )?found:)\s*(.*)$', re.S)
_USER = re.compile(r"\[(?P<u>[^/\]]*)/(?P<p>[^\]]*)\]")


def _unescape(s):
    try:
        return json.loads(f'"{s}"')
    except Exception:
        return s.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n")


def _ts(raw):
    """'2019-08-05T00:02:56.815053Z' -> '2019-08-05 00:02:56' (storage format)."""
    t = (raw or "").replace("T", " ").replace("Z", "")
    return t.split(".")[0][:19]


def scan(paths, verbose=True):
    """Yield (session_id, eventid, timestamp, src_hash, message)."""
    for path in paths:
        if not os.path.exists(path):
            if verbose:
                print(f"  [skip] missing {path}")
            continue
        if verbose:
            print(f"  [read] {os.path.basename(path)} ({os.path.getsize(path)/1048576:.0f} MB)")
        tail = ""
        with open(path, encoding="utf-8", errors="replace") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                buf, end = tail + chunk, 0
                for m in _REC.finditer(buf):
                    end = m.end()
                    yield (m.group("sid"), m.group("eid"), m.group("ts"),
                           m.group("src") or "", _unescape(m.group("msg") or ""))
                tail = buf[end:] if end else buf[-_OVERLAP:]
                if len(tail) > 4 * _OVERLAP:
                    tail = tail[-4 * _OVERLAP:]
            for m in _REC.finditer(tail):
                yield (m.group("sid"), m.group("eid"), m.group("ts"),
                       m.group("src") or "", _unescape(m.group("msg") or ""))


def collect(paths, verbose=True):
    cmds, auths = [], []
    stats = collections.Counter()
    scorer = FIScorer()
    for sid, eid, ts, src, msg in scan(paths, verbose=verbose):
        stats[eid] += 1
        short = (src or "unknown")[:16]
        if eid.startswith("cowrie.command."):
            m = _CMD_MSG.match(msg.strip())
            if not m:
                stats["cmd_unparsed"] += 1
                continue
            cmd = m.group(1).strip()
            if not cmd:
                continue
            fi, _how = scorer.score(cmd)
            cmds.append({"instance": INSTANCE, "session_id": sid,
                         "timestamp": _ts(ts), "src_ip": short, "public_ip": short,
                         "agent": "cowrie", "cmd": cmd, "response": None,
                         "fi_score": fi, "latency_ms": None,
                         "technique_id": None, "technique": None, "tactic": None})
        elif eid in ("cowrie.login.success", "cowrie.login.failed"):
            u = _USER.search(msg)
            auths.append({"instance": INSTANCE, "timestamp": _ts(ts),
                          "src_ip": short, "src_port": None,
                          "username": u.group("u") if u else None,
                          "password": u.group("p") if u else None,
                          "auth_type": "password",
                          "event": "login.success" if eid.endswith("success") else "login.failed"})
    return cmds, auths, stats


def purge(path=storage.DB_PATH):
    con = sqlite3.connect(path)
    n1 = con.execute("DELETE FROM sessions WHERE instance=?", (INSTANCE,)).rowcount
    n2 = con.execute("DELETE FROM auth WHERE instance=?", (INSTANCE,)).rowcount
    con.commit(); con.close()
    return n1, n2


def main():
    ap = argparse.ArgumentParser(description="Import CyberLab Cowrie capture into hydrapot.db")
    ap.add_argument("--commit", action="store_true", help="write to the database")
    ap.add_argument("--purge", action="store_true", help="delete a previous CyberLab import first")
    ap.add_argument("--limit", type=int, help="cap command rows (testing)")
    a = ap.parse_args()

    print("Scanning CyberLab datasets…")
    cmds, auths, stats = collect(DATASETS)
    if a.limit:
        cmds = cmds[:a.limit]

    sess = {c["session_id"] for c in cmds}
    ips = {c["src_ip"] for c in cmds}
    fi = collections.Counter(c["fi_score"] for c in cmds)
    span = (min((c["timestamp"] for c in cmds), default="—"),
            max((c["timestamp"] for c in cmds), default="—"))

    print("\n── what will be imported ────────────────────────────────")
    print(f"  command rows   : {len(cmds):,}")
    print(f"  sessions       : {len(sess):,}")
    print(f"  unique sources : {len(ips):,}   (hashed identifiers, not IPs)")
    print(f"  auth rows      : {len(auths):,}")
    print(f"  date range     : {span[0]}  ->  {span[1]}")
    print(f"  FI spread      : " + "  ".join(f"FI{k}={fi[k]:,}" for k in sorted(fi)))
    print("\n  source events seen:")
    for k, v in stats.most_common(8):
        print(f"    {k:34} {v:,}")

    if not a.commit:
        print("\n  DRY RUN — nothing written. Re-run with --commit to apply.")
        return

    if a.purge:
        n1, n2 = purge()
        print(f"\n  purged previous import: {n1:,} sessions rows, {n2:,} auth rows")
    else:
        con = sqlite3.connect(storage.DB_PATH)
        n = con.execute("SELECT COUNT(*) FROM auth WHERE instance=?", (INSTANCE,)).fetchone()[0]
        con.close()
        if n:
            print(f"\n  NOTE: {n:,} CyberLab auth rows already exist and auth has no "
                  f"unique key.\n  Re-run with --purge to avoid duplicating them. "
                  f"Skipping auth import.")
            auths = []

    # One connection and one transaction for the whole import. Calling
    # storage.insert_command() per row would open ~78,000 separate connections
    # and commit ~78,000 times; the same statements batched run in seconds.
    # COLUMNS / AUTH_COLUMNS come from storage, so the schema stays authoritative.
    print("\n  writing…")
    seq = collections.Counter()
    con = sqlite3.connect(storage.DB_PATH)
    try:
        # continue each session's counter from whatever is already stored
        for sid, mx in con.execute(
                "SELECT session_id, MAX(seq) FROM sessions WHERE instance=? GROUP BY session_id",
                (INSTANCE,)):
            seq[sid] = (mx or -1) + 1
        rows = []
        for r in cmds:
            sid = r["session_id"]
            rows.append(tuple({**r, "seq": seq[sid]}.get(c) for c in storage.COLUMNS))
            seq[sid] += 1
        con.executemany(
            f"INSERT OR IGNORE INTO sessions ({','.join(storage.COLUMNS)}) "
            f"VALUES ({','.join('?' * len(storage.COLUMNS))})", rows)
        if auths:
            con.executemany(
                f"INSERT INTO auth ({','.join(storage.AUTH_COLUMNS)}) "
                f"VALUES ({','.join('?' * len(storage.AUTH_COLUMNS))})",
                [tuple(r.get(c) for c in storage.AUTH_COLUMNS) for r in auths])
        con.commit()
    finally:
        con.close()
    print(f"  done: {len(cmds):,} commands, {len(auths):,} auth rows")


if __name__ == "__main__":
    main()
