"""
storage.py — SQLite data layer for session command logs.

Replaces "one JSON file per session, thousands of files per sensor". That
layout had two scaling problems:

  READ  — the dashboard globbed and json.load()ed every file on each cache
          miss (3,811 files / 105 MB today), which blocks for ~300ms and gets
          worse with every new session.
  WRITE — main.py's log() read the whole session file, appended one record,
          and rewrote the whole thing. A 100-command session therefore did 100
          rewrites of a steadily growing file: O(n^2) bytes per session.

Both become a single indexed statement here.

WAL is enabled so the dashboard can read while a sensor is mid-write — that
is what makes near-real-time refresh work without reader/writer blocking.

Rows carry a natural key (instance, session_id, seq) with a UNIQUE index, so
importing the legacy JSON files is idempotent: re-running --migrate can never
double-insert.

    python storage.py --migrate      # import existing data/logs/sessions*/ files
    python storage.py --stats        # row counts per instance
"""

import json
import os
import sqlite3
import glob

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_HERE, "data", "logs", "hydrapot.db")

# Column order used by insert_command(); kept in one place so the writer and
# the migration can't drift apart.
COLUMNS = (
    "instance", "session_id", "seq", "timestamp", "src_ip", "public_ip",
    "agent", "cmd", "response", "fi_score", "latency_ms",
    "technique_id", "technique", "tactic",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    instance     TEXT NOT NULL DEFAULT 'default',
    session_id   TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    timestamp    TEXT,
    src_ip       TEXT,
    public_ip    TEXT,
    agent        TEXT,
    cmd          TEXT,
    response     TEXT,
    fi_score     INTEGER,
    latency_ms   REAL,
    technique_id TEXT,
    technique    TEXT,
    tactic       TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sessions_natural
    ON sessions(instance, session_id, seq);
CREATE INDEX IF NOT EXISTS ix_sessions_timestamp ON sessions(timestamp);
CREATE INDEX IF NOT EXISTS ix_sessions_session   ON sessions(session_id);
CREATE INDEX IF NOT EXISTS ix_sessions_instance  ON sessions(instance);
-- composite, for the live feed's "newest N for ONE sensor". Without it that
-- query filters by instance and then sorts the matches; with it the rows are
-- already in the right order and SQLite just walks back N of them.
CREATE INDEX IF NOT EXISTS ix_sessions_inst_ts   ON sessions(instance, timestamp);
"""


_initialised = set()


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    """A WAL-mode connection. Fresh per call: sqlite3 connections are not
    shareable across threads, and the dashboard serves requests threaded.

    The schema is applied once per process per path — running executescript()
    on every read cost more than the queries themselves."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # WAL-safe, much faster commits
    if path not in _initialised:
        conn.executescript(SCHEMA)
        _initialised.add(path)
    return conn


def init_db(path: str = DB_PATH):
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def insert_command(entry: dict, path: str = DB_PATH):
    """Append one command. `seq` is derived from what's already stored for the
    session, so callers don't have to track a counter."""
    with connect(path) as conn:
        inst = entry.get("instance") or "default"
        sid = str(entry.get("session_id"))
        seq = conn.execute(
            "SELECT COALESCE(MAX(seq), -1) + 1 FROM sessions WHERE instance=? AND session_id=?",
            (inst, sid),
        ).fetchone()[0]
        row = {**entry, "instance": inst, "session_id": sid, "seq": seq}
        conn.execute(
            f"INSERT OR IGNORE INTO sessions ({','.join(COLUMNS)}) "
            f"VALUES ({','.join('?' * len(COLUMNS))})",
            tuple(row.get(c) for c in COLUMNS),
        )


def query_all(path: str = DB_PATH) -> list:
    """Every command, oldest first. Used for the full-dataset dashboard views."""
    try:
        with connect(path) as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM sessions ORDER BY timestamp")]
    except sqlite3.Error:
        return []


# Everything except `response`. That one column is 51.8 MB of a 92 MB table and
# no page render reads it — only the IOC extractor does, and only when the
# "Generate Intelligence" button is pressed. Excluding it here is most of the
# difference between a 460ms load and a 145ms one.
SUMMARY_COLUMNS = (
    "instance", "session_id", "seq", "timestamp", "src_ip", "public_ip",
    "agent", "cmd", "fi_score", "latency_ms",
)


def query_all_df(path: str = DB_PATH, include_response: bool = False):
    """Every command as a DataFrame. Reads straight from the cursor instead of
    materialising 132k dicts first.

    include_response=False by default: see SUMMARY_COLUMNS for why."""
    import pandas as pd
    cols = COLUMNS if include_response else SUMMARY_COLUMNS
    try:
        # Built from plain tuples rather than pd.read_sql_query: same result,
        # ~65ms cheaper at 132k rows because it skips read_sql's per-row
        # adaptation. row_factory is left off for the same reason.
        conn = sqlite3.connect(path, timeout=10)
        try:
            rows = conn.execute(
                f"SELECT {','.join(cols)} FROM sessions ORDER BY timestamp").fetchall()
        finally:
            conn.close()
        return pd.DataFrame(rows, columns=list(cols))
    except Exception:
        return pd.DataFrame()


def query_session(session_id: str, instance: str = None, path: str = DB_PATH) -> list:
    """One session's commands in order, `response` included — the drill-down
    case, where fetching the big column is fine because it's one session."""
    try:
        with connect(path) as conn:
            if instance:
                cur = conn.execute(
                    "SELECT * FROM sessions WHERE session_id=? AND instance=? ORDER BY seq",
                    (str(session_id), instance))
            else:
                cur = conn.execute(
                    "SELECT * FROM sessions WHERE session_id=? ORDER BY seq",
                    (str(session_id),))
            return [dict(r) for r in cur]
    except sqlite3.Error:
        return []


def query_recent(limit: int = 30, instance: str = None, path: str = DB_PATH) -> list:
    """Newest `limit` commands — the live feed's whole job. Uses the timestamp
    index instead of opening files."""
    try:
        with connect(path) as conn:
            if instance and instance != "all":
                cur = conn.execute(
                    "SELECT * FROM sessions WHERE instance=? ORDER BY timestamp DESC LIMIT ?",
                    (instance, limit))
            else:
                cur = conn.execute(
                    "SELECT * FROM sessions ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur]
    except sqlite3.Error:
        return []


def migrate_from_json(session_glob: str = None, path: str = DB_PATH) -> dict:
    """One-off import of the legacy per-session JSON files.

    Idempotent via the (instance, session_id, seq) unique index — running it
    twice inserts nothing the second time. The JSON files are left untouched
    as an archive; the dashboard simply stops reading them."""
    if session_glob is None:
        session_glob = os.path.join(_HERE, "data", "logs", "sessions*", "*.json")

    init_db(path)
    stats = {"files": 0, "rows_seen": 0, "rows_inserted": 0, "unreadable": 0}

    with connect(path) as conn:
        for fp in sorted(glob.glob(session_glob)):
            try:
                with open(fp, encoding="utf-8") as f:
                    rows = json.load(f)
            except Exception:
                stats["unreadable"] += 1
                continue
            if not isinstance(rows, list):
                continue
            stats["files"] += 1

            # seq = position within the file, which is the order the commands
            # were actually run in — the same thing live inserts will produce.
            payload = []
            for seq, r in enumerate(rows):
                stats["rows_seen"] += 1
                row = {**r,
                       "instance": r.get("instance") or "default",
                       "session_id": str(r.get("session_id") or
                                         os.path.basename(fp).replace(".json", "")),
                       "seq": seq}
                payload.append(tuple(row.get(c) for c in COLUMNS))

            before = conn.total_changes
            conn.executemany(
                f"INSERT OR IGNORE INTO sessions ({','.join(COLUMNS)}) "
                f"VALUES ({','.join('?' * len(COLUMNS))})", payload)
            stats["rows_inserted"] += conn.total_changes - before

    return stats


def stats(path: str = DB_PATH) -> dict:
    with connect(path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        per = {r["instance"]: r["n"] for r in conn.execute(
            "SELECT instance, COUNT(*) n FROM sessions GROUP BY instance ORDER BY n DESC")}
        sess = conn.execute("SELECT COUNT(DISTINCT session_id) FROM sessions").fetchone()[0]
    return {"rows": total, "sessions": sess, "per_instance": per}


if __name__ == "__main__":
    import sys
    if "--migrate" in sys.argv:
        s = migrate_from_json()
        print(f"[storage] files read     : {s['files']}")
        print(f"[storage] rows seen      : {s['rows_seen']}")
        print(f"[storage] rows inserted  : {s['rows_inserted']}  (dupes skipped)")
        if s["unreadable"]:
            print(f"[storage] unreadable     : {s['unreadable']}")
    st = stats()
    print(f"[storage] db: {DB_PATH}")
    print(f"[storage] {st['rows']:,} rows across {st['sessions']:,} sessions")
    for k, v in st["per_instance"].items():
        print(f"    {k:<20} {v:>8,}")
