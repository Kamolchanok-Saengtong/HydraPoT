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
import functools
import ipaddress
from datetime import datetime, timedelta
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

CREATE TABLE IF NOT EXISTS auth (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    instance   TEXT NOT NULL DEFAULT 'default',
    timestamp  TEXT,
    src_ip     TEXT,
    src_port   INTEGER,
    username   TEXT,
    password   TEXT,
    auth_type  TEXT,
    event      TEXT
);
CREATE INDEX IF NOT EXISTS ix_auth_timestamp ON auth(timestamp);
CREATE INDEX IF NOT EXISTS ix_auth_instance  ON auth(instance, timestamp);

CREATE TABLE IF NOT EXISTS impactful (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    instance     TEXT NOT NULL DEFAULT 'default',
    session_id   TEXT,
    timestamp    REAL,      -- epoch float, as FILogManager records it
    datetime     TEXT,      -- ISO string, same instant
    command      TEXT,
    output       TEXT,
    agent        TEXT,
    fi           INTEGER,
    fi_label     TEXT,
    score_method TEXT       -- rule vs LLM; the one field `sessions` lacks
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_impactful_natural
    ON impactful(session_id, timestamp, command);
CREATE INDEX IF NOT EXISTS ix_impactful_session ON impactful(session_id);
CREATE INDEX IF NOT EXISTS ix_impactful_ts      ON impactful(timestamp);
-- Login attempts have no natural key: the same IP can retry the same
-- credentials in the same second, and those really are distinct events. So
-- dedupe for the one-off JSON import is done by the importer, not by a UNIQUE
-- index that would silently discard real repeats at runtime.

-- Alerts: a detection an analyst is expected to ACT on, with state that
-- outlives a page render. Everything upstream is recomputed from scratch on
-- every window load; this table is the one place the pipeline remembers
-- something a human did.
--
-- alert_key is the natural key and must stay stable across recomputation, or
-- acknowledging an alert would be undone by the next refresh. It is
-- rule_id|link_type|link_value, and every part is derived rather than
-- generated: link_value is the sha1 of a command sequence, or "type:value" for
-- an indicator, or the source address -- the same relationship produces the
-- same key tomorrow. An AUTOINCREMENT id would NOT be stable, which is why the
-- unique index is on (instance, alert_key) and writes are upserts.
--
-- The counted fields are a SNAPSHOT for triage, refreshed on each upsert. They
-- are not the source of truth; correlation is, and re-deriving from it is
-- always correct. Analyst state (state/acknowledged_*/note) is the opposite:
-- it exists nowhere else and is never overwritten by a refresh.
CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    instance         TEXT NOT NULL DEFAULT 'default',
    alert_key        TEXT NOT NULL,
    alert_rule       TEXT,      -- which alert rule promoted it
    detection_rule   TEXT,      -- the detection rule that surfaced it
    link_type        TEXT,      -- the correlation strategy
    link_value       TEXT,
    title            TEXT,
    severity         TEXT,      -- NULL = unrated, never coerced to a level
    member_count     INTEGER,
    distinct_sources INTEGER,
    first_seen       TEXT,      -- of the ACTIVITY, from the relationship
    last_seen        TEXT,
    created_at       TEXT,      -- of the ALERT RECORD; a different question
    updated_at       TEXT,
    state            TEXT NOT NULL DEFAULT 'new',   -- new|acknowledged|closed
    acknowledged_by  TEXT,
    acknowledged_at  TEXT,
    closed_at        TEXT,
    note             TEXT,
    routed_at        TEXT       -- last successful delivery, NULL = never sent
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_natural ON alerts(instance, alert_key);
CREATE INDEX IF NOT EXISTS ix_alerts_state    ON alerts(state);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS ix_alerts_updated  ON alerts(updated_at);

-- Runtime facts the API cannot observe for itself. `hp start` (the SSH
-- honeypot and its sweeper) and `hp dashboard` (uvicorn) are SEPARATE
-- PROCESSES sharing only this file, so a module-global counter in one is
-- invisible to the other. These two tables are that channel.
--
-- A heartbeat, not a status: the writer records when it last ran, and the
-- reader decides whether that is too long ago. A sweeper that died three
-- hours back then reads as stale rather than silently missing.
CREATE TABLE IF NOT EXISTS runtime_health (
    instance   TEXT NOT NULL DEFAULT 'default',
    component  TEXT NOT NULL,
    updated_at TEXT,
    ok         INTEGER,
    detail     TEXT,
    PRIMARY KEY (instance, component)
);

-- Counters for things that happen too often to log one row each, bucketed by
-- hour so "the last hour" is one SELECT and the history is kept for free.
CREATE TABLE IF NOT EXISTS runtime_counters (
    instance TEXT NOT NULL DEFAULT 'default',
    name     TEXT NOT NULL,
    hour     TEXT NOT NULL,          -- 'YYYY-MM-DD HH'
    n        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (instance, name, hour)
);
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


def query_all(path: str = DB_PATH, columns: tuple = None) -> list:
    """Every command, oldest first. Used for full-dataset scans.

    `columns` lets a caller that doesn't need `response` (51.8 MB of a 92 MB
    table, see SUMMARY_COLUMNS below) skip it — same reasoning, applied to
    callers that need SELECT * elsewhere, e.g. aggregator.py's per-session /
    per-time-window scans, which read `technique_id`/`tactic` too so
    SUMMARY_COLUMNS alone isn't enough for them."""
    cols = ",".join(columns) if columns else "*"
    try:
        with connect(path) as conn:
            return [dict(r) for r in conn.execute(
                f"SELECT {cols} FROM sessions ORDER BY timestamp")]
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


def query_range(start: str, end: str, instance: str = None,
                columns: tuple = None, path: str = DB_PATH) -> list:
    """Commands with `start` <= timestamp <= `end`, oldest first.

    `start`/`end` are "YYYY-MM-DD HH:MM:SS" strings — the same format the
    writer stores, so this is a plain indexed string comparison (see
    ix_sessions_timestamp / ix_sessions_inst_ts) rather than a per-row date
    parse. Windowed views must use this instead of filtering query_all() in
    Python: a 15-minute window otherwise pays the cost of loading every row
    in the database to throw almost all of them away.

    `columns` behaves as in query_all()."""
    cols = ",".join(columns) if columns else "*"
    try:
        with connect(path) as conn:
            if instance and instance != "all":
                cur = conn.execute(
                    f"SELECT {cols} FROM sessions "
                    "WHERE timestamp >= ? AND timestamp <= ? AND instance = ? "
                    "ORDER BY timestamp", (start, end, instance))
            else:
                cur = conn.execute(
                    f"SELECT {cols} FROM sessions "
                    "WHERE timestamp >= ? AND timestamp <= ? "
                    "ORDER BY timestamp", (start, end))
            return [dict(r) for r in cur]
    except sqlite3.Error:
        return []


def query_auth_range(start: str, end: str, instance: str = None,
                     path: str = DB_PATH) -> list:
    """Auth events within a time range, oldest first — the auth-table twin of
    query_range(). Separate from query_auth() so its existing callers keep
    their current signature."""
    try:
        with connect(path) as conn:
            if instance and instance != "all":
                cur = conn.execute(
                    "SELECT * FROM auth "
                    "WHERE timestamp >= ? AND timestamp <= ? AND instance = ? "
                    "ORDER BY timestamp", (start, end, instance))
            else:
                cur = conn.execute(
                    "SELECT * FROM auth WHERE timestamp >= ? AND timestamp <= ? "
                    "ORDER BY timestamp", (start, end))
            return [dict(r) for r in cur]
    except sqlite3.Error:
        return []


def time_bounds(instance: str = None, path: str = DB_PATH) -> tuple:
    """(earliest, latest) timestamp across sessions AND auth, or (None, None).

    Used to default an overview's reference time to the newest event that
    actually exists rather than to `now` — this database spans 2019 to today,
    so anchoring presets on the wall clock renders an empty page on any
    historical capture."""
    lo = hi = None
    try:
        with connect(path) as conn:
            for table in ("sessions", "auth"):
                q = f"SELECT MIN(timestamp), MAX(timestamp) FROM {table}"
                args = ()
                if instance and instance != "all":
                    q += " WHERE instance = ?"
                    args = (instance,)
                a, b = conn.execute(q, args).fetchone()
                if a and (lo is None or a < lo):
                    lo = a
                if b and (hi is None or b > hi):
                    hi = b
    except sqlite3.Error:
        return (None, None)
    return (lo, hi)


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


AUTH_COLUMNS = ("instance", "timestamp", "src_ip", "src_port",
                "username", "password", "auth_type", "event")


def insert_auth(entry: dict, path: str = DB_PATH):
    """Append one login attempt / connection event."""
    with connect(path) as conn:
        row = {**entry, "instance": entry.get("instance") or "default"}
        conn.execute(
            f"INSERT INTO auth ({','.join(AUTH_COLUMNS)}) "
            f"VALUES ({','.join('?' * len(AUTH_COLUMNS))})",
            tuple(row.get(c) for c in AUTH_COLUMNS),
        )


def query_auth(instance: str = None, limit: int = None, path: str = DB_PATH) -> list:
    """Login attempts, oldest first — the order the dashboard feed expects."""
    try:
        with connect(path) as conn:
            if limit:
                # newest N, then flipped back into chronological order
                q = "SELECT * FROM auth{} ORDER BY timestamp DESC LIMIT ?"
                args = ([instance, limit] if instance and instance != "all" else [limit])
                cur = conn.execute(q.format(" WHERE instance=?" if len(args) == 2 else ""), args)
                return [dict(r) for r in cur][::-1]
            if instance and instance != "all":
                cur = conn.execute(
                    "SELECT * FROM auth WHERE instance=? ORDER BY timestamp", (instance,))
            else:
                cur = conn.execute("SELECT * FROM auth ORDER BY timestamp")
            return [dict(r) for r in cur]
    except sqlite3.Error:
        return []


def migrate_auth_from_json(auth_glob: str = None, path: str = DB_PATH) -> dict:
    """One-off import of the legacy auth_log*.json files.

    Idempotent by comparing against what is already stored rather than by a
    UNIQUE index — see the schema comment: genuine duplicate login attempts
    must still be insertable at runtime."""
    if auth_glob is None:
        auth_glob = os.path.join(_HERE, "data", "logs", "auth_log*.json")

    init_db(path)
    stats = {"files": 0, "rows_seen": 0, "rows_inserted": 0}

    with connect(path) as conn:
        seen = {tuple(r) for r in conn.execute(
            f"SELECT {','.join(AUTH_COLUMNS)} FROM auth")}
        for fp in sorted(glob.glob(auth_glob)):
            try:
                with open(fp, encoding="utf-8") as f:
                    rows = json.load(f)
            except Exception:
                continue
            if not isinstance(rows, list):
                continue
            stats["files"] += 1
            for r in rows:
                stats["rows_seen"] += 1
                key = tuple({**r, "instance": r.get("instance") or "default"}.get(c)
                            for c in AUTH_COLUMNS)
                if key in seen:
                    continue
                seen.add(key)
                conn.execute(
                    f"INSERT INTO auth ({','.join(AUTH_COLUMNS)}) "
                    f"VALUES ({','.join('?' * len(AUTH_COLUMNS))})", key)
                stats["rows_inserted"] += 1
    return stats


IMPACTFUL_COLUMNS = ("instance", "session_id", "timestamp", "datetime", "command",
                     "output", "agent", "fi", "fi_label", "score_method")


def insert_impactful(entry: dict, path: str = DB_PATH):
    """Append one impactful (FI >= threshold) event.

    INSERT OR IGNORE against the natural key so a retry can't double-record.
    Note this is an audit log only: the H_i the model actually sees comes from
    MemoryPruner's in-memory buffer, never from here."""
    with connect(path) as conn:
        row = {**entry, "instance": entry.get("instance") or "default"}
        conn.execute(
            f"INSERT OR IGNORE INTO impactful ({','.join(IMPACTFUL_COLUMNS)}) "
            f"VALUES ({','.join('?' * len(IMPACTFUL_COLUMNS))})",
            tuple(row.get(c) for c in IMPACTFUL_COLUMNS),
        )


def query_impactful(session_id: str = None, instance: str = None,
                    path: str = DB_PATH) -> list:
    """Impactful events, oldest first; optionally for one session."""
    try:
        with connect(path) as conn:
            where, args = [], []
            if session_id:
                where.append("session_id=?"); args.append(str(session_id))
            if instance and instance != "all":
                where.append("instance=?"); args.append(instance)
            q = "SELECT * FROM impactful"
            if where:
                q += " WHERE " + " AND ".join(where)
            return [dict(r) for r in conn.execute(q + " ORDER BY timestamp", args)]
    except sqlite3.Error:
        return []


def count_impactful(session_id: str = None, path: str = DB_PATH) -> int:
    """Row count — what FILogManager's summary used to get by re-reading a file."""
    try:
        with connect(path) as conn:
            if session_id:
                return conn.execute(
                    "SELECT COUNT(*) FROM impactful WHERE session_id=?",
                    (str(session_id),)).fetchone()[0]
            return conn.execute("SELECT COUNT(*) FROM impactful").fetchone()[0]
    except sqlite3.Error:
        return 0


def migrate_impactful_from_json(imp_glob: str = None, path: str = DB_PATH) -> dict:
    """One-off import of the production impactful logs.

    Deliberately scoped to data/logs/impactful* — the experiment sandbox keeps its own JSON logs
    (experiment_data/results/_direct_fi.json and friends) and must not be touched."""
    if imp_glob is None:
        imp_glob = os.path.join(_HERE, "data", "logs", "impactful*", "*.json")

    init_db(path)
    stats = {"files": 0, "rows_seen": 0, "rows_inserted": 0, "empty": 0}

    with connect(path) as conn:
        for fp in sorted(glob.glob(imp_glob)):
            try:
                with open(fp, encoding="utf-8") as f:
                    rows = json.load(f)
            except Exception:
                continue
            if not isinstance(rows, list):
                continue
            stats["files"] += 1
            if not rows:
                stats["empty"] += 1
                continue
            payload = []
            for r in rows:
                stats["rows_seen"] += 1
                payload.append(tuple({**r, "instance": r.get("instance") or "default"}
                                     .get(c) for c in IMPACTFUL_COLUMNS))
            before = conn.total_changes
            conn.executemany(
                f"INSERT OR IGNORE INTO impactful ({','.join(IMPACTFUL_COLUMNS)}) "
                f"VALUES ({','.join('?' * len(IMPACTFUL_COLUMNS))})", payload)
            stats["rows_inserted"] += conn.total_changes - before
    return stats


# ── Read-only browsing (dashboard "Database" page) ───────────────────────────
#
# Everything below opens the DB through SQLite's own read-only URI mode. That
# is the whole security model: writes are refused by the engine, not by us
# inspecting the SQL. Blocklisting statement keywords is the usual approach and
# it is the wrong one — "SELECT ... " can carry sub-statements, PRAGMA can
# change behaviour, and ATTACH can reach other files. mode=ro makes all of that
# moot: the connection physically cannot modify anything.

MAX_BROWSE_ROWS = 500      # hard cap on rows returned to the browser at once


# ══════════════════════════════════════════════════════════════════════════════
# RETENTION
# ══════════════════════════════════════════════════════════════════════════════
# A honeypot on port 22 takes thousands of hits a day and nothing here ever
# deleted a row. Left alone the database grows until the disk fills and the
# sensor stops recording — silently, which is the worst way for a sensor to
# fail.
#
# DISABLED BY DEFAULT, and deliberately so. This database holds more than live
# traffic: the experiment-sandbox runs and the CyberLab capture live in the same
# tables. CyberLab is from 2019, so a naive "delete anything older than 90
# days" would destroy the only real attacker corpus on the box before it
# touched a single row of noise. Retention must be switched on knowingly, and
# `protect_instances` exists so the rows behind published results can never be
# reached by it.
#
# Always dry-run first: prune(..., dry_run=True) reports exactly what would go.

PRUNE_TABLES = ("sessions", "impactful", "auth")


def prune(retention_days: int = 0,
          max_rows: int = 0,
          protect_instances=(),
          vacuum: bool = True,
          dry_run: bool = True,
          path: str = DB_PATH) -> dict:
    """Delete old rows so the database cannot grow without bound.

    retention_days    delete rows whose timestamp is older than this. 0 = off.
    max_rows          per table, keep only this many newest rows. 0 = off.
    protect_instances instance names that are NEVER deleted, whatever the age.
    vacuum            reclaim the freed pages afterwards. Needs temporary disk
                      roughly equal to the final database size, so it is
                      skipped automatically when free space looks tight.
    dry_run           report what would be deleted and change nothing.

    Returns {table: {"deleted": n, "kept": n}, "vacuum": bool, "dry_run": bool,
             "size_before": bytes, "size_after": bytes}
    """
    out = {"dry_run": dry_run, "vacuum": False,
           "size_before": os.path.getsize(path) if os.path.exists(path) else 0}
    if retention_days <= 0 and max_rows <= 0:
        out["skipped"] = "retention disabled (retention_days and max_rows both 0)"
        out["size_after"] = out["size_before"]
        return out

    protect = tuple(protect_instances or ())
    conn = connect(path)
    try:
        for table in PRUNE_TABLES:
            try:
                total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                continue          # table not present in this database
            where, params = [], []

            if retention_days > 0:
                # The two timestamp formats in this database are NOT
                # interchangeable: sessions/auth store "YYYY-MM-DD HH:MM:SS"
                # strings, impactful stores a UNIX float. SQLite orders every
                # number before every string, so comparing a float column
                # against a date string matched EVERY row — a dry run showed
                # all 49,234 impactful rows queued for deletion regardless of
                # age. Detect the storage type and compare like with like.
                cutoff_dt = datetime.now() - timedelta(days=retention_days)
                probe = conn.execute(
                    f"SELECT timestamp FROM {table} "
                    f"WHERE timestamp IS NOT NULL LIMIT 1").fetchone()
                numeric_ts = bool(probe) and isinstance(probe[0], (int, float))
                if numeric_ts:
                    where.append("CAST(timestamp AS REAL) < ?")
                    params.append(cutoff_dt.timestamp())
                else:
                    where.append("timestamp < ?")
                    params.append(cutoff_dt.strftime("%Y-%m-%d %H:%M:%S"))

            if protect:
                where.append(f"instance NOT IN ({','.join('?' * len(protect))})")
                params.extend(protect)

            if not where:
                deleted = 0
            else:
                sql_where = " AND ".join(where)
                deleted = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {sql_where}", params
                ).fetchone()[0]
                if not dry_run and deleted:
                    conn.execute(f"DELETE FROM {table} WHERE {sql_where}", params)

            # max_rows runs AFTER the age pass, on whatever survived, and also
            # respects protect_instances.
            if max_rows > 0:
                keep_guard = ""
                kp = []
                if protect:
                    keep_guard = f" AND instance NOT IN ({','.join('?' * len(protect))})"
                    kp = list(protect)
                over = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE id NOT IN "
                    f"(SELECT id FROM {table} ORDER BY id DESC LIMIT ?){keep_guard}",
                    [max_rows] + kp).fetchone()[0]
                deleted += over
                if not dry_run and over:
                    conn.execute(
                        f"DELETE FROM {table} WHERE id NOT IN "
                        f"(SELECT id FROM {table} ORDER BY id DESC LIMIT ?){keep_guard}",
                        [max_rows] + kp)

            out[table] = {"deleted": deleted, "kept": total - deleted}
        if not dry_run:
            conn.commit()
    finally:
        conn.close()

    if not dry_run and vacuum:
        # VACUUM rebuilds the file, so it needs free space about the size of
        # the result. Skip rather than risk filling the very disk this is
        # meant to protect.
        try:
            st = os.statvfs(os.path.dirname(path) or ".")
            free = st.f_bavail * st.f_frsize
            if free > out["size_before"] * 1.2:
                c2 = sqlite3.connect(path)
                c2.execute("VACUUM")
                c2.close()
                out["vacuum"] = True
            else:
                out["vacuum_skipped"] = "not enough free disk for VACUUM"
        except Exception as e:
            out["vacuum_skipped"] = f"{type(e).__name__}: {e}"

    out["size_after"] = os.path.getsize(path) if os.path.exists(path) else 0
    return out


def _deny_attach(action, arg1, arg2, db_name, trigger):
    """Authorizer: refuse ATTACH/DETACH, allow everything else.

    mode=ro protects THIS database, but it does not stop ATTACH — a read-only
    connection can still attach any other SQLite file the process can read and
    select out of it. Verified: without this, `ATTACH DATABASE '/tmp/x.db'`
    succeeded. So the file-access hole is closed here, and the write hole by
    mode=ro; neither alone is sufficient."""
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def connect_readonly(path: str = DB_PATH) -> sqlite3.Connection:
    """A connection that cannot write and cannot reach other files. Raises if
    the DB doesn't exist yet (mode=ro will not create one, which is what we
    want)."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.set_authorizer(_deny_attach)
    return conn


def list_tables(path: str = DB_PATH) -> list:
    """[{name, rows}] for each real table, biggest first."""
    try:
        with connect_readonly(path) as conn:
            names = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            out = []
            for n in names:
                # table names come from sqlite_master, never from user input,
                # so this f-string can't be injected through
                cnt = conn.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0]
                out.append({"name": n, "rows": cnt})
            return sorted(out, key=lambda t: -t["rows"])
    except sqlite3.Error:
        return []


def table_schema(table: str, path: str = DB_PATH) -> list:
    """[{name, type, pk}] for one table, or [] if it doesn't exist."""
    try:
        with connect_readonly(path) as conn:
            if not _table_exists(conn, table):
                return []
            return [{"name": r["name"], "type": r["type"] or "", "pk": bool(r["pk"])}
                    for r in conn.execute(f'PRAGMA table_info("{table}")')]
    except sqlite3.Error:
        return []


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone() is not None


def browse_table(table: str, limit: int = 50, offset: int = 0,
                 sort_by: str = None, descending: bool = False,
                 search: str = None, path: str = DB_PATH) -> dict:
    """One page of a table. Returns {columns, rows, total, error}.

    `table` and `sort_by` are validated against the real schema rather than
    interpolated blindly — they can't be parameterised in SQL, so the only safe
    approach is to accept them only if they match something that exists."""
    try:
        with connect_readonly(path) as conn:
            if not _table_exists(conn, table):
                return {"columns": [], "rows": [], "total": 0,
                        "error": f"no such table: {table}"}

            cols = [r["name"] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            where, args = "", []
            if search:
                # match the search across every column, as text
                where = " WHERE " + " OR ".join(
                    f'CAST("{c}" AS TEXT) LIKE ?' for c in cols)
                args = [f"%{search}%"] * len(cols)

            total = conn.execute(
                f'SELECT COUNT(*) FROM "{table}"{where}', args).fetchone()[0]

            order = ""
            if sort_by in cols:                      # ignored unless it's a real column
                order = f' ORDER BY "{sort_by}" ' + ("DESC" if descending else "ASC")

            limit = max(1, min(int(limit), MAX_BROWSE_ROWS))
            rows = [dict(r) for r in conn.execute(
                f'SELECT * FROM "{table}"{where}{order} LIMIT ? OFFSET ?',
                (*args, limit, max(0, int(offset))))]
            return {"columns": cols, "rows": rows, "total": total, "error": None}
    except sqlite3.Error as e:
        return {"columns": [], "rows": [], "total": 0, "error": str(e)}


def run_readonly_query(sql: str, limit: int = MAX_BROWSE_ROWS,
                       path: str = DB_PATH) -> dict:
    """Run an arbitrary query on a read-only connection.

    Any write is rejected by SQLite itself ("attempt to write a readonly
    database"), so this needs no keyword filtering to be safe. The row cap is
    about not shipping 132k rows into the browser, not about security."""
    sql = (sql or "").strip().rstrip(";")
    if not sql:
        return {"columns": [], "rows": [], "error": None, "truncated": False}
    try:
        with connect_readonly(path) as conn:
            cur = conn.execute(sql)
            if cur.description is None:      # e.g. a statement returning nothing
                return {"columns": [], "rows": [], "error": None, "truncated": False}
            cols = [d[0] for d in cur.description]
            rows = [dict(r) for r in cur.fetchmany(limit + 1)]
            truncated = len(rows) > limit
            return {"columns": cols, "rows": rows[:limit],
                    "error": None, "truncated": truncated}
    # sqlite3.Warning (raised for "only one statement at a time") is NOT a
    # subclass of sqlite3.Error, so catching Error alone let it escape as a
    # 500. Any failure here is user-supplied SQL going wrong: report it in the
    # UI, never crash the page.
    except Exception as e:
        return {"columns": [], "rows": [], "error": str(e), "truncated": False}


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


# ── what counts as real attacker traffic ────────────────────────────────────
# The DB holds real honeypot traffic and experiment-sandbox runs in the SAME
# tables. Harnesses put a run label in src_ip ("hrreplay_27765", "eval_sync_on")
# where real traffic has an IP, so the label is what separates them.
#
# THIS LIVES HERE, not in SIEM/data.py where it started, because it is not a
# presentation rule. Every layer that reads rows needs the same answer, and the
# ones that did not have it were shipping 83% harness traffic: /export sent
# replayed corpus to external SIEMs as observed telemetry, and /threats/iocs
# reported 72 indicators this honeypot never saw. storage.py is the one module
# all of them already import, and it pulls in no pandas.
#
# Presentation-only in effect: nothing is deleted, the sandbox's own scripts
# still read every row.

EXPERIMENT_SRC_PREFIXES = (
    "eval", "parta_", "partb_", "partc_", "hrreplay_", "bench",
    "ml4net", "quickcheck", "cloudcheck", "sanity", "smoke", "replay",
)

# Harness rows whose src_ip is a bare token rather than a prefixed label
# ("t", "x", "t1", "test"). Matched by SHAPE, not a growing list of literals: a
# real source is either a dotted IP or CyberLab's 16-char hashed identifier, so
# anything non-numeric and shorter than 6 characters is a label somebody typed.
# The public resolvers appear as test TARGETS; none of them ever opens an SSH
# connection to a honeypot.
HARNESS_TOKEN_MAXLEN = 5
EXPERIMENT_SRC_EXACT = {"localhost", "-", "", "8.8.8.8", "8.8.4.4",
                        "1.1.1.1", "9.9.9.9"}

# NOTE: "cyberlab" is deliberately NOT a prefix. The CyberLab Cowrie capture is
# imported as real sensor traffic (instance="CyberLab", src_ip = the dataset's
# hashed attacker id), so filtering on that string would hide the only genuine
# attacker data there is.


def _is_non_routable(value) -> bool:
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return False        # a hashed identifier is not an IP; keep it
    return not addr.is_global


@functools.lru_cache(maxsize=8192)
def is_experiment_ip(ip: str) -> bool:
    """The whole harness test, keyed on src_ip alone.

    Memoised because addresses repeat enormously: a sensor switch ran this
    78,208 times over 766 distinct IPs, and re-parsing each was 0.49s of pure
    repeat work.
    """
    if ip.startswith(EXPERIMENT_SRC_PREFIXES):
        return True
    if ip.lower() in EXPERIMENT_SRC_EXACT:
        return True
    if len(ip) <= HARNESS_TOKEN_MAXLEN and "." not in ip:
        return True
    return _is_non_routable(ip)


def is_experiment_row(row) -> bool:
    """One row. THE definition -- every caller uses this one, so two endpoints
    can never disagree about what real traffic is."""
    return is_experiment_ip(str(row.get("src_ip") or ""))


def real_rows(rows):
    """Drop harness traffic. What every read path should go through."""
    return [r for r in rows if not is_experiment_row(r)]


# ── runtime health & counters ────────────────────────────────────────────────
# Written by the honeypot process, read by the API process. See the two table
# definitions in SCHEMA for why this goes through the database at all.
#
# Every function here swallows its own failures. These are diagnostics: losing
# a heartbeat must never take down the thing it was reporting on.

def record_health(component: str, ok: bool, detail: str = None,
                  instance: str = "default", path: str = DB_PATH) -> None:
    """Upsert one component's heartbeat. Called by whoever owns the work."""
    try:
        with connect(path) as conn:
            conn.execute(
                """INSERT INTO runtime_health (instance, component, updated_at, ok, detail)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(instance, component) DO UPDATE SET
                       updated_at = excluded.updated_at,
                       ok         = excluded.ok,
                       detail     = excluded.detail""",
                (instance, component, _now_iso(), 1 if ok else 0, detail))
    except Exception:
        pass


def read_health(instance: str = "default", path: str = DB_PATH) -> dict:
    """-> {component: {"ok", "detail", "updated_at", "age_sec"}}.

    `age_sec` is the point of this table: the caller needs to distinguish a
    component reporting healthy a second ago from the same row left behind by
    a process that died.
    """
    out = {}
    try:
        with connect(path) as conn:
            rows = conn.execute(
                "SELECT * FROM runtime_health WHERE instance = ?",
                (instance,)).fetchall()
    except Exception:
        return out
    now = datetime.now()
    for r in rows:
        try:
            stamp = datetime.fromisoformat(r["updated_at"])
        except (TypeError, ValueError):
            stamp = None
        out[r["component"]] = {
            "ok": bool(r["ok"]),
            "detail": r["detail"],
            "updated_at": r["updated_at"],
            "age_sec": int((now - stamp).total_seconds()) if stamp else None,
        }
    return out


def bump_counter(name: str, instance: str = "default", when=None,
                 path: str = DB_PATH) -> None:
    """Add one to this hour's bucket for `name`."""
    hour = (when or datetime.now()).strftime("%Y-%m-%d %H")
    try:
        with connect(path) as conn:
            conn.execute(
                """INSERT INTO runtime_counters (instance, name, hour, n)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(instance, name, hour) DO UPDATE SET n = n + 1""",
                (instance, name, hour))
    except Exception:
        pass


def counter_total(name: str, hours: int = 1, instance: str = "default",
                  path: str = DB_PATH) -> int:
    """Sum of `name` over the last `hours` hourly buckets, this one included.

    Measured from the wall clock, unlike the aggregation windows elsewhere:
    this asks "is the system sick RIGHT NOW", so an imported 2019 corpus is
    exactly what it should report zero for.
    """
    now = datetime.now()
    wanted = [(now - timedelta(hours=h)).strftime("%Y-%m-%d %H")
              for h in range(max(1, hours))]
    try:
        with connect(path) as conn:
            marks = ",".join("?" * len(wanted))
            row = conn.execute(
                f"""SELECT COALESCE(SUM(n), 0) AS total FROM runtime_counters
                    WHERE instance = ? AND name = ? AND hour IN ({marks})""",
                (instance, name, *wanted)).fetchone()
        return int(row["total"])
    except Exception:
        return 0


def db_writable(path: str = DB_PATH) -> bool:
    """Can we actually WRITE, not merely read?

    A full disk, a read-only mount or a stale WAL lock all leave SELECT
    working while every INSERT fails -- which is the shape of outage where a
    honeypot keeps answering attackers and silently records none of it.
    Writes to runtime_health rather than to a real table, so the probe never
    pollutes the data it is checking on.
    """
    try:
        record_health("_probe", True, "write check", path=path)
        with connect(path) as conn:
            conn.execute("DELETE FROM runtime_health WHERE component = '_probe'")
        return True
    except Exception:
        return False


# ── alerts ───────────────────────────────────────────────────────────────────
# The alert record is a JOIN of two things with different lifetimes:
#   * facts, recomputed from correlation every refresh
#   * analyst state, which exists only here and must survive every refresh
# Every function below exists to keep that line from being crossed.

ALERT_STATES = ("new", "acknowledged", "closed")


def upsert_alert(alert: dict, path: str = DB_PATH) -> str:
    """Insert a new alert, or refresh the FACTS of one already known.

    -> "inserted" | "updated"

    The ON CONFLICT clause deliberately updates only the counted/snapshot
    columns. state, acknowledged_by, acknowledged_at, closed_at, note and
    routed_at are NOT in the update list: re-running the pipeline must never
    un-acknowledge an alert a human has already worked, and a re-render happens
    every few minutes. That omission is the whole point of this function.
    """
    now = _now_iso()
    inst = alert.get("instance") or "default"
    with connect(path) as conn:
        # Asked BEFORE the write, not inferred after it. Comparing created_at
        # to "now" looked equivalent and was wrong: timestamps here have
        # one-second resolution, so two upserts in the same second made an
        # update indistinguishable from an insert -- and routing, which fires
        # on new alerts, would have re-sent an alert on every refresh.
        existed = conn.execute(
            "SELECT 1 FROM alerts WHERE instance=? AND alert_key=?",
            (inst, alert["alert_key"])).fetchone() is not None
        conn.execute(
            """
            INSERT INTO alerts (instance, alert_key, alert_rule, detection_rule,
                                link_type, link_value, title, severity,
                                member_count, distinct_sources, first_seen,
                                last_seen, created_at, updated_at, state)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new')
            ON CONFLICT(instance, alert_key) DO UPDATE SET
                alert_rule       = excluded.alert_rule,
                detection_rule   = excluded.detection_rule,
                title            = excluded.title,
                severity         = excluded.severity,
                member_count     = excluded.member_count,
                distinct_sources = excluded.distinct_sources,
                -- COALESCE guards: SQLite's scalar MIN/MAX return NULL if
                -- ANY argument is NULL, so min(NULL, '2019-08-05') is NULL --
                -- a refresh would erase a timestamp it was meant to widen.
                first_seen       = MIN(COALESCE(alerts.first_seen, excluded.first_seen),
                                       COALESCE(excluded.first_seen, alerts.first_seen)),
                last_seen        = MAX(COALESCE(alerts.last_seen, excluded.last_seen),
                                       COALESCE(excluded.last_seen, alerts.last_seen)),
                updated_at       = excluded.updated_at
            """,
            (inst, alert["alert_key"], alert.get("alert_rule"),
             alert.get("detection_rule"), alert.get("link_type"),
             alert.get("link_value"), alert.get("title"), alert.get("severity"),
             alert.get("member_count"), alert.get("distinct_sources"),
             alert.get("first_seen"), alert.get("last_seen"), now, now))
    return "updated" if existed else "inserted"


def set_alert_state(alert_key: str, state: str, instance: str = "default",
                    by: str = None, note: str = None,
                    path: str = DB_PATH) -> bool:
    """Move an alert through its lifecycle. -> True if a row changed.

    Timestamps are written for the transition that actually happened rather
    than blanket-stamped: acknowledging sets acknowledged_*, closing sets
    closed_at, and reopening (back to "new") CLEARS both, so a reopened alert
    does not carry a stale "closed 3 days ago" beside an open state.
    """
    if state not in ALERT_STATES:
        raise ValueError(f"state must be one of {list(ALERT_STATES)}, got {state!r}")
    now = _now_iso()
    sets = ["state = ?", "updated_at = ?"]
    args = [state, now]
    if state == "acknowledged":
        sets += ["acknowledged_by = ?", "acknowledged_at = ?"]
        args += [by, now]
    elif state == "closed":
        sets.append("closed_at = ?")
        args.append(now)
    else:                       # reopened
        sets += ["acknowledged_by = NULL", "acknowledged_at = NULL",
                 "closed_at = NULL"]
    if note is not None:
        sets.append("note = ?")
        args.append(note)
    args += [instance, alert_key]
    with connect(path) as conn:
        cur = conn.execute(
            f"UPDATE alerts SET {', '.join(sets)} "
            f"WHERE instance = ? AND alert_key = ?", args)
        return cur.rowcount > 0


def mark_alert_routed(alert_key: str, instance: str = "default",
                      path: str = DB_PATH) -> bool:
    """Stamp a successful delivery. Only ever set AFTER a sink reports success,
    so a failed send leaves routed_at NULL and the alert is retried rather than
    silently dropped."""
    with connect(path) as conn:
        cur = conn.execute(
            "UPDATE alerts SET routed_at = ? WHERE instance = ? AND alert_key = ?",
            (_now_iso(), instance, alert_key))
        return cur.rowcount > 0


def query_alerts(state=None, severity=None, instance=None, unrouted_only=False,
                 limit: int = 500, path: str = DB_PATH) -> list:
    """Alerts, newest activity first. Every filter is optional."""
    where, args = [], []
    if state:
        where.append("state = ?")
        args.append(state)
    if severity:
        where.append("severity = ?")
        args.append(severity)
    if instance and instance != "all":
        where.append("instance = ?")
        args.append(instance)
    if unrouted_only:
        where.append("routed_at IS NULL")
    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    # COALESCE so an alert whose activity has no timestamp still sorts by when
    # the record was made, instead of sinking below everything.
    sql += " ORDER BY COALESCE(last_seen, updated_at) DESC LIMIT ?"
    args.append(limit)
    with connect(path) as conn:
        return [dict(r) for r in conn.execute(sql, args)]


def get_alert(alert_key: str, instance: str = "default", path: str = DB_PATH):
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE instance=? AND alert_key=?",
                           (instance, alert_key)).fetchone()
        return dict(row) if row else None


def alert_counts(instance=None, path: str = DB_PATH) -> dict:
    """{state: n} for the UI's triage filters, counted in SQL rather than by
    pulling every row back and len()-ing it in Python."""
    sql = "SELECT state, COUNT(*) n FROM alerts"
    args = []
    if instance and instance != "all":
        sql += " WHERE instance = ?"
        args.append(instance)
    sql += " GROUP BY state"
    with connect(path) as conn:
        return {r["state"]: r["n"] for r in conn.execute(sql, args)}


def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    import sys
    if "--migrate" in sys.argv:
        s = migrate_from_json()
        print(f"[storage] files read     : {s['files']}")
        print(f"[storage] rows seen      : {s['rows_seen']}")
        print(f"[storage] rows inserted  : {s['rows_inserted']}  (dupes skipped)")
        if s["unreadable"]:
            print(f"[storage] unreadable     : {s['unreadable']}")
        a = migrate_auth_from_json()
        print(f"[storage] auth files     : {a['files']}")
        print(f"[storage] auth inserted  : {a['rows_inserted']} of {a['rows_seen']} seen")
        m = migrate_impactful_from_json()
        print(f"[storage] impactful files: {m['files']} ({m['empty']} empty)")
        print(f"[storage] impactful rows : {m['rows_inserted']} of {m['rows_seen']} seen")
    st = stats()
    print(f"[storage] db: {DB_PATH}")
    print(f"[storage] {st['rows']:,} rows across {st['sessions']:,} sessions")
    for k, v in st["per_instance"].items():
        print(f"    {k:<20} {v:>8,}")
