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

    Deliberately scoped to data/logs/impactful* — NSC keeps its own JSON logs
    (NSC/results/_direct_fi.json and friends) and must not be touched."""
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
# traffic: the NSC experiment runs and the CyberLab capture live in the same
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
