"""
api/services/console_views.py — the application layer behind api/v1/bridge.py.

The console v2 (Next.js) needs views the original v1 resources did not expose:
the live feed, a geo rollup, the attention queue, the attack timeline, ATT&CK
tactic counts, top credentials, the database explorer (schema + read-only SQL),
a STIX bundle, component health, the AI analyst, and the investigation
workbench.

Every function here reuses the SAME data layer the Dash dashboard uses --
console.data, console.geo, console.investigation, console.ioc and core.storage
-- so the v2 UI shows exactly what the Dash app showed. No new aggregation is
invented here; this module is where the shaping/validation/masking logic lives
so the routes in bridge.py stay thin (parse -> one call -> return).
"""
import os

from core import storage

# since (15m/1h/24h/7d/all) -> the preset string console.data expects.
_PRESET = {"15m": "15m", "1h": "1h", "24h": "24h", "7d": "7d", "all": "ALL"}

# Secret columns in the access DB -- masked in query results, never sent raw.
_DB_MASK = {"password_hash", "token_hash", "value", "session_secret"}
_MASK = "•" * 8


def _preset(since):
    return _PRESET.get((since or "all").lower(), "ALL")


def _instance(instance):
    """The instance filter console.data expects: None means every sensor."""
    return None if instance in (None, "all") else instance


def _fi(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ─── live feed ───────────────────────────────────────────────────────────────

def feed(instance=None, limit=50, since=None):
    """Newest commands + recent auth attempts, as feed lines -- the same stream
    the Dash terminal renders (console.data.load_feed_rows).

    `since` bounds the window: the feed is a slice of the command/auth stream,
    which the aggregation layer does not window for us, so it is applied here
    (window_filter, same newest-row anchor as the rest of v1)."""
    from console.data import load_feed_rows
    from api.services.common import window_filter
    inst = _instance(instance)
    rows = window_filter(load_feed_rows(inst, limit=limit), since, "timestamp")
    out = []
    # recent logins first (SCAN / LOGIN lines in the Dash feed)
    try:
        with storage.connect_readonly(storage.DB_PATH) as conn:
            where = "" if inst is None else " WHERE instance=?"
            args = () if inst is None else (inst,)
            auth = conn.execute(
                f"SELECT timestamp, src_ip, username, password, auth_type "
                f"FROM auth{where} ORDER BY id DESC LIMIT 10", args).fetchall()
        for a in reversed(window_filter([dict(r) for r in auth], since,
                                        "timestamp")):
            ts = str(a.get("timestamp") or "")[11:19]
            if a.get("auth_type") == "tcp_connect":
                out.append({"ts": ts, "ip": a.get("src_ip", "?"),
                            "cmd": "TCP connection (port probe)", "fi": 3,
                            "agent": "unknown", "kind": "login"})
            else:
                out.append({"ts": ts, "ip": a.get("src_ip", "?"),
                            "cmd": f"{a.get('username','?')}:{a.get('password','?')}",
                            "fi": 1, "agent": "unknown", "kind": "login"})
    except Exception:
        pass
    for r in rows:
        ts = str(r.get("timestamp") or "")[11:19]
        out.append({"ts": ts, "ip": r.get("src_ip", "?"),
                    "cmd": str(r.get("cmd") or "")[:200],
                    "fi": _fi(r.get("fi_score")),
                    "agent": r.get("agent") or "unknown", "kind": "cmd"})
    return out


# ─── overview-derived views ──────────────────────────────────────────────────

def geo_rollup(instance=None, limit=500, since=None):
    """Distinct recent source IPs rolled up by country (console.geo). `since`
    bounds the window the same way /feed does (window_filter)."""
    from console.geo import geolocate
    from api.services.common import window_filter
    rows = window_filter(storage.query_recent(limit, instance=_instance(instance)),
                         since, "timestamp")
    counts = {}
    for r in rows:
        ip = r.get("src_ip")
        if not ip:
            continue
        g = geolocate(ip)
        if not g:
            continue
        name = g.get("country") or "Unknown"
        c = counts.setdefault(name, {"name": name,
                                     "code": g.get("country_code") or "",
                                     "count": 0})
        c["count"] += 1
    return sorted(counts.values(), key=lambda x: -x["count"])


def attention_queue(since=None, instance=None, limit=20):
    """Highest-interaction sessions in the window -- the same list the Summary
    page's attention queue ranks."""
    from console.data import load_overview
    o = load_overview(_preset(since), _instance(instance))
    sessions = (o or {}).get("sessions") or []
    ranked = sorted(sessions, key=lambda s: -(s.get("technique_count") or 0))
    return [{
        "session_id": s.get("session_id"),
        "ip": s.get("src_ip", "?"),
        "score": s.get("technique_count") or 0,
        "chain": list(s.get("tactics") or []),
        "techniques": list(s.get("technique_ids") or []),
    } for s in ranked[:limit]]


def attack_series(since=None, instance=None):
    """The command-timeline buckets from the aggregation overview."""
    from console.data import load_overview
    o = load_overview(_preset(since), _instance(instance))
    return [{"t": b.get("bucket_start"), "attacks": b.get("commands") or 0}
            for b in ((o or {}).get("timeline") or [])]


def tactic_counts(since=None, instance=None):
    """ATT&CK tactic counts, sorted, from the MITRE activity service."""
    from api import services as svc
    m = svc.mitre_activity(since, instance)
    return [{"tactic": k, "count": v}
            for k, v in sorted((m.get("tactics") or {}).items(),
                               key=lambda kv: -kv[1])]


def top_credentials(instance=None, limit=8):
    """Most-tried usernames and passwords from the auth table."""
    inst = _instance(instance)
    where = "" if inst is None else " WHERE instance=?"
    args = () if inst is None else (inst,)

    def top(col):
        try:
            with storage.connect_readonly(storage.DB_PATH) as conn:
                rows = conn.execute(
                    f"SELECT {col} AS v, COUNT(*) AS n FROM auth"
                    f"{where}{' AND' if where else ' WHERE'} {col} IS NOT NULL "
                    f"GROUP BY {col} ORDER BY n DESC LIMIT ?",
                    (*args, limit)).fetchall()
            return [{"label": r["v"], "n": r["n"]} for r in rows]
        except Exception:
            return []

    return {"usernames": top("username"), "passwords": top("password")}


# ─── database explorer (schema + read-only SQL) ──────────────────────────────

def _explorer_dbs():
    """The two databases the explorer browses: (key, path, label)."""
    from console import auth
    return [("capture", storage.DB_PATH, "Capture data"),
            ("login", auth.session_db_path(), "Dashboard access")]


def _explorer_path(db):
    for key, path, _label in _explorer_dbs():
        if key == db:
            return path
    return storage.DB_PATH


def db_schema():
    """Tables + columns for BOTH databases the explorer browses: the capture DB
    and the dashboard access DB (operator accounts/sessions), like the Dash
    explorer. Returns [{db, file, label, tables:[{table, columns}]}]."""
    out = []
    for key, path, label in _explorer_dbs():
        tables = []
        try:
            for t in storage.list_tables(path=path):
                cols = [c["name"] for c in storage.table_schema(t["name"], path=path)]
                tables.append({"table": t["name"], "columns": cols})
        except Exception:
            pass
        out.append({"db": key, "file": os.path.basename(path),
                    "label": label, "tables": tables})
    return out


def _validate_select(sql, tables):
    """Accept ONLY a single read-only SELECT, parsed rather than regex-sniffed.

    Comments are stripped, the text is split into statements on semicolons that
    are not inside quotes, and exactly one statement must remain. That statement
    must begin with SELECT or WITH, and every table it names after FROM/JOIN
    must exist in sqlite_master (passed in as `tables`). Returns an error
    string, or None when the query is allowed. (The connection is still opened
    mode=ro, so this is validation for clear errors, not the only guard.)
    """
    import re
    s = re.sub(r"--[^\n]*", " ", sql)
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    stmts, buf, quote = [], [], None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
            buf.append(ch)
        elif ch == ";":
            if "".join(buf).strip():
                stmts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if "".join(buf).strip():
        stmts.append("".join(buf).strip())
    if len(stmts) != 1:
        return "only a single statement is allowed"
    stmt = stmts[0]
    head = (stmt.split(None, 1)[0] if stmt.split() else "").lower()
    if head not in ("select", "with"):
        return "only SELECT is allowed (read-only)"
    known = {t.lower() for t in tables}
    # CTE names (WITH a AS (...), b AS (...)) are valid "tables" too
    known |= {c.lower() for c in
              re.findall(r'(?:\bwith\b|,)\s*([A-Za-z_]\w*)\s+as\s*\(', stmt, re.I)}
    for m in re.finditer(r'\b(?:from|join)\s+["\'`]?([A-Za-z_]\w*)', stmt, re.I):
        if m.group(1).lower() not in known:
            return f"no such table: {m.group(1)}"
    return None


def run_query(sql, db="capture"):
    """The Database page's grid/console. A single SELECT only (validated), run
    on a mode=ro connection with ATTACH blocked. For the access DB, secret
    columns are masked before anything leaves here. Returns {columns, rows} or
    {columns:[], rows:[], error}."""
    path = _explorer_path(db)
    tables = [t["name"] for t in storage.list_tables(path=path)]
    err = _validate_select(sql, tables)
    if err:
        return {"columns": [], "rows": [], "error": err}
    res = storage.run_readonly_query(sql, path=path)
    if res.get("error"):
        return {"columns": [], "rows": [], "error": res["error"]}
    cols = res.get("columns") or []
    mask = _DB_MASK if db == "login" else set()
    rows = [[(_MASK if (c in mask and r.get(c) not in (None, "")) else r.get(c))
             for c in cols] for r in (res.get("rows") or [])]
    return {"columns": cols, "rows": rows}


# ─── STIX export ─────────────────────────────────────────────────────────────

def stix_bundle():
    """The IOC export the Dash threat-intel 'Export STIX' button produced: the
    real extraction (console.ioc.build_ioc_snapshot) rendered as a STIX 2.1
    bundle (threat_intel.ioc_extractor.to_stix). Scope is 'all' -- the
    extraction layer has no per-sensor scope to honor an instance filter."""
    import json
    import tempfile
    from console.ioc import build_ioc_snapshot
    from threat_intel.ioc_extractor import to_stix
    snap = build_ioc_snapshot(scope="all")
    recs = snap.get("recs") or []
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        to_stix(recs, path)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ─── component health, assistant, investigation ──────────────────────────────

def agent_health_rows():
    """The per-component health the Dash sidebar's status panel shows
    (console.data.agent_health): the SSH front door and each agent, each a real
    probe -- not the /health summary's database/collector view."""
    from console.data import agent_health
    return [{"name": n, "ok": bool(ok), "detail": d}
            for (n, ok, d) in agent_health()]


def ask_assistant(payload):
    """The AI analyst the dashboard's assistant widget talks to -- the same
    api.assistant.ask() the Dash chat used. Returns
    {answer, tools, error, unavailable}."""
    from api.assistant import ask
    question = str((payload or {}).get("question") or "").strip()
    history = (payload or {}).get("history") or []
    if not question:
        return {"answer": "", "tools": [], "error": "empty question"}
    return ask(question, history)


def investigation(since=None, instance=None):
    """The exact investigation data the Dash page builds:
    console.investigation.build_investigation() over the same detections +
    overview inputs."""
    from console.data import load_overview, load_detections
    from console.investigation import build_investigation
    inst = _instance(instance)
    preset = _preset(since)
    detect = load_detections(preset, inst)
    over = load_overview(preset, inst)
    data = build_investigation(detect, over, inst)
    queue = data.get("queue") or []
    # the UI's Commands tab reads item["commands"]; build_investigation calls
    # that list "sample" (the shared command sequence) -- expose it under both.
    for it in queue:
        it["commands"] = [{"cmd": c, "ts": "", "technique": None}
                          for c in (it.get("sample") or [])]
    # drop the heavy raw detection payload; the UI reads summary + queue
    return {"summary": data.get("summary") or {}, "queue": queue}
