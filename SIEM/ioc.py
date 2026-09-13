"""
SIEM/ioc.py — Threat Intel: on-demand snapshot generation (SIEM-style, not
live).

build_iocs() runs regex extraction over every session row (~11s at 130k+
rows) — far slower than REFRESH_MS (1s), and in a real SIEM, threat intel is
a generated snapshot, not a live-refreshing feed. So this is ONLY ever
invoked by the "Generate Intelligence" button (see pages/threat_intel.py's
generate_intelligence() callback), never on a timer or page-navigation
auto-render.
"""
from datetime import datetime, timedelta

from threat_intel.ioc_extractor import build_iocs

from SIEM.data import load_raw_session_rows, load_auth_log


def _scope_filter_rows(session_rows, auth_rows, scope="all", **scope_kwargs):
    """IOC data-scope filter. Only 'all' does anything meaningful today —
    the other branches are real, working implementations, just not wired to
    any UI control yet — so a future scope selector (Current Session /
    Selected Session / Last 24 Hours) only needs to pass `scope=` (+
    `session_id=`/`cutoff=`) through to build_ioc_snapshot(); no changes
    needed here or in the extraction pipeline itself."""
    if scope == "current_session":
        sid = scope_kwargs.get("session_id")
        session_rows = [r for r in session_rows if r.get("session_id") == sid]
    elif scope == "selected_session":
        sid = scope_kwargs.get("session_id")
        session_rows = [r for r in session_rows if r.get("session_id") == sid]
    elif scope == "last_24h":
        cutoff = scope_kwargs.get("cutoff") or (datetime.now() - timedelta(hours=24))
        def _after_cutoff(r):
            try:
                return datetime.strptime(r.get("timestamp", ""), "%Y-%m-%d %H:%M:%S") >= cutoff
            except (ValueError, TypeError):
                return False
        session_rows = [r for r in session_rows if _after_cutoff(r)]
        auth_rows = [r for r in auth_rows if _after_cutoff(r)]
    # scope == "all" (default): no filtering — every collected session/auth row
    return session_rows, auth_rows


def _resolve_current_session_id(session_rows):
    """'Current session' = the most recently active session_id (newest row by
    timestamp) — this dashboard aggregates many past connections' logs, not
    one live session, so 'current' means 'the latest one seen'."""
    latest_row, latest_ts = None, None
    for r in session_rows:
        try:
            ts = datetime.strptime(r.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue
        if latest_ts is None or ts > latest_ts:
            latest_ts, latest_row = ts, r
    return latest_row.get("session_id") if latest_row else None


def build_ioc_snapshot(scope="all", **scope_kwargs) -> dict:
    """Run the real (expensive) extraction over the requested scope of logs
    and return a snapshot dict — {"recs", "scope", "generated_at"} — meant to
    be stored as-is in the ioc-store and rendered by _render_ioc_body()."""
    session_rows = load_raw_session_rows()
    auth_rows = load_auth_log()
    if scope == "current_session" and "session_id" not in scope_kwargs:
        scope_kwargs["session_id"] = _resolve_current_session_id(session_rows)
    session_rows, auth_rows = _scope_filter_rows(session_rows, auth_rows, scope=scope, **scope_kwargs)
    store = build_iocs(session_rows, auth_rows)
    return {
        "recs": store.records(),
        "scope": scope,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
