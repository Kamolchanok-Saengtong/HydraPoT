"""
app.py — HydraPoT SIEM Dashboard (Plotly Dash)
Layout: live terminal | metric cards | world map | events over time | summary table

pip install dash plotly pandas geoip2
"""

import glob
import json
import os
import time
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from dash import Dash, html, dcc, Input, Output, State, ctx, ALL, dash_table
from dash.exceptions import PreventUpdate

from threat_intel.ioc_extractor import build_iocs, to_stix
from threat_intel.mitre_mapper import tag as _mitre_tag
import storage

# ── Config ────────────────────────────────────────────────────────────────────

SESSION_DIR  = "data/logs/sessions"
AUTH_LOG     = "data/logs/auth_log.json"
REFRESH_MS   = 5000    # safe again: the tick now refreshes ONLY the live feed
                       # (build_live_feed), not the whole page's figures
LOGO_PATH    = os.path.join(_HERE, "production", "logo.png")
MMDB_PATH    = os.path.join(_HERE, "geoip.mmdb")
MAX_SESSION_FILES = 7000

# ── Live cost/energy estimation constants ──────────────────────────────────────
# Production session logs record `agent` + `latency_ms` per command, but NOT
# tokens/cost (cost capture is off in the real run). So the dashboard ESTIMATES:
#
#   on-device electricity  — from the REAL logged latency_ms of on_device
#     commands (GPU busy time) x measured avg draw, converted via config.yaml's
#     MEA tariff. This is a genuine per-command estimate, not a flat guess.
#   cloud cost             — logs have no token count, so this is (# cloud
#     commands) x a per-cloud-command $ rate measured in Part C. Coarser, but
#     the only signal available live. Both are clearly labelled "(est.)".
#
# Numbers below come from Part C measurement (see NSC/PartC/results/…):
#   avg GPU draw during on_device inference : 112.89 W  (utilization-scaled;
#     this GPU's driver reports power.draw as N/A — see estimate_electricity_bill.py)
#   avg cloud $ per cloud-routed command    : $0.0301 / 67 cmds ≈ $0.000449
GPU_AVG_WATT              = 112.89
CLOUD_COST_PER_CLOUD_CMD  = 0.0301 / 67
# A single on_device inference can't realistically exceed ~2 min of GPU time.
# Some log records carry corrupt latency_ms (e.g. 1.7e9 ms ≈ 495 h — a bad
# t_start / timing artifact); left unclamped, a handful of these dominate the
# whole energy sum (~100x inflation). Cap each command's contribution here.
LATENCY_CAP_MS            = 120_000

try:
    import sys as _sys
    if os.path.join(_HERE, "NSC", "PartA") not in _sys.path:
        _sys.path.insert(0, os.path.join(_HERE, "NSC", "PartA"))
    from power_cost import kwh_to_thb as _kwh_to_thb
    from config_loader import load_config as _load_config
    _POWER_TARIFF = _load_config().power_tariff
except Exception:
    _kwh_to_thb = None
    _POWER_TARIFF = None


def estimate_costs(df):
    """Live cost/energy estimates scoped to the CURRENT CALENDAR MONTH — so a
    SOC team reads "what is this honeypot costing this month" at a glance.
    Month-to-date is the actual accrued figure; on_device_thb_projected
    extrapolates to a full month at the current rate. Monthly scoping also
    matches how MEA's progressive tariff is actually billed (per month of kWh).
    Safe on empty/missing columns."""
    import calendar
    out = {"cloud_cost_usd": 0.0, "on_device_kwh": 0.0, "on_device_thb": 0.0,
           "on_device_thb_projected": 0.0, "projection_ready": False,
           "n_cloud": 0, "n_on_device": 0,
           "month_label": datetime.now().strftime("%b %Y")}
    if df is None or df.empty or "agent" not in df.columns:
        return out

    # scope to the current calendar month via timestamp (fall back to all rows
    # if there's no usable timestamp column, so the cards never go blank)
    mdf = df
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        now = datetime.now()
        ts = df["timestamp"]
        mdf = df[(ts.dt.year == now.year) & (ts.dt.month == now.month)]

    cloud_mask = mdf["agent"] == "cloud"
    od_mask    = mdf["agent"] == "on_device"
    out["n_cloud"]     = int(cloud_mask.sum())
    out["n_on_device"] = int(od_mask.sum())
    out["cloud_cost_usd"] = out["n_cloud"] * CLOUD_COST_PER_CLOUD_CMD

    if "latency_ms" in mdf.columns:
        # clamp per-command latency to exclude corrupt outlier records
        od_latency_ms = float(
            mdf.loc[od_mask, "latency_ms"].fillna(0).clip(upper=LATENCY_CAP_MS).sum()
        )
        hours = od_latency_ms / 1000.0 / 3600.0
        out["on_device_kwh"] = GPU_AVG_WATT * hours / 1000.0
        if _kwh_to_thb and _POWER_TARIFF:
            out["on_device_thb"] = _kwh_to_thb(out["on_device_kwh"], _POWER_TARIFF)["total_thb"]

        # project month-to-date -> full month at the current daily rate.
        # Require at least ~1 full day of the month elapsed before projecting:
        # very early in a month the elapsed fraction is near-zero and dividing
        # by it produces a wildly inflated (meaningless) projection. Until then
        # we simply don't project (the card shows the projection as n/a).
        now = datetime.now()
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        elapsed_days = (now.day - 1) + now.hour / 24.0
        if elapsed_days >= 1.0 and _kwh_to_thb and _POWER_TARIFF:
            proj_kwh = out["on_device_kwh"] * (days_in_month / elapsed_days)
            out["on_device_thb_projected"] = _kwh_to_thb(proj_kwh, _POWER_TARIFF)["total_thb"]
            out["projection_ready"] = True
        else:
            out["projection_ready"] = False
    return out

FI_LABEL = {0:"Read/Display", 1:"Create/Install", 2:"Modify/Navigate",
            3:"Service/Elevate", 4:"High Impact"}
FI_COLOR = {0:"#6c757d", 1:"#0d6efd", 2:"#ffc107", 3:"#fd7e14", 4:"#dc3545"}
AGENT_COLOR = {"cowrie":"#28a745","on_device":"#ffc107","cloud":"#dc3545","unknown":"#6c757d"}
THREAT_LEVEL = {
    0:("LOW","#28a745","🟢"), 1:("LOW","#28a745","🟢"),
    2:("MEDIUM","#ffc107","🟡"), 3:("HIGH","#fd7e14","🟠"),
    4:("CRITICAL","#dc3545","🔴"),
}

# ── HydraPoT design tokens (matches landing page) ──────────────────────────────

INK         = "#1A1410"
INK_2       = "#3A2E20"
INK_3       = "#6B5A45"
PAPER       = "#FFFCF2"
Y_50        = "#FFFBEB"
Y_100       = "#FEF3C7"
Y_200       = "#FDE68A"
Y_300       = "#FCD34D"
Y_400       = "#FBBF24"
Y_500       = "#F59E0B"
Y_700       = "#B45309"
LINE        = "rgba(180, 83, 9, 0.18)"
LINE_STRONG = "rgba(180, 83, 9, 0.35)"

AMBER_SCALE = [Y_300, Y_500, Y_700]
AGENT_COLOR_AMBER = {"cowrie": Y_500, "on_device": Y_300, "cloud": INK, "unknown": INK_3}

# ── GeoIP ─────────────────────────────────────────────────────────────────────

_geo_reader = None
_geo_reader_loaded = False
_geo_cache: dict = {}

def _load_geo_reader():
    global _geo_reader, _geo_reader_loaded
    if _geo_reader_loaded:
        return _geo_reader
    _geo_reader_loaded = True
    if not os.path.exists(MMDB_PATH):
        return None
    try:
        import geoip2.database
        _geo_reader = geoip2.database.Reader(MMDB_PATH)
    except Exception as e:
        print(f"[geo] failed: {e}")
        _geo_reader = None
    return _geo_reader

def geolocate(ip: str):
    if not ip or ip in ("?", "127.0.0.1", "::1", ""):
        return None
    if ip in _geo_cache:
        return _geo_cache[ip]
    reader = _load_geo_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        if r.location.latitude is None:
            _geo_cache[ip] = None
            return None
        result = {
            "lat": r.location.latitude, "lon": r.location.longitude,
            "country": r.country.name or "Unknown", "city": r.city.name or "",
        }
        _geo_cache[ip] = result
        return result
    except Exception:
        _geo_cache[ip] = None
        return None

# ── Data loaders (simple TTL cache — Dash has no st.cache_data) ───────────────

_cache = {"all_df": None, "all_ts": 0, "auth": None, "auth_ts": 0}
# load_raw_session_rows() re-reads every individual session JSON file from
# disk on a cache miss (~300-400ms at 3700+ files) — 1.0s was shorter than
# the time it takes a person to click something, so nearly every click paid
# that cost. 4s (just under REFRESH_MS) still keeps the live auto-refresh
# feeling live, but reuses the cache across fast clicks.
# TTL MUST be longer than REFRESH_MS or every tick is a guaranteed cold miss —
# at 4s vs a 5s tick this re-read all 3800 session files and rebuilt the 132k-row
# DataFrame every 5 seconds, which is what made the whole UI feel frozen.
TTL = 30.0        # heavy full-dataset cache (page renders, charts, MITRE)
FEED_ROWS = 60    # newest rows pulled for the 30-line feed. Small headroom for
                  # rows with an unparseable timestamp, which get dropped before
                  # the head(30); no reason to fetch more than that.
FEED_TTL = 4.0    # feed is cheap, so it can stay near-real-time

_feed_cache = {}   # instance key ("all" or sensor name) -> (rows, fetched_at)

# Rendered pages, keyed by everything they depend on -> (component, built_at).
# Kept to the same TTL as the data caches: a page built from a snapshot of the
# data is valid for exactly as long as that snapshot is, so this adds no
# staleness beyond what the dashboard already had.
PAGE_TTL = TTL
_page_cache = {}


def _cached_page(key, build):
    """Serve an already-rendered page instead of rebuilding it.

    Switching pages rebuilt every Plotly figure and Dash component from
    scratch — ~550ms for the Summary page — even when nothing behind it had
    changed. Profiling showed the cost is figure/component construction
    (26% plotly, 39% Dash components), not the data query, so the only real
    fix is to not rebuild at all.

    The live terminal is deliberately NOT frozen by this: it has its own 5s
    callback writing into live-feed-wrap, which replaces the feed inside
    whatever page is on screen, cached or not."""
    now = time.time()
    hit = _page_cache.get(key)
    if hit is not None and (now - hit[1]) < PAGE_TTL:
        return hit[0]
    page = build()
    _page_cache[key] = (page, now)
    return page


def load_feed_rows(instance=None):
    """The newest rows, straight off the timestamp index.

    This used to open the 40 newest session files per sensor and parse them in
    full to render 30 lines — ~300ms of work for ~2KB of output. As one indexed
    LIMIT query it is ~2ms, which is what lets the 5s tick feel instant.

    The sensor filter is pushed into the query rather than applied after. Taking
    the newest N globally and filtering in pandas looks equivalent but is not:
    if one sensor is busy it occupies the whole window and every quieter sensor
    renders as an empty feed. Cached per instance for the same reason."""
    now = time.time()
    key = instance or "all"
    hit = _feed_cache.get(key)
    if hit is not None and (now - hit[1]) < FEED_TTL:
        return hit[0]
    rows = storage.query_recent(FEED_ROWS, instance=instance)
    _feed_cache[key] = (rows, now)
    return rows

def _discover_session_dirs() -> list:
    """Any directory matching data/logs/sessions* — one HydraPoT sensor
    writes to each (config.yaml's logging.session_dir per sensor entry).
    New sensors need zero dashboard changes, just a matching directory."""
    base_dir  = os.path.dirname(SESSION_DIR) or "."
    base_name = os.path.basename(SESSION_DIR)
    return sorted(d for d in glob.glob(os.path.join(base_dir, base_name + "*"))
                  if os.path.isdir(d))

def _discover_auth_logs() -> list:
    base_dir = os.path.dirname(AUTH_LOG) or "."
    stem, ext = os.path.splitext(os.path.basename(AUTH_LOG))
    return sorted(glob.glob(os.path.join(base_dir, stem + "*" + ext)))

def load_raw_session_rows() -> list:
    """Raw dict rows (not the parsed load_all() DataFrame) — the shape
    threat_intel.ioc_extractor.build_iocs() expects: cmd/response/src_ip/
    session_id/fi_score/timestamp/instance per row.

    The one reader that genuinely needs `response` (IOCs are extracted from
    command output as well as the command), so this is the full-width query.
    It is only reached by the "Generate Intelligence" button, never by a page
    render — which is why load_all() gets its own narrower query instead."""
    now = time.time()
    if _cache.get("raw_rows") is not None and (now - _cache.get("raw_rows_ts", 0)) < TTL:
        return _cache["raw_rows"]

    rows = storage.query_all()
    _cache["raw_rows"] = rows
    _cache["raw_rows_ts"] = now
    return rows

def load_all() -> pd.DataFrame:
    now = time.time()
    if _cache["all_df"] is not None and (now - _cache["all_ts"]) < TTL:
        return _cache["all_df"]

    # Deliberately NOT load_raw_session_rows(): this runs on every page render,
    # and it never reads `response`. Skipping that column alone is ~460ms ->
    # ~145ms. Anything here that does need it should use storage.query_session().
    df = storage.query_all_df()
    if df.empty:
        df = pd.DataFrame()
    else:
        df["fi_score"]   = df.get("fi_score",   0).fillna(0).astype(int)
        df["latency_ms"] = df.get("latency_ms", 0).fillna(0).astype(float)
        df["agent"]      = df.get("agent",      "unknown").fillna("unknown")
        df["session_id"] = df.get("session_id", "default").fillna("default")
        df["src_ip"]     = df.get("src_ip",     "?").fillna("?")
        if "instance" not in df.columns:
            df["instance"] = "default"
        else:
            df["instance"] = df["instance"].fillna("default")
        # ATT&CK tags applied here rather than stored in the logs: the mapper is
        # pure regex over the command text, so historical rows get exactly the
        # answer they'd have got live, and editing MITRE_RULES re-tags
        # everything on the next refresh with no migration. Cached per UNIQUE
        # command (4.3k uniques for 132k rows) so it costs ~0.06s.
        _lut = {c: _mitre_tag(c) for c in df["cmd"].astype(str).unique()}
        df["technique_id"] = df["cmd"].astype(str).map(lambda c: (_lut.get(c) or {}).get("technique_id"))
        df["technique"]    = df["cmd"].astype(str).map(lambda c: (_lut.get(c) or {}).get("technique"))
        df["tactic"]       = df["cmd"].astype(str).map(lambda c: (_lut.get(c) or {}).get("tactic"))
        df["timestamp"]  = pd.to_datetime(df.get("timestamp", ""), errors="coerce")

    _cache["all_df"] = df
    _cache["all_ts"] = now
    return df

def load_auth_log() -> list:
    now = time.time()
    if _cache["auth"] is not None and (now - _cache["auth_ts"]) < TTL:
        return _cache["auth"]

    data = []
    for path in _discover_auth_logs():
        try:
            with open(path) as f:
                raw = json.load(f)
            if isinstance(raw, list):
                data.extend(raw)
        except Exception:
            pass

    _cache["auth"] = data
    _cache["auth_ts"] = now
    return data

def get_sensor_summary() -> list:
    """One row per HydraPoT instance actually present in the data (not per
    directory) — {'instance', 'commands', 'sessions', 'src_ips'}, sorted by
    command volume."""
    df = load_all()
    if df.empty or "instance" not in df.columns:
        return []
    out = []
    for instance, g in df.groupby("instance"):
        out.append({
            "instance": instance,
            "commands": len(g),
            "sessions": g["session_id"].nunique(),
            "src_ips":  g["src_ip"].nunique(),
        })
    return sorted(out, key=lambda r: r["commands"], reverse=True)

# ── Threat Intel: on-demand snapshot generation (SIEM-style, not live) ────────
#
# build_iocs() runs regex extraction over every session row (~11s at 130k+
# rows) — far slower than REFRESH_MS (5s), and in a real SIEM, threat intel is
# a generated snapshot, not a live-refreshing feed. So this is ONLY ever
# invoked by the "Generate Intelligence" button (see generate_intelligence()
# callback below), never on a timer or page-navigation auto-render.

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

# ── Plotly chart chrome helper (consistent ink/amber theme) ───────────────────

def theme_layout(fig, height=None, legend=False):
    layout_kwargs = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="JetBrains Mono, monospace", color=INK_3, size=12),
        margin=dict(t=10, b=10, l=10, r=10),
    )
    if height:
        layout_kwargs["height"] = height
    if not legend:
        layout_kwargs["showlegend"] = False
    fig.update_layout(**layout_kwargs)
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=LINE_STRONG, tickfont=dict(color=INK_3))
    fig.update_yaxes(showgrid=True, gridcolor=LINE, zeroline=False, linecolor=LINE_STRONG, tickfont=dict(color=INK_3))
    return fig

def empty_geo_fig():
    fig = go.Figure(go.Scattergeo())
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        geo=dict(bgcolor="rgba(0,0,0,0)", landcolor=Y_100, showocean=True,
                  oceancolor=PAPER, coastlinecolor=LINE_STRONG, showcountries=True,
                  countrycolor=LINE_STRONG),
        height=320, margin=dict(t=0, b=0, l=0, r=0),
    )
    return fig

# ── App ───────────────────────────────────────────────────────────────────────

app = Dash(__name__, suppress_callback_exceptions=True)
app.title = "HydraPoT"

app.index_string = """
<!DOCTYPE html>
<html>
<head>
  {%metas%}
  <title>{%title%}</title>
  {%favicon%}
  {%css%}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --y-50: """ + Y_50 + """; --y-100: """ + Y_100 + """; --y-200: """ + Y_200 + """;
      --y-300: """ + Y_300 + """; --y-400: """ + Y_400 + """; --y-500: """ + Y_500 + """; --y-700: """ + Y_700 + """;
      --ink: """ + INK + """; --ink-2: """ + INK_2 + """; --ink-3: """ + INK_3 + """;
      --paper: """ + PAPER + """; --line: """ + LINE + """; --line-strong: """ + LINE_STRONG + """;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      overflow-x: hidden;
      width: 100%;
    }
    body {
      font-family: 'Inter', system-ui, sans-serif;
      background: var(--paper);
      color: var(--ink);
      background-image:
        radial-gradient(circle at 15% 0%, rgba(252, 211, 77, 0.20) 0%, transparent 40%),
        radial-gradient(circle at 90% 60%, rgba(251, 191, 36, 0.14) 0%, transparent 45%);
    }
    h1,h2,h3,h4,h5 { font-weight:800; letter-spacing:-0.02em; color:var(--ink); margin:0; }

    .app-shell {
      display:flex; min-height:100vh;
      overflow-x: hidden;
      width: 100%;
      max-width: 100vw;
    }
    /* the nav sidebar is a normal flex child, so it scrolls WITH the page and
       only ever collapses in/out — it must never be what widens the layout */
    .sidebar { flex-shrink: 0; }

    /* Sidebar */
    .sidebar {
  width: 260px; flex-shrink:0;
  background: var(--y-50);
  border-right: 2px solid var(--ink);
  padding: 70px 20px 24px 20px;   /* was: 24px 20px — extra top padding clears the floating button */
  display:flex; flex-direction:column; gap:14px;
  transition: width 0.2s ease, padding 0.2s ease, opacity 0.15s ease;
  overflow: hidden;
}
.sidebar.collapsed {
  width: 0;
  padding: 70px 0 24px 0;   /* keep top padding consistent on collapse */
  opacity: 0;
  pointer-events: none;
}
    .sidebar-logo { font-size:1.3rem; font-weight:800; display:flex; align-items:center; gap:8px; white-space:nowrap; }
    .sidebar-caption { font-size:0.78rem; color:var(--ink-3); line-height:1.5; font-family:'JetBrains Mono',monospace; }
    .sidebar-divider { border-top: 1.5px solid var(--line-strong); margin: 6px 0; }
    .nav-pill {
      background: var(--paper); border:2px solid var(--ink); border-radius:999px;
      padding:9px 16px; font-weight:600; font-size:0.85rem; cursor:pointer;
      text-align:left; transition: all 0.15s; white-space:nowrap;
    }
    .nav-pill:hover { background: var(--y-100); }
    .nav-pill.active { background: var(--ink); color: var(--y-300); }
    .toggle-row { display:flex; align-items:center; justify-content:space-between; font-size:0.85rem; font-weight:600; }
    .refresh-btn {
      background: var(--ink); color: var(--y-300); border:2px solid var(--ink);
      border-radius:999px; padding:8px 14px; font-weight:600; cursor:pointer; font-size:0.85rem;
      transition: all 0.15s; white-space:nowrap;
    }
    .refresh-btn:hover { background: var(--y-400); color: var(--ink); }
    .status-pill {
      border:1.5px solid var(--ink); border-radius:10px; padding:8px 10px;
      font-size:0.78rem; font-family:'JetBrains Mono',monospace; font-weight:600;
    }
    .status-ok { background: #eaf7ee; color:#1f7a3a; }
    .status-warn { background: var(--y-100); color: var(--y-700); }
    /* reserves space so the badge popping in after load doesn't push the
       rest of the sidebar down (a real, measurable CLS contributor) */
    #geo-status { min-height: 36px; }
    .source-cap { font-size:0.72rem; color:var(--ink-3); font-family:'JetBrains Mono',monospace; word-break:break-all; }

    /* Sidebar toggle (floating button, always visible) */
    .sidebar-toggle {
      position: fixed; top: 20px; left: 16px; z-index: 50;
      background: var(--ink); color: var(--y-300); border:2px solid var(--ink);
      border-radius:10px; width:38px; height:38px; cursor:pointer;
      font-size:1.1rem; display:flex; align-items:center; justify-content:center;
      transition: left 0.2s ease;
    }
    .sidebar-toggle:hover { background: var(--y-400); color: var(--ink); }

    /* Content */
    .content {
      flex:1; padding: 32px 36px 32px 70px; max-width: 1500px;
      min-width: 0;
      overflow-x: hidden;
      width: 100%;
    }

    /* Section header */
    .section-header {
      font-size:1.05rem; font-weight:700; letter-spacing:-0.01em;
      margin: 18px 0 12px; display:flex; align-items:center; gap:8px; color: var(--ink);
    }
    .section-header:before {
      content:""; width:8px; height:8px; background:var(--y-400);
      border:1.5px solid var(--ink); border-radius:3px; display:inline-block;
    }

    /* Metric cards */
    .metric-row { display:flex; gap:16px; flex-wrap:wrap; margin: 14px 0; }
    .metric-card {
      background: var(--paper); border:2px solid var(--ink); border-radius:14px;
      padding:14px 18px; box-shadow:4px 4px 0 var(--ink); flex:1; min-width:140px;
    }
    .metric-label {
      font-family:'JetBrains Mono',monospace; text-transform:uppercase; letter-spacing:0.08em;
      font-size:0.68rem; color:var(--ink-3); margin-bottom:6px;
    }
    .metric-value { font-weight:800; font-size:1.7rem; color:var(--ink); }
    .metric-sub { font-size:0.68rem; color:var(--ink-3); margin-top:4px;
      font-family:'JetBrains Mono',monospace; }
    /* Cost/energy cards — stand out in green so they read at a glance */
    .metric-card.cost-card {
      background:#0f8a4d; border-color:#0a5c34; box-shadow:4px 4px 0 #0a5c34;
    }
    .metric-card.cost-card .metric-label { color:#d6ffe6; }
    .metric-card.cost-card .metric-value { color:#ffffff; }
    .metric-card.cost-card .metric-sub { color:#bff0d1; font-size:0.65rem;
      font-family:'JetBrains Mono',monospace; margin-top:4px; }
    .threat-badge { border-radius:14px; padding:12px; text-align:center; border:2px solid var(--ink); flex:1; min-width:140px; }
    /* ── MITRE ATT&CK page ── */
    /* align-items:start on BOTH grids: otherwise the sidebar stretches to the
       card row's height and every card stretches to the tallest one, which is
       what produced the dead space under the trend charts (#3, #4). */
    /* min-width:0 on every grid child: a grid track's default min-width is
       "auto" (= its content), so a wide table or chart refuses to shrink and
       shoves the whole page sideways. This is what made the page drift
       horizontally instead of just scrolling down. */
    .mitre-grid { display:grid; grid-template-columns: 320px minmax(0, 1fr);
                  gap:16px; align-items:start; width:100%; }
    .mitre-grid > * { min-width:0; }
    .mitre-side { display:flex; flex-direction:column; min-width:0; }
    .tech-card { width:100%; margin-top:14px; }
    .tech-card .stage-body { padding:6px 10px 2px; }
    .side-head { font-weight:700; font-size:0.86rem; margin-bottom:6px; display:flex;
                 align-items:center; gap:7px; }
    .side-head:before { content:""; width:7px; height:7px; background:var(--y-400);
                        border:1.5px solid var(--ink); border-radius:3px; }
    .stage-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                  gap:14px; align-items:start; min-width:0; }
    .stage-grid > * { min-width:0; }
    .stage-card { background:var(--paper); border:2px solid var(--ink); border-radius:14px;
                  box-shadow:4px 4px 0 var(--ink); overflow:hidden;
                  display:flex; flex-direction:column; height:fit-content; }
    .stage-head { color:#fff; font-weight:800; letter-spacing:0.06em; font-size:0.86rem;
                  padding:9px 13px; border-bottom:2px solid var(--ink); }
    .stage-body { padding:10px 12px 4px; }
    .stage-top { display:flex; gap:8px; align-items:center; }
    .stage-tactics { flex:0 0 42%; display:flex; flex-direction:column; gap:4px; }
    .stage-tactic { font-family:'JetBrains Mono',monospace; font-size:0.68rem; line-height:1.25;
                    background:var(--y-100); border:1.5px solid var(--line-strong);
                    border-radius:6px; padding:3px 6px; }
    .donut-key { display:flex; justify-content:center; gap:9px; margin-top:-6px; }
    .key-item { font-family:'JetBrains Mono',monospace; font-size:0.6rem; color:var(--ink-3);
                display:inline-flex; align-items:center; gap:3px; }
    .key-dot { width:7px; height:7px; border-radius:50%; display:inline-block;
               border:1px solid var(--ink); }
    .sev-row { display:flex; gap:7px; margin:8px 0 0; }
    .sev-badge { flex:1; text-align:center; background:var(--y-50);
                 border:1.5px solid var(--line-strong); border-radius:9px; padding:5px 3px; }
    .sev-dot { display:block; width:10px; height:10px; border-radius:50%;
               margin:0 auto 3px; border:1.5px solid var(--ink); }
    .sev-n { font-weight:800; font-size:1.05rem; color:var(--ink); }
    .sev-lbl { font-size:0.58rem; color:var(--ink-3); font-family:'JetBrains Mono',monospace;
               text-transform:uppercase; letter-spacing:0.03em; margin-top:1px; }
    @media (max-width: 1100px) { .mitre-grid { grid-template-columns: 1fr; } }

    .sensor-card {
      font-family:'Inter',sans-serif; text-align:left; cursor:pointer;
      transition: all 0.15s;
    }
    .sensor-card:hover { background: var(--y-100); }
    .sensor-card.active { background: var(--ink); }
    .sensor-card.active .metric-label,
    .sensor-card.active .metric-value,
    .sensor-card.active .metric-sub { color: var(--y-300); }

    /* Terminal feed */
    .terminal-feed {
      background: var(--ink); border-radius:16px; overflow:hidden;
      box-shadow: 0 1px 0 rgba(255,255,255,0.05) inset, 8px 8px 0 var(--y-400), 8px 8px 0 1px var(--ink);
      font-family:'JetBrains Mono',monospace; font-size:0.78rem; line-height:1.6; color:#E8DBC6;
      margin: 14px 0;
      min-width: 0;
      max-width: 100%;
    }
    .term-chrome { background:#2A2118; padding:10px 16px; display:flex; align-items:center; gap:8px; border-bottom:1px solid rgba(255,255,255,0.08); }
    .term-dot { width:11px; height:11px; border-radius:50%; }
    .dot-r { background:#FF5F56; } .dot-y { background:#FFBD2E; } .dot-g { background:#27C93F; }
    .term-chrome-title { color:rgba(255,255,255,0.45); font-size:0.7rem; margin-left:8px; }
    .term-header { color:var(--y-300); font-weight:700; padding:12px 16px 4px; font-size:0.82rem; }
    .term-body { padding:4px 16px 16px; max-height:280px; overflow-y:auto; overflow-x:hidden; min-width:0; }
    .term-line {
      margin:2px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      max-width: 100%;
    }
    .term-time { color:#6e7681; }
    .term-ip { color: var(--y-400); }
    .term-cmd { color:#E8DBC6; }
    .term-fi0 { color:#9aa3ad; } .term-fi1 { color:#6fb1ff; } .term-fi2 { color: var(--y-300); }
    .term-fi3 { color:#ff9f5a; } .term-fi4 { color:#ff6b6b; font-weight:700; }
    .term-agent-cowrie { color:#6fdb8f; } .term-agent-on_device { color: var(--y-300); } .term-agent-cloud { color:#ff6b6b; }
    .term-login { color:#6fdb8f; }
    .term-separator { color:#463826; }

    /* Stat box (auth breakdown) */
    .stat-box {
      background: var(--paper); border:2px solid var(--ink); border-radius:14px;
      padding:16px 18px; font-size:0.85rem; line-height:2.2; font-family:'JetBrains Mono',monospace;
      box-shadow:4px 4px 0 var(--ink);
    }
    .stat-box hr { border-color: var(--line-strong); margin: 8px 0; }

    /* Dangerous command card */
    .danger-card {
      background: var(--paper); border:1.5px solid var(--ink); border-radius:8px;
      padding:8px 12px; margin-bottom:6px; font-family:'JetBrains Mono',monospace;
      box-shadow:2px 2px 0 rgba(26,20,16,0.15);
    }

    .caption { color: var(--ink-3); font-family:'JetBrains Mono',monospace; font-size:0.78rem; }
    .empty-state {
      background: var(--y-100); border:1.5px solid var(--ink); border-radius:10px;
      padding: 12px 16px; font-size:0.9rem; color: var(--ink-2);
    }

    hr.divider { border:none; border-top:1.5px solid var(--line-strong); margin: 18px 0; }

    .grid-2 { display:grid; grid-template-columns: 3fr 2fr; gap: 24px; min-width:0; }
    .grid-4 { display:grid; grid-template-columns: repeat(4, 1fr); gap: 16px; min-width:0; }
    .grid-2 > div, .grid-4 > div { min-width: 0; overflow-x: auto; }
    @media (max-width: 1100px) {
      .grid-2 { grid-template-columns: 1fr; }
      .grid-4 { grid-template-columns: repeat(2, 1fr); }
    }

    /* Dash DataTable container border */
    .dash-table-container { border:2px solid var(--ink) !important; border-radius:12px !important; overflow:hidden !important; max-width:100% !important; }

    select.dd {
      border:2px solid var(--ink) !important; border-radius:10px !important;
      background: var(--paper) !important; font-family:'Inter',sans-serif !important;
    }
  </style>
</head>
<body>
  {%app_entry%}
  <footer>{%config%}{%scripts%}{%renderer%}</footer>
</body>
</html>
"""

# ── DataTable style helper (ink-bordered, amber header) ────────────────────────

TABLE_STYLE = dict(
    style_table={"overflowX": "auto"},
    style_header={
        "backgroundColor": Y_200, "color": INK, "fontWeight": "700",
        "fontFamily": "Inter, sans-serif", "border": "none",
        "borderBottom": f"2px solid {INK}", "fontSize": "13px",
    },
    style_cell={
        "backgroundColor": PAPER, "color": INK_2, "fontFamily": "JetBrains Mono, monospace",
        "fontSize": "12.5px", "border": "none", "borderTop": f"1px solid {LINE}",
        "padding": "8px 12px",
    },
    style_data_conditional=[
        {"if": {"row_index": "odd"}, "backgroundColor": Y_50},
    ],
)

# ── Layout ────────────────────────────────────────────────────────────────────

toggle_btn = html.Button("☰", id="sidebar-toggle-btn", className="sidebar-toggle", n_clicks=0)
sidebar = html.Div(className="sidebar", id="sidebar", children=[
    html.Div(className="sidebar-logo", children=["🍯 HydraPoT"]),
    html.Div(className="sidebar-caption",
             children="An Intelligent Honeypot Framework Using Large Language Models (LLM) for Interactive Attack Analysis"),
    html.Div(className="sidebar-divider"),
    html.Button("Summary", id="nav-summary", className="nav-pill active", n_clicks=0),
    html.Button("Threat Intel", id="nav-intel", className="nav-pill", n_clicks=0),
    html.Button("MITRE ATT&CK", id="nav-mitre", className="nav-pill", n_clicks=0),
    html.Div(className="sidebar-divider"),
    html.Div(className="toggle-row", children=[
        "Auto-refresh",
        dcc.Checklist(
            id="auto-refresh-toggle",
            options=[{"label": "", "value": "on"}],
            value=["on"],
            inline=True,
        ),
    ]),
    html.Div(className="source-cap", children=f"Source: {SESSION_DIR}"),
    html.Button("🔄 Refresh", id="manual-refresh", className="refresh-btn", n_clicks=0),
    html.Div(id="geo-status"),
    dcc.Store(id="page-store", data="Summary"),
    dcc.Interval(id="interval", interval=REFRESH_MS, n_intervals=0),
])
app.layout = html.Div(className="app-shell", children=[
    toggle_btn,
    sidebar,
    html.Div(className="content", id="content-area"),
    dcc.Store(id="sidebar-collapsed-store", data=False),
    # Threat Intel snapshot — lives at the app level (not inside content-area)
    # so it survives navigating away from and back to the Threat Intel page;
    # None until "Generate Intelligence" is clicked for the first time.
    dcc.Store(id="ioc-store", data=None),
    dcc.Store(id="sensor-filter-store", data="all"),
])

# ── Sidebar toggle (clientside) ─────────────────────────────────────────────

app.clientside_callback(
    """
    function(n_clicks, current) {
        if (!n_clicks) { return [false, "sidebar"]; }
        const collapsed = !current;
        return [collapsed, collapsed ? "sidebar collapsed" : "sidebar"];
    }
    """,
    Output("sidebar-collapsed-store", "data"),
    Output("sidebar", "className"),
    Input("sidebar-toggle-btn", "n_clicks"),
    State("sidebar-collapsed-store", "data"),
)

# ── Live feed scroll preservation (clientside) ──────────────────────────────

app.clientside_callback(
    """
    function(children) {
        const el = document.getElementById('live-feed-body');
        if (!el) { return window.dash_clientside.no_update; }
        if (!el.dataset.scrollBound) {
            el.dataset.scrollBound = "true";
            el.addEventListener('scroll', function() {
                window.__feedScrollTop = el.scrollTop;
            });
        }
        requestAnimationFrame(function() {
            if (window.__feedScrollTop !== undefined) {
                el.scrollTop = window.__feedScrollTop;
            }
        });
        return window.dash_clientside.no_update;
    }
    """,
    Output("live-feed-body", "title"),
    Input("live-feed-wrap", "children"),
)


# ── Page nav callback ───────────────────────────────────────────────────────────

@app.callback(
    Output("page-store", "data"),
    Output("nav-summary", "className"),
    Output("nav-intel", "className"),
    Output("nav-mitre", "className"),
    Input("nav-summary", "n_clicks"),
    Input("nav-intel", "n_clicks"),
    Input("nav-mitre", "n_clicks"),
    prevent_initial_call=True,
)
def switch_page(n_summary, n_intel, n_mitre):
    triggered = ctx.triggered_id
    if triggered == "nav-intel":
        return "Threat Intel", "nav-pill", "nav-pill active", "nav-pill"
    if triggered == "nav-mitre":
        return "MITRE ATT&CK", "nav-pill", "nav-pill", "nav-pill active"
    return "Summary", "nav-pill active", "nav-pill", "nav-pill"


# ── GeoIP status badge ──────────────────────────────────────────────────────────

@app.callback(Output("geo-status", "children"), Input("page-store", "data"))
def update_geo_status(_page):
    if os.path.exists(MMDB_PATH):
        return html.Div("🌍 GeoIP ready", className="status-pill status-ok")
    return html.Div("⚠️ geoip.mmdb not found", className="status-pill status-warn")


# ── Manual refresh just clears cache so next interval tick reloads fresh ───────

@app.callback(Output("interval", "n_intervals"), Input("manual-refresh", "n_clicks"), prevent_initial_call=True)
def manual_refresh(_n):
    _cache["all_ts"] = 0
    _cache["auth_ts"] = 0
    _cache["raw_rows_ts"] = 0
    # both are keyed dicts, so expiring them means dropping the keys — setting
    # a "ts" entry would just add a stray key and leave the entries live
    _feed_cache.clear()
    _page_cache.clear()
    return 0


# ── Single router callback ───────────────────────────────────────────────────

@app.callback(
    Output("content-area", "children"),
    Input("page-store", "data"),
    Input("sensor-filter-store", "data"),
    prevent_initial_call=False,
)
def render_router(page, sensor_filter):
    if page == "Threat Intel":
        # Threat Intel never auto-refreshes on the interval tick — it's a
        # generated snapshot (SIEM-style), not a live feed. Only navigating
        # to the page (re)renders the shell, using whatever snapshot is
        # already in ioc-store; a NEW snapshot only comes from clicking
        # "Generate Intelligence" (see generate_intelligence() below), which
        # updates ioc-content directly and never touches this callback.
        if ctx.triggered_id in ("interval", "sensor-filter-store"):
            raise PreventUpdate
        # shell only — render_ioc_content() fills in the snapshot from the
        # store, so the 0.68 MB blob never round-trips on navigation
        return _cached_page(("intel",), lambda: build_threat_intel_page(None))
    if page == "MITRE ATT&CK":
        # Same reasoning as Threat Intel: this is an analysis view, not a live
        # feed. Rebuilding it on the interval re-initialised 7 Plotly figures
        # in the browser every 5s (the real source of the sluggishness) AND
        # reset the time-period dropdown back to its default mid-selection.
        if ctx.triggered_id == "sensor-filter-store":
            raise PreventUpdate
        return _cached_page(("mitre",), build_mitre_page)
    sf = sensor_filter or "all"
    # keyed by sensor: each sensor's Summary is a different page
    return _cached_page(("summary", sf), lambda: build_summary_page(sf))


# ── Threat Intel: generate-on-demand (heavy compute, button-triggered only) ────
#
# The button click is the ONLY thing that runs build_ioc_snapshot(); it never
# fires from the interval. dcc.Loading (wrapping ioc-generate-status, one of
# this callback's outputs) shows a spinner over the button for the ~11s the
# real extraction takes, while ioc-content — a completely separate Output,
# updated by render_ioc_content() below — is untouched the whole time, so the
# previous results stay exactly as they were until the new snapshot is ready.
@app.callback(
    Output("ioc-store", "data"),
    Output("ioc-generate-status", "children"),
    Output("ioc-last-updated", "children"),
    Input("generate-ioc-btn", "n_clicks"),
    State("ioc-scope", "value"),
    prevent_initial_call=True,
)
def generate_intelligence(_n, scope):
    snapshot = build_ioc_snapshot(scope=scope or "all")
    restored_button = [html.Button("🔄 Generate Intelligence", id="generate-ioc-btn",
                                   className="refresh-btn", n_clicks=0)]
    return snapshot, restored_button, _ioc_status_text(snapshot)


@app.callback(
    Output("ioc-content", "children"),
    Input("ioc-store", "data"),
    prevent_initial_call=False,
)
def render_ioc_content(ioc_data):
    return _render_ioc_body(ioc_data)


@app.callback(
    Output("sensor-filter-store", "data"),
    Input({"type": "sensor-card-btn", "sensor": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def set_sensor_filter(_clicks):
    triggered = ctx.triggered_id
    if not triggered:
        raise PreventUpdate
    return triggered["sensor"]


# ── STIX export — reuses threat_intel.ioc_extractor.to_stix() unchanged, just
# fed the cached ioc-store records instead of a live IOCStore. Written to the
# same data/threat_intel/ directory `hp intel --format stix` uses, then served
# to the browser as a download. ─────────────────────────────────────────────
STIX_OUT_DIR = os.path.join(_HERE, "data", "threat_intel")

@app.callback(
    Output("stix-download", "data"),
    Input("export-stix-btn", "n_clicks"),
    State("ioc-store", "data"),
    prevent_initial_call=True,
)
def export_stix(_n, ioc_data):
    recs = (ioc_data or {}).get("recs")
    if not recs:
        raise PreventUpdate
    os.makedirs(STIX_OUT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(STIX_OUT_DIR, f"iocs_stix_{ts}.json")
    to_stix(recs, path)
    return dcc.send_file(path)


# ── Category filter pills — click a type (URL, domain, ipv4, ...) to narrow
# the table down to just that type, instead of scrolling through everything
# mixed together. Two callbacks: one tracks which pill is selected, the other
# applies it (recomputes the table + which pill shows as active). ────────────
@app.callback(
    Output("ioc-cat-filter-store", "data"),
    Input({"type": "ioc-cat-btn", "cat": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def set_ioc_category_filter(_clicks):
    triggered = ctx.triggered_id
    if not triggered:
        raise PreventUpdate
    return triggered["cat"]


@app.callback(
    Output("ioc-table", "data"),
    Output({"type": "ioc-cat-btn", "cat": ALL}, "className"),
    Output("ioc-table-caption", "children"),
    Input("ioc-cat-filter-store", "data"),
    State("ioc-store", "data"),
    State({"type": "ioc-cat-btn", "cat": ALL}, "id"),
    prevent_initial_call=True,
)
def apply_ioc_category_filter(selected_cat, ioc_data, btn_ids):
    recs = (ioc_data or {}).get("recs") or []
    selected_cat = selected_cat or "all"
    filtered = recs if selected_cat == "all" else [r for r in recs if r["type"] == selected_cat]
    classnames = ["nav-pill active" if bid["cat"] == selected_cat else "nav-pill" for bid in btn_ids]
    caption = f"{len(recs)} unique indicators — showing {len(filtered[:200])}" + (
        "" if selected_cat == "all" else f" of type '{selected_cat}'")
    return _ioc_table_rows(filtered), classnames, caption


@app.callback(
    Output("session-detail", "children"),
    Input("session-dropdown", "value"),
    Input("interval", "n_intervals"),
    prevent_initial_call=True,
)
def update_session_detail(selected, _n):
    df = load_all()
    if not selected or df.empty:
        raise PreventUpdate
    return build_session_detail(df, selected)


# ── Auto-refresh toggle: disable/enable interval ────────────────────────────────

@app.callback(Output("interval", "disabled"), Input("auto-refresh-toggle", "value"))
def toggle_autorefresh(value):
    return "on" not in (value or [])

# ── Main content renderer ───────────────────────────────────────────────────────



# NOTE: Dash requires component IDs referenced in callbacks to exist in the
# layout tree before the app starts, and the session dropdown only exists on
# page 2. We solve this with a router pattern: render_content owns page
# switching + the session dropdown lives *inside* the rendered children, with
# its own follow-up callback for drill-down refresh.

def build_live_feed(sensor_filter="all"):
    """Just the terminal feed. Lives in its own function + callback so the
    5s tick can refresh ONLY this block: re-rendering the whole page also
    tore down and rebuilt every Plotly figure and the geo map, which is what
    made the dashboard feel sluggish and made buttons slow to respond."""
    # sensor filter pushed into the query — see load_feed_rows()
    rows = load_feed_rows(None if sensor_filter in (None, "all") else sensor_filter)
    auth_entries = load_auth_log()
    if not rows:
        return None
    df = pd.DataFrame(rows)
    df["fi_score"]  = df["fi_score"].fillna(0).astype(int) if "fi_score" in df else 0
    df["agent"]     = df["agent"].fillna("unknown") if "agent" in df else "unknown"
    df["src_ip"]    = df["src_ip"].fillna("?") if "src_ip" in df else "?"
    df["instance"]  = df["instance"].fillna("default") if "instance" in df else "default"
    df["timestamp"] = pd.to_datetime(df.get("timestamp", ""), errors="coerce")
    if sensor_filter and sensor_filter != "all":
        df = df[df["instance"] == sensor_filter]
        auth_entries = [a for a in auth_entries if a.get("instance") == sensor_filter]
    if df.empty:
        return None

    recent = df[df["timestamp"].notna()].sort_values("timestamp", ascending=False).head(30)

    def line(ts, ip, fi=None, agent=None, cmd=None, kind="cmd"):
        spans = [html.Span(f"[{ts}]", className="term-time")]
        if kind == "scan":
            spans += [html.Span(" SCAN ", className="term-fi3"), html.Span(ip, className="term-ip"),
                      html.Span(" TCP connection (port probe)", className="term-cmd")]
        elif kind == "login":
            spans += [html.Span(" LOGIN ", className="term-login"), html.Span(f" {ip} ", className="term-ip"),
                      html.Span(cmd, className="term-cmd")]
        else:
            spans += [html.Span(f" {ip} ", className="term-ip"), html.Span(f"FI:{fi} ", className=f"term-fi{fi}"),
                      html.Span(f"[{agent}] ", className=f"term-agent-{agent}"),
                      html.Span(f"$ {cmd}", className="term-cmd")]
        return html.Div(spans, className="term-line")

    rows = []
    for e in auth_entries[-5:]:
        ts, ip = e.get("timestamp", ""), e.get("src_ip", "?")
        if e.get("auth_type") == "tcp_connect":
            rows.append(line(ts, ip, kind="scan"))
        else:
            rows.append(line(ts, ip, cmd=f"{e.get('username','?')}:{e.get('password','?')}", kind="login"))

    if rows and not recent.empty:
        rows.append(html.Div(html.Span("────────────────────────────────────────────",
                                        className="term-separator"), className="term-line"))

    for _, r in recent.iterrows():
        ts = r["timestamp"].strftime("%H:%M:%S") if pd.notna(r["timestamp"]) else "??:??:??"
        rows.append(line(ts, r.get("src_ip", "?"), fi=int(r.get("fi_score", 0)),
                         agent=r.get("agent", "unknown"), cmd=str(r.get("cmd", ""))[:80]))

    if not rows:
        return None
    return html.Div(className="terminal-feed", children=[
        html.Div(className="term-chrome", children=[
            html.Span(className="term-dot dot-r"), html.Span(className="term-dot dot-y"),
            html.Span(className="term-dot dot-g"),
            html.Span("hydrapot — live feed", className="term-chrome-title"),
        ]),
        html.Div("▶ Live Session Feed", className="term-header"),
        html.Div(className="term-body", id="live-feed-body", children=rows),
    ])


def build_summary_page(sensor_filter="all"):
    df = load_all()
    auth_entries = load_auth_log()
    all_sensors = get_sensor_summary()   # computed pre-filter, so the sensor
                                          # panel itself always shows every sensor

    if sensor_filter and sensor_filter != "all" and not df.empty:
        df = df[df["instance"] == sensor_filter]
        auth_entries = [a for a in auth_entries if a.get("instance") == sensor_filter]

    if df.empty:
        return [
            html.H3("HydraPoT Dashboard"),
            html.Div("No data yet. Start the honeypot with `hp run`.", className="empty-state"),
        ]


    feed = build_live_feed(sensor_filter)

    # Metric cards    # Metric cards
    peak_fi = int(df["fi_score"].max())
    tl, tc, ti = THREAT_LEVEL[peak_fi]
    _costs = estimate_costs(df)
    metrics = html.Div(className="metric-row", children=[
        html.Div(className="metric-card", children=[
            html.Div("Total Commands", className="metric-label"),
            html.Div(f"{len(df)}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("Unique Sessions", className="metric-label"),
            html.Div(f"{df['session_id'].nunique()}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("Unique Attackers", className="metric-label"),
            html.Div(f"{df['src_ip'].nunique()}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("High Impact (FI≥3)", className="metric-label"),
            html.Div(f"{int((df['fi_score'] >= 3).sum())}", className="metric-value"),
        ]),
        html.Div(className="metric-card cost-card", children=[
            html.Div(f"☁ Cloud Cost · {_costs['month_label']} (est.)", className="metric-label"),
            html.Div(f"${_costs['cloud_cost_usd']:.4f}", className="metric-value"),
            html.Div(f"{_costs['n_cloud']} cloud commands this month", className="metric-sub"),
        ]),
        html.Div(className="metric-card cost-card", children=[
            html.Div(f"⚡ On-device Electricity · {_costs['month_label']} (est.)", className="metric-label"),
            html.Div(f"{_costs['on_device_thb']:.2f} ฿", className="metric-value"),
            html.Div(
                (f"≈ {_costs['on_device_thb_projected']:.2f} ฿ projected full month · "
                 if _costs['projection_ready'] else "projection pending (early in month) · ")
                + f"{_costs['on_device_kwh']:.4f} kWh · {_costs['n_on_device']} cmds",
                className="metric-sub"),
        ]),
        html.Div(className="threat-badge", style={"background": f"{tc}1A"}, children=[
            html.Div(ti, style={"fontSize": "2rem"}),
            html.Div(tl, style={"fontWeight": "700", "color": tc, "fontFamily": "JetBrains Mono, monospace"}),
            html.Div("Peak Threat", style={"fontSize": "0.7rem", "opacity": "0.7", "fontFamily": "JetBrains Mono, monospace"}),
        ]),
    ])

    # Events over time
    tdf = df[df["timestamp"].notna()].copy()
    if not tdf.empty:
        tdf["bucket"] = tdf["timestamp"].dt.floor("30min")
        buckets = tdf.groupby("bucket").size().reset_index(name="count")
        fig_t = go.Figure()
        fig_t.add_trace(go.Scatter(
            x=buckets["bucket"], y=buckets["count"], fill="tozeroy",
            line=dict(color=Y_700, width=2.5), fillcolor="rgba(245,158,11,0.18)",
            hovertemplate="<b>%{x}</b><br>Events: %{y}<extra></extra>",
        ))
        theme_layout(fig_t, height=200)
        fig_t.update_layout(xaxis_title="@timestamp per 30 minutes")
        time_chart = dcc.Graph(figure=fig_t, config={"displayModeBar": False})
    else:
        time_chart = html.Div("No timestamp data.", className="caption")

    # Summary of events table
    summary_rows = []
    hi_fi = df[df["fi_score"] >= 2].copy()
    for fi in [4, 3, 2]:
        sub = hi_fi[hi_fi["fi_score"] == fi]
        if sub.empty:
            continue
        top = sub["cmd"].apply(lambda c: c.split()[0] if c else "").value_counts().head(5)
        for cmd_base, cnt in top.items():
            tl2, _, _ = THREAT_LEVEL[fi]
            summary_rows.append({"Rule": f"FI-{fi}: {FI_LABEL[fi]} via `{cmd_base}`", "Severity": tl2, "Events": int(cnt)})

    if summary_rows:
        sev_colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}
        summary_table = dash_table.DataTable(
            data=summary_rows,
            columns=[{"name": c, "id": c} for c in ["Rule", "Severity", "Events"]],
            style_data_conditional=[
                {"if": {"row_index": "odd"}, "backgroundColor": Y_50},
                *[{"if": {"filter_query": f'{{Severity}} = "{sev}"', "column_id": "Severity"},
                   "color": col, "fontWeight": "bold"} for sev, col in sev_colors.items()],
            ],
            style_header=TABLE_STYLE["style_header"],
            style_cell=TABLE_STYLE["style_cell"],
            style_table=TABLE_STYLE["style_table"],
        )
    else:
        summary_table = html.Div("No high-impact events yet.", className="caption")

    # Map
    ip_col = "public_ip" if "public_ip" in df.columns else "src_ip"
    unique_ips = df[ip_col].dropna().unique()
    geo_rows = []
    for ip in unique_ips:
        geo = geolocate(ip)
        if geo:
            count = int((df[ip_col] == ip).sum())
            geo_rows.append({"ip": ip, "lat": geo["lat"], "lon": geo["lon"],
                              "country": geo["country"], "city": geo["city"], "count": count})

    if geo_rows:
        geo_df = pd.DataFrame(geo_rows)
        fig_map = px.scatter_geo(
            geo_df, lat="lat", lon="lon", size="count", color="count",
            hover_name="country", hover_data={"ip": True, "city": True, "count": True, "lat": False, "lon": False},
            color_continuous_scale=AMBER_SCALE, size_max=40, projection="natural earth",
        )
        fig_map.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            geo=dict(bgcolor="rgba(0,0,0,0)", landcolor=Y_100, oceancolor=PAPER, showocean=True,
                      showland=True, lakecolor=PAPER, coastlinecolor=LINE_STRONG, countrycolor=LINE_STRONG,
                      showcoastlines=True, showcountries=True),
            coloraxis_showscale=False, margin=dict(t=0, b=0, l=0, r=0), height=320,
        )
        map_chart = dcc.Graph(figure=fig_map, config={"displayModeBar": False})

        ip_table = geo_df.sort_values("count", ascending=False).head(10)
        ip_table = ip_table[["ip", "country", "city", "count"]].rename(
            columns={"ip": "IP", "country": "Country", "city": "City", "count": "Events"})
        ip_table_component = html.Div([
            html.Div("Top Attacker IPs", style={"fontWeight": "700", "marginBottom": "8px"}),
            dash_table.DataTable(data=ip_table.to_dict("records"),
                                  columns=[{"name": c, "id": c} for c in ip_table.columns],
                                  **TABLE_STYLE),
        ])
    else:
        map_chart = dcc.Graph(figure=empty_geo_fig(), config={"displayModeBar": False})
        geo_msg = "⚠️ geoip.mmdb not found — map unavailable" if _load_geo_reader() is None else "All connections from localhost — no geo data to plot"
        ip_table_component = html.Div(geo_msg, className="caption")

    left_col = html.Div([
        html.Div("Events Over Time", className="section-header"),
        time_chart,
        html.Div("Summary of Events", className="section-header"),
        summary_table,
    ])
    right_col = html.Div([
        html.Div("Attacker Origin Map", className="section-header"),
        map_chart,
        ip_table_component,
        # CC BY 4.0 attribution required for the DB-IP City Lite database
        html.Div(
            ["IP geolocation by ",
             html.A("DB-IP", href="https://db-ip.com", target="_blank",
                    style={"color": "inherit"}),
             " — City Lite, CC BY 4.0"],
            className="caption",
            style={"fontSize": "0.68rem", "opacity": "0.6", "marginTop": "6px"},
        ),
    ])

    # Auth intelligence
    auth_block = build_auth_intelligence(df, auth_entries)

    def _sensor_card(sensor_id, label, s):
        active = sensor_filter == sensor_id
        return html.Button(
            className="metric-card sensor-card" + (" active" if active else ""),
            id={"type": "sensor-card-btn", "sensor": sensor_id},
            n_clicks=0,
            children=[
                html.Div(label, className="metric-label"),
                html.Div(f"{s['commands']}", className="metric-value"),
                html.Div(f"{s['sessions']} sessions · {s['src_ips']} attacker IPs",
                          className="metric-sub"),
            ],
        )

    _full_df = load_all()   # unfiltered — for the "All Sensors" card's real totals
    all_card_stats = {
        "commands": len(_full_df),
        "sessions": _full_df["session_id"].nunique() if not _full_df.empty else 0,
        "src_ips":  _full_df["src_ip"].nunique() if not _full_df.empty else 0,
    }
    sensors_block = html.Div(className="metric-row", children=(
        [_sensor_card("all", "All Sensors", all_card_stats)]
        + [_sensor_card(s["instance"], s["instance"], s) for s in all_sensors]
    )) if all_sensors else html.Div("No sensors detected.", className="caption")

    children = [html.H3("🍯 HydraPoT Dashboard")]
    children.append(html.Div(id="live-feed-wrap", children=feed))
    children.append(metrics)
    children.append(html.Hr(className="divider"))
    children.append(html.Div(f"{len(all_sensors)} HydraPoT Sensor{'s' if len(all_sensors) != 1 else ''} Plugged In"
                              + (f" — viewing: {sensor_filter}" if sensor_filter != "all" else ""),
                              className="section-header"))
    children.append(sensors_block)
    children.append(html.Hr(className="divider"))
    children.append(html.Div(className="grid-2", children=[left_col, right_col]))
    children.append(html.Hr(className="divider"))
    children.append(html.Div("Auth Intelligence", className="section-header"))
    children.append(auth_block)
    return children


# ── MITRE ATT&CK page ─────────────────────────────────────────────────────────
#
# Kill-chain stages group MITRE's CURRENT tactic names (checked against the
# official STIX — several classic ones were renamed, e.g. there is no "Defense
# Evasion" any more, it's "Stealth"/"Defense Impairment"). Grouping on names
# that don't exist would render three empty columns.
MITRE_STAGES = [
    ("COMPROMISE",   ["Execution", "Persistence", "Privilege Escalation"],              "#7EB3C8"),
    ("INFILTRATION", ["Discovery", "Credential Access", "Lateral Movement"],            "#5B7FA6"),
    ("DATA LOSS",    ["Command And Control", "Impact", "Stealth", "Defense Impairment"], "#2F4A6B"),
]

# HydraPoT has no success/failure signal — it's a honeypot, every command
# "works" by design. Severity here is the FI band it already computes and
# defends in the evaluation, which is a real measured property rather than an
# invented outcome label.
SEV = [("High impact",   "high",   3, 4, "#C1443A"),
       ("State-changing", "medium", 1, 2, "#E07B39"),
       ("Reconnaissance", "low",    0, 0, "#AAAAAA")]


def _mitre_window(df, days):
    """Current window + the preceding window of equal length, for % change."""
    d = df[df["timestamp"].notna()]
    if d.empty:
        return d, d
    if not days:
        return d, d.iloc[0:0]
    end = d["timestamp"].max()
    start = end - pd.Timedelta(days=days)
    prev_start = start - pd.Timedelta(days=days)
    return d[d["timestamp"] > start], d[(d["timestamp"] > prev_start) & (d["timestamp"] <= start)]


def _stage_stats(cur, prev, tactics):
    s = cur[cur["tactic"].isin(tactics)]
    p = prev[prev["tactic"].isin(tactics)]
    counts = {key: int(((s["fi_score"] >= lo) & (s["fi_score"] <= hi)).sum())
              for _, key, lo, hi, _ in SEV}
    total, ptotal = len(s), len(p)
    pct = ((total - ptotal) / ptotal * 100) if ptotal else None
    return s, counts, total, pct


def _donut(counts, total, colors):
    vals = [counts[k] for _, k, _, _, _ in SEV]
    fig = go.Figure(go.Pie(
        values=vals or [1], hole=0.68, sort=False,
        marker=dict(colors=colors, line=dict(color=PAPER, width=2)),
        textinfo="none", hoverinfo="label+value",
        labels=[lbl for lbl, _, _, _, _ in SEV],
    ))
    fig.add_annotation(text=f"<b>{total:,}</b><br><span style='font-size:11px'>TOTAL</span>",
                       showarrow=False, font=dict(size=26, color=INK, family="Inter"))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
                      margin=dict(t=6, b=6, l=6, r=6), height=190)
    return fig


def _trend(sub, days=7):
    """Total vs high-impact per day over the last `days`."""
    fig = go.Figure()
    if not sub.empty:
        d = sub.copy()
        d["day"] = d["timestamp"].dt.floor("D")
        last = sorted(d["day"].unique())[-days:]
        d = d[d["day"].isin(last)]
        tot = d.groupby("day").size()
        hi = d[d["fi_score"] >= 3].groupby("day").size().reindex(tot.index, fill_value=0)
        lbl = [pd.Timestamp(x).strftime("%d %b") for x in tot.index]
        fig.add_trace(go.Scatter(x=lbl, y=tot.values, name="All", mode="lines+markers",
                                 line=dict(color="#AAAAAA", width=2), marker=dict(size=5)))
        fig.add_trace(go.Scatter(x=lbl, y=hi.values, name="High impact", mode="lines+markers",
                                 line=dict(color="#C1443A", width=2.5), marker=dict(size=5)))
    theme_layout(fig, height=140)
    fig.update_layout(margin=dict(t=6, b=4, l=4, r=4))
    return fig


def _pct_badge(pct):
    if pct is None:
        return html.Span("— no prior period", className="caption")
    if pct > 0:
        return html.Span(f"▲ {pct:+.0f}% vs previous", style={"color": "#C1443A", "fontWeight": 700})
    if pct < 0:
        return html.Span(f"▼ {pct:.0f}% vs previous", style={"color": "#1f7a3a", "fontWeight": 700})
    return html.Span("— unchanged", className="caption")


def _stage_card(name, tactics, color, cur, prev):
    sub, counts, total, pct = _stage_stats(cur, prev, tactics)
    return html.Div(className="stage-card", children=[
        html.Div(name, className="stage-head", style={"background": color}),
        html.Div(className="stage-body", children=[
            html.Div(className="stage-top", children=[
                html.Div([html.Div(t, className="stage-tactic") for t in tactics],
                         className="stage-tactics"),
                html.Div([
                    dcc.Graph(figure=_donut(counts, total, [c for *_, c in SEV]),
                              config={"displayModeBar": False}),
                    # ring segments explained in place, so the donut reads on
                    # its own without scanning down to the badges
                    html.Div(className="donut-key", children=[
                        html.Span([html.Span(className="key-dot", style={"background": col}),
                                   short], className="key-item")
                        for short, col in (("High", "#C1443A"), ("State", "#E07B39"),
                                           ("Recon", "#AAAAAA"))
                    ]),
                    html.Div(_pct_badge(pct), style={"textAlign": "center", "fontSize": "0.76rem"}),
                ], style={"flex": "1"}),
            ]),
            html.Div(className="sev-row", children=[
                html.Div([html.Span(className="sev-dot", style={"background": col}),
                          html.Span(f"{counts[key]:,}", className="sev-n"),
                          html.Div(lbl, className="sev-lbl")], className="sev-badge")
                for lbl, key, _, _, col in SEV
            ]),
            dcc.Graph(figure=_trend(sub), config={"displayModeBar": False}),
        ]),
    ])


def _top_table(rows, cols, widths=None, tooltip_col=None, row_padding="2px 6px"):
    """Sidebar list. maxWidth:0 + ellipsis is the dash idiom for "let the
    percentage widths win and clip overflow" — without it a long technique
    name ("Ingress Tool Transfer") pushes the Events column off the edge.
    The full value stays reachable on hover."""
    tips = None
    if tooltip_col:
        tips = [{tooltip_col: {"value": str(r[tooltip_col]), "type": "markdown"}} for r in rows]
    return dash_table.DataTable(
        data=rows, columns=[{"name": c, "id": c} for c in cols],
        style_data_conditional=[{"if": {"row_index": "odd"}, "backgroundColor": Y_50}],
        style_header={**TABLE_STYLE["style_header"], "fontSize": "10px", "padding": "4px 6px"},
        style_cell={
            "backgroundColor": PAPER, "color": INK_2,
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "10.5px",
            "border": "none", "borderTop": f"1px solid {LINE}",
            "padding": row_padding, "textAlign": "left",
            "overflow": "hidden", "textOverflow": "ellipsis", "maxWidth": 0,
        },
        style_cell_conditional=widths or [],
        tooltip_data=tips, tooltip_duration=None,
        style_table={"overflowX": "hidden"},
    )


def build_mitre_body(days):
    df = load_all()
    if df.empty or "tactic" not in df.columns:
        return html.Div("No data yet.", className="empty-state")

    cur, prev = _mitre_window(df, days)
    tagged = cur[cur["tactic"].notna()]
    if tagged.empty:
        return html.Div("No ATT&CK-mapped commands in this period.", className="empty-state")

    top_ip = (tagged.groupby("src_ip").size().sort_values(ascending=False).head(10)
              .reset_index(name="Events").rename(columns={"src_ip": "Source IP"}))
    top_tech = (tagged.groupby(["technique_id", "technique"]).size()
                .sort_values(ascending=False).head(10).reset_index(name="Events")
                .rename(columns={"technique_id": "ID", "technique": "Technique"}))

    cov = f"{len(tagged):,} of {len(cur):,} commands mapped ({len(tagged)/max(len(cur),1)*100:.0f}%) · " \
          f"{tagged['technique_id'].nunique()} techniques · {tagged['tactic'].nunique()} tactics"

    # techniques render as a full-width horizontal bar chart below the cards:
    # long names get the whole page width instead of a 54%-of-330px column, so
    # nothing clips, and it fills the space the old sidebar entry left empty.
    tt = top_tech.sort_values("Events")
    fig_tech = go.Figure(go.Bar(
        x=tt["Events"], y=tt["ID"] + "  " + tt["Technique"], orientation="h",
        marker=dict(color=tt["Events"], colorscale=AMBER_SCALE,
                    line=dict(color=INK, width=1.2)),
        text=tt["Events"], textposition="outside",
        textfont=dict(size=11, family="JetBrains Mono, monospace"),
        hovertemplate="%{y}<br>%{x} events<extra></extra>",
    ))
    theme_layout(fig_tech, height=max(430, 46 * len(tt)))
    fig_tech.update_layout(coloraxis_showscale=False, margin=dict(t=8, b=8, l=8, r=48))
    fig_tech.update_yaxes(title="", tickfont=dict(size=11, family="JetBrains Mono, monospace"))
    fig_tech.update_xaxes(title="Commands")

    return html.Div([
        html.Div(cov, className="caption", style={"marginBottom": "8px"}),
        html.Div(className="mitre-grid", children=[
            html.Div(className="mitre-side", children=[
                html.Div("Top 10 Attacker Sources", className="side-head"),
                _top_table(top_ip.to_dict("records"), ["Source IP", "Events"],
                           widths=[{"if": {"column_id": "Source IP"}, "width": "68%"},
                                   {"if": {"column_id": "Events"}, "width": "32%",
                                    "textAlign": "right"}],
                           row_padding="9px 6px"),
            ]),
            html.Div(className="stage-grid", children=[
                _stage_card(n, t, c, tagged, prev[prev["tactic"].notna()])
                for n, t, c in MITRE_STAGES
            ]),
        ]),
        # full page width — spans the sidebar AND all three cards, no gap
        html.Div(className="stage-card tech-card", children=[
            html.Div("TOP 10 ATTACK TECHNIQUES", className="stage-head",
                     style={"background": "#5B7FA6"}),
            html.Div(dcc.Graph(figure=fig_tech, config={"displayModeBar": False},
                               style={"width": "100%"}),
                     className="stage-body"),
        ]),
    ])


def build_mitre_page():
    return [
        html.Div(style={"display": "flex", "justifyContent": "space-between",
                        "alignItems": "center", "flexWrap": "wrap", "gap": "12px"},
                 children=[
            html.Div([
                html.H3("⚔ MITRE ATT&CK Summary"),
                html.Div("Attacker activity mapped to ATT&CK tactics and techniques",
                         className="caption"),
            ]),
            html.Div([
                html.Div("Time period", className="metric-label"),
                dcc.Dropdown(id="mitre-window", clearable=False, value=30,
                             options=[{"label": "Last 7 days", "value": 7},
                                      {"label": "Last 30 days", "value": 30},
                                      {"label": "Last 90 days", "value": 90},
                                      {"label": "All time", "value": 0}],
                             style={"width": "190px", "fontFamily": "JetBrains Mono, monospace"}),
            ]),
        ]),
        html.Div(id="mitre-content", children=build_mitre_body(30)),
    ]


@app.callback(Output("live-feed-wrap", "children"),
              Input("interval", "n_intervals"),
              State("page-store", "data"),
              State("sensor-filter-store", "data"),
              prevent_initial_call=True)
def _refresh_live_feed(_n, page, sensor_filter):
    # the feed only exists on Summary; without this guard the tick still ran
    # load_all() + rebuilt the feed while you were on another page, and the
    # result was thrown away
    if page != "Summary":
        raise PreventUpdate
    return build_live_feed(sensor_filter or "all")


@app.callback(Output("mitre-content", "children"),
              Input("mitre-window", "value"), prevent_initial_call=True)
def _refresh_mitre(days):
    # ~170ms and 7 Plotly figures per rebuild; the window dropdown gets toggled
    # back and forth, so cache each window rather than redrawing it every time
    return _cached_page(("mitre-body", days), lambda: build_mitre_body(days))


def build_auth_intelligence(df, auth_entries):
    if not auth_entries:
        return html.Div("No auth log data yet.", className="caption")

    auth_df = pd.DataFrame(auth_entries)
    login_df = auth_df[auth_df.get("auth_type", pd.Series(dtype=object)) != "tcp_connect"].copy()

    if login_df.empty:
        return html.Div("No login attempts recorded yet.", className="caption")

    pw_counts = login_df["password"].value_counts().head(10).reset_index()
    pw_counts.columns = ["Password", "Attempts"]
    fig_pw = px.bar(pw_counts, x="Attempts", y="Password", orientation="h",
                     color="Attempts", color_continuous_scale=AMBER_SCALE)
    theme_layout(fig_pw, height=300)
    fig_pw.update_layout(coloraxis_showscale=False)
    fig_pw.update_yaxes(title="", autorange="reversed")

    user_counts = login_df["username"].value_counts().head(10).reset_index()
    user_counts.columns = ["Username", "Attempts"]
    fig_user = px.bar(user_counts, x="Attempts", y="Username", orientation="h",
                       color="Attempts", color_continuous_scale=AMBER_SCALE)
    theme_layout(fig_user, height=300)
    fig_user.update_layout(coloraxis_showscale=False)
    fig_user.update_yaxes(title="", autorange="reversed")

    total_logins = len(login_df)
    unique_pw = login_df["password"].nunique()
    unique_users = login_df["username"].nunique()
    tcp_scans = len(auth_df[auth_df.get("auth_type", pd.Series(dtype=object)) == "tcp_connect"])
    unique_ips = login_df["src_ip"].nunique()
    top_pw = login_df["password"].value_counts()

    stat_box = html.Div(className="stat-box", children=[
        html.Div([" Login attempts: ", html.B(f"{total_logins}")]),
        html.Div([" Unique passwords: ", html.B(f"{unique_pw}")]),
        html.Div([" Unique usernames: ", html.B(f"{unique_users}")]),
        html.Div([" Unique source IPs: ", html.B(f"{unique_ips}")]),
        html.Div([" TCP scan probes: ", html.B(f"{tcp_scans}")]),
        html.Hr(),
        html.Div(["Most tried: ", html.Span(f"{top_pw.index[0]}", style={"color": "#dc3545", "fontWeight": "700"}),
                  f" ({top_pw.iloc[0]}×)"]),
    ])

    ac = df["agent"].value_counts().reset_index()
    ac.columns = ["agent", "count"]
    fig_donut = px.pie(ac, names="agent", values="count", color="agent",
                        color_discrete_map=AGENT_COLOR_AMBER, hole=0.55)
    fig_donut.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", font=dict(family="JetBrains Mono, monospace", color=INK_3),
        margin=dict(t=10, b=10, l=10, r=10), height=280,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.1),
    )
    fig_donut.update_traces(textposition="inside", textinfo="percent+label",
                             marker=dict(line=dict(color=PAPER, width=2)))

    return html.Div(className="grid-4", children=[
        html.Div([html.Div("Top Passwords", style={"fontWeight": "700", "marginBottom": "8px"}),
                  dcc.Graph(figure=fig_pw, config={"displayModeBar": False})]),
        html.Div([html.Div("Top Usernames", style={"fontWeight": "700", "marginBottom": "8px"}),
                  dcc.Graph(figure=fig_user, config={"displayModeBar": False})]),
        html.Div([html.Div("Auth Breakdown", style={"fontWeight": "700", "marginBottom": "8px"}), stat_box]),
        html.Div([html.Div("Agent Distribution", style={"fontWeight": "700", "marginBottom": "8px"}),
                  dcc.Graph(figure=fig_donut, config={"displayModeBar": False})]),
    ])


_SCOPE_LABEL = {"all": "All Sessions", "current_session": "Current Session",
                "selected_session": "Selected Session", "last_24h": "Last 24 Hours"}


def _ioc_status_text(ioc_data):
    if not ioc_data:
        return "No analysis generated yet — click \"Generate Intelligence\" to run it."
    scope = _SCOPE_LABEL.get(ioc_data.get("scope"), ioc_data.get("scope", "all"))
    return f"Last updated: {ioc_data['generated_at']}  ·  scope: {scope}"


def _ioc_table_rows(recs):
    return [
        {
            "Type": r["type"],
            "Value": r["value"][:64],
            "Count": r["count"],
            "Sessions": r["session_count"],
            "Max FI": r["max_fi"],
            "First Seen": str(r["first_seen"] or ""),
            "Last Seen": str(r["last_seen"] or ""),
        }
        for r in recs[:200]
    ]


def _render_ioc_body(ioc_data):
    """Pure rendering — takes an already-computed snapshot dict (or None) and
    builds the metrics/chart/table. Never calls build_iocs() itself, so
    displaying a snapshot is always instant regardless of how long it took
    to generate."""
    if ioc_data is None:
        return html.Div(
            "No analysis generated yet. Click \"Generate Intelligence\" above "
            "to extract indicators from all collected sessions.",
            className="empty-state",
        )

    recs = ioc_data.get("recs") or []
    if not recs:
        return html.Div("Analysis complete — no indicators found in the current logs.",
                         className="empty-state")

    from collections import Counter
    by_type = Counter(r["type"] for r in recs)
    ip_types = {"ipv4", "ipv6"}
    hash_types = {"md5", "sha1", "sha256"}
    wallet_types = {"wallet_btc", "wallet_eth", "wallet_xmr"}

    n_ip       = sum(n for t, n in by_type.items() if t in ip_types)
    n_domain_url = by_type.get("domain", 0) + by_type.get("url", 0)
    n_hash     = sum(n for t, n in by_type.items() if t in hash_types)
    n_wallet   = sum(n for t, n in by_type.items() if t in wallet_types)
    n_cred     = by_type.get("credential", 0)

    metrics = html.Div(className="metric-row", children=[
        html.Div(className="metric-card", children=[
            html.Div("Total Indicators", className="metric-label"),
            html.Div(f"{len(recs)}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("IPs", className="metric-label"),
            html.Div(f"{n_ip}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("Domains / URLs", className="metric-label"),
            html.Div(f"{n_domain_url}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("File Hashes", className="metric-label"),
            html.Div(f"{n_hash}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("Wallet Addresses", className="metric-label"),
            html.Div(f"{n_wallet}", className="metric-value"),
        ]),
        html.Div(className="metric-card", children=[
            html.Div("Credentials Tried", className="metric-label"),
            html.Div(f"{n_cred}", className="metric-value"),
        ]),
    ])

    type_df = pd.DataFrame(sorted(by_type.items(), key=lambda kv: kv[1], reverse=True),
                            columns=["type", "count"])
    fig_type = px.bar(type_df, x="count", y="type", orientation="h",
                       color="count", color_continuous_scale=AMBER_SCALE)
    theme_layout(fig_type, height=max(220, 34 * len(type_df)))
    fig_type.update_layout(coloraxis_showscale=False)
    fig_type.update_yaxes(title="", autorange="reversed")
    fig_type.update_xaxes(title="Indicators")

    # category filter pills — "All" + one per IOC type actually present,
    # ordered by frequency (same order as the chart above)
    cat_order = ["all"] + [t for t, _ in by_type.most_common()]
    cat_buttons = [
        html.Button(
            "All" if cat == "all" else cat,
            id={"type": "ioc-cat-btn", "cat": cat},
            className="nav-pill active" if cat == "all" else "nav-pill",
            n_clicks=0,
            style={"padding": "6px 12px", "fontSize": "0.8rem"},
        )
        for cat in cat_order
    ]

    ioc_table = dash_table.DataTable(
        id="ioc-table",
        data=_ioc_table_rows(recs),
        columns=[{"name": c, "id": c} for c in
                 ["Type", "Value", "Count", "Sessions", "Max FI", "First Seen", "Last Seen"]],
        style_data_conditional=[
            {"if": {"row_index": "odd"}, "backgroundColor": Y_50},
            {"if": {"filter_query": "{Max FI} >= 3", "column_id": "Max FI"},
             "color": "#dc3545", "fontWeight": "bold"},
        ],
        page_size=15,
        style_header=TABLE_STYLE["style_header"],
        style_cell=TABLE_STYLE["style_cell"],
        style_table=TABLE_STYLE["style_table"],
    )

    return [
        metrics,
        html.Hr(className="divider"),
        html.Div("Indicators by Type", className="section-header"),
        dcc.Graph(figure=fig_type, config={"displayModeBar": False}),
        html.Div("Top Indicators (by severity, then frequency)", className="section-header"),
        dcc.Store(id="ioc-cat-filter-store", data="all"),
        html.Div(cat_buttons, style={"display": "flex", "flexWrap": "wrap",
                                       "gap": "8px", "marginBottom": "10px"}),
        html.Div(f"{len(recs)} unique indicators — showing top {len(recs[:200])}",
                  id="ioc-table-caption", className="caption", style={"marginBottom": "6px"}),
        ioc_table,
    ]


def build_threat_intel_page(ioc_data=None):
    """Page SHELL only — title, last-updated caption, Generate button, and an
    ioc-content div pre-filled with whatever's already in ioc-store. Does NOT
    call build_iocs()/build_ioc_snapshot() itself — this must stay fast, since
    it re-renders every time you navigate to this page (main.py's render_router)."""
    scope_picker = dcc.RadioItems(
        id="ioc-scope",
        options=[
            {"label": " Current Session", "value": "current_session"},
            {"label": " Last 24 Hours",   "value": "last_24h"},
            {"label": " All Sessions",    "value": "all"},
        ],
        value=(ioc_data or {}).get("scope", "all"),
        inline=True,
        labelStyle={"marginRight": "16px", "fontSize": "0.85rem", "fontWeight": "600"},
        style={"fontFamily": "JetBrains Mono, monospace"},
    )

    toolbar = html.Div(
        style={"display": "flex", "justifyContent": "space-between",
               "alignItems": "center", "flexWrap": "wrap", "gap": "12px"},
        children=[
            html.Div([
                html.H3("🛰 Threat Intel", style={"marginBottom": "4px"}),
                html.Div(_ioc_status_text(ioc_data), id="ioc-last-updated", className="caption"),
            ]),
            html.Div([
                html.Div("Scope", className="metric-label", style={"marginBottom": "6px"}),
                scope_picker,
            ]),
            dcc.Loading(
                id="ioc-loading", type="circle", color=Y_700,
                children=html.Div(id="ioc-generate-status", children=[
                    html.Button("🔄 Generate Intelligence", id="generate-ioc-btn",
                                className="refresh-btn", n_clicks=0),
                ]),
            ),
            html.Button("⬇ Export STIX", id="export-stix-btn",
                        className="refresh-btn", n_clicks=0),
            dcc.Download(id="stix-download"),
        ],
    )

    return [
        toolbar,
        html.Div(id="ioc-content", children=_render_ioc_body(ioc_data)),
    ]


def build_session_explorer_page(selected_session=None):
    df = load_all()
    if df.empty:
        return [html.H3("🔎 Session Explorer"), html.Div("No session data yet.", className="empty-state")]

    sessions = df.groupby("session_id").agg(
        commands=("cmd", "count"), peak_fi=("fi_score", "max"),
        src_ip=("src_ip", "first"), start_time=("timestamp", "min"), end_time=("timestamp", "max"),
    ).reset_index().sort_values("start_time", ascending=False)
    sessions["threat"] = sessions["peak_fi"].map(lambda x: THREAT_LEVEL[int(x)][0])
    sessions["start_time"] = sessions["start_time"].dt.strftime("%Y-%m-%d %H:%M:%S")

    session_ids = sessions["session_id"].tolist()
    if selected_session not in session_ids:
        selected_session = session_ids[0] if session_ids else None

    table_df = sessions.rename(columns={
        "session_id": "Session", "commands": "Cmds", "peak_fi": "Peak FI",
        "src_ip": "Src IP", "start_time": "Start", "threat": "Threat",
    })[["Session", "Src IP", "Cmds", "Peak FI", "Threat", "Start"]]

    sessions_table = dash_table.DataTable(
        data=table_df.to_dict("records"),
        columns=[{"name": c, "id": c} for c in table_df.columns],
        **TABLE_STYLE,
    )

    dropdown = dcc.Dropdown(
        id="session-dropdown", className="dd",
        options=[{"label": s, "value": s} for s in session_ids],
        value=selected_session, clearable=False,
        style={"maxWidth": "420px", "fontFamily": "JetBrains Mono, monospace"},
    )

    detail = build_session_detail(df, selected_session) if selected_session else html.Div()

    return [
        html.H3("🔎 Session Explorer"),
        sessions_table,
        html.Hr(className="divider"),
        html.Div("Drill into session", style={"fontWeight": "600", "marginBottom": "8px"}),
        dropdown,
        html.Hr(className="divider"),
        html.Div(id="session-detail", children=detail),
    ]


def build_session_detail(df, selected):
    # Drill-down re-queries this one session rather than slicing `df`: load_all()
    # drops `response` for speed, and the replay below is the one view that
    # wants it. One session is a handful of rows, so fetching it in full is free.
    rows = storage.query_session(selected)
    sdf = pd.DataFrame(rows) if rows else df[df["session_id"] == selected].copy()
    if sdf.empty:
        return html.Div()
    if "response" not in sdf.columns:
        sdf["response"] = ""
    sdf["timestamp"] = pd.to_datetime(sdf.get("timestamp", ""), errors="coerce")
    sdf["fi_score"]  = sdf.get("fi_score", 0).fillna(0).astype(int)

    peak = int(sdf["fi_score"].max())
    tl, tc, ti = THREAT_LEVEL[peak]

    metrics = html.Div(className="metric-row", children=[
        html.Div(className="metric-card", children=[html.Div("Commands", className="metric-label"), html.Div(f"{len(sdf)}", className="metric-value")]),
        html.Div(className="metric-card", children=[html.Div("Peak FI", className="metric-label"), html.Div(f"{peak} — {FI_LABEL[peak]}", className="metric-value", style={"fontSize": "1.1rem"})]),
        html.Div(className="metric-card", children=[html.Div("Threat", className="metric-label"), html.Div(f"{ti} {tl}", className="metric-value", style={"fontSize": "1.2rem"})]),
        html.Div(className="metric-card", children=[html.Div("Agents", className="metric-label"), html.Div(f"{sdf['agent'].nunique()}", className="metric-value")]),
    ])
    session_cmds = sdf.sort_values("timestamp")
    replay_components = []
    for _, row in session_cmds.iterrows():
        ts = row["timestamp"].strftime("%H:%M:%S") if pd.notna(row["timestamp"]) else "??:??:??"
        cmd = str(row.get("cmd", ""))[:100]
        fi = int(row.get("fi_score", 0))
        agent = row.get("agent", "unknown")
        resp = str(row.get("response", ""))[:60]

        replay_components.append(html.Div([
            html.Span(f"[{ts}]", className="term-time"),
            html.Span(f" FI:{fi} ", className=f"term-fi{fi}"),
            html.Span(f"[{agent}] ", className=f"term-agent-{agent}"),
            html.Span(f"$ {cmd}", className="term-cmd"),
        ], className="term-line"))

        if resp.strip():
            replay_components.append(html.Div([
                html.Span("       ", className="term-time"),
                html.Span(f"→ {resp.replace(chr(10), ' ')}", style={"color": "#8b949e"}),
            ], className="term-line"))

    replay = html.Div(className="terminal-feed", children=[
        html.Div(className="term-chrome", children=[
            html.Span(className="term-dot dot-r"), html.Span(className="term-dot dot-y"), html.Span(className="term-dot dot-g"),
            html.Span(f"session — {selected}", className="term-chrome-title"),
        ]),
        html.Div(f"▶ Session Replay — {selected}", className="term-header"),
        html.Div(className="term-body", style={"maxHeight": "350px"}, children=replay_components),
    ])
    fi_c = sdf["fi_score"].value_counts().reindex([0, 1, 2, 3, 4], fill_value=0).reset_index()
    fi_c.columns = ["FI", "Count"]
    fi_c["Label"] = fi_c["FI"].map(FI_LABEL)
    fig_bar = px.bar(fi_c, x="Count", y="Label", orientation="h", color="FI",
                      color_discrete_map={i: FI_COLOR[i] for i in range(5)}, text="Count")
    theme_layout(fig_bar, height=240)
    fig_bar.update_yaxes(title="")

    danger_cards = []
    for _, row in sdf[sdf["fi_score"] >= 2].sort_values("fi_score", ascending=False).head(8).iterrows():
        fi = int(row["fi_score"])
        cmd_display = str(row.get("cmd", "")).replace("<", "&lt;").replace(">", "&gt;")
        danger_cards.append(html.Div(className="danger-card", style={"borderLeft": f"5px solid {FI_COLOR[fi]}"}, children=[
            html.Div(style={"display": "flex", "justifyContent": "space-between"}, children=[
                html.Span(f"FI:{fi} {FI_LABEL[fi]}", style={"color": FI_COLOR[fi], "fontSize": "0.75rem", "fontWeight": "700"}),
                html.Span(f"▶ {row['agent']}", style={"color": AGENT_COLOR.get(row["agent"], "#6c757d"), "fontSize": "0.75rem"}),
            ]),
            html.Div(f"$ {cmd_display}", style={"fontSize": "0.9rem"}),
        ]))

    left = html.Div([html.Div("FI Distribution", className="section-header"),
                      dcc.Graph(figure=fig_bar, config={"displayModeBar": False})])
    right = html.Div([html.Div("⚠️ Dangerous Commands", className="section-header"), *danger_cards])

    hist = sdf[["timestamp", "cmd", "agent", "fi_score", "latency_ms", "response"]].copy()
    hist["timestamp"] = hist["timestamp"].dt.strftime("%H:%M:%S")
    hist["fi_score"] = hist["fi_score"].map(lambda x: f"{x} {FI_LABEL[int(x)]}")
    hist["latency_ms"] = hist["latency_ms"].map(lambda x: f"{x:.0f}ms")
    hist["response"] = hist["response"].astype(str).str[:80]
    hist = hist.rename(columns={"timestamp": "Time", "cmd": "Command", "agent": "Agent",
                                  "fi_score": "FI", "latency_ms": "Latency", "response": "Response"})
    hist_table = dash_table.DataTable(data=hist.to_dict("records"),
                                       columns=[{"name": c, "id": c} for c in hist.columns],
                                       **TABLE_STYLE)

    return html.Div([
        metrics, html.Hr(className="divider"), replay,
        html.Div(className="grid-2", children=[left, right]),
        html.Hr(className="divider"),
        html.Div("Full Command History", className="section-header"),
        hist_table,
    ])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)
