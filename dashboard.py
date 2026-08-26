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


def estimate_savings(df):
    """What HydraPoT's routing saved, over the WHOLE visible dataset.

    Scoped to the WHOLE visible dataset on purpose. (An earlier month-scoped
    cost helper lived here; it was removed once the KPI strip stopped using it,
    because month-to-date reads as zero on historical data.) This is the
    research claim: every command answered by a cheaper agent is one an
    all-cloud honeypot would have paid for.

      cloud saved  — commands NOT sent to cloud x the same per-command rate
                     CLOUD_COST_PER_CLOUD_CMD, i.e. vs an all-cloud baseline.
      energy saved — commands answered by Cowrie (deterministic, no GPU) x the
                     measured average energy of an on-device command, i.e. vs
                     an all-LLM baseline.

    Both are estimates against an explicit baseline, not measured counterfactuals.
    """
    out = {"cloud_saved_usd": 0.0, "cloud_avoided_pct": 0.0,
           "energy_saved_thb": 0.0, "energy_avoided_pct": 0.0,
           "n_total": 0, "n_cloud": 0, "n_switches": 0}
    if df is None or df.empty or "agent" not in df.columns:
        return out

    n_total = len(df)
    n_cloud = int((df["agent"] == "cloud").sum())
    n_od    = int((df["agent"] == "on_device").sum())
    n_cow   = int((df["agent"] == "cowrie").sum())
    out.update(n_total=n_total, n_cloud=n_cloud)

    out["cloud_saved_usd"]   = (n_total - n_cloud) * CLOUD_COST_PER_CLOUD_CMD
    out["cloud_avoided_pct"] = (n_total - n_cloud) / n_total * 100.0

    # average energy of one on-device command, measured from real latency
    if n_od and "latency_ms" in df.columns:
        od_ms = float(df.loc[df["agent"] == "on_device", "latency_ms"]
                      .fillna(0).clip(upper=LATENCY_CAP_MS).sum())
        kwh_per_cmd = (GPU_AVG_WATT * (od_ms / 1000.0 / 3600.0) / 1000.0) / n_od
        if _kwh_to_thb and _POWER_TARIFF:
            out["energy_saved_thb"] = _kwh_to_thb(kwh_per_cmd * n_cow, _POWER_TARIFF)["total_thb"]
    if n_cow + n_od:
        out["energy_avoided_pct"] = n_cow / (n_cow + n_od) * 100.0

    # how often routing actually changed agent mid-session — the multi-agent
    # behaviour in one number
    if {"session_id", "seq"} <= set(df.columns):
        # one pass over the sorted arrays: a switch is "agent changed AND we are
        # still inside the same session". groupby().apply() ran a Python lambda
        # per session for the same answer.
        srt = df.sort_values(["session_id", "seq"])
        ag, sid = srt["agent"].to_numpy(), srt["session_id"].to_numpy()
        out["n_switches"] = int(((ag[1:] != ag[:-1]) & (sid[1:] == sid[:-1])).sum())
    return out


_health_cache = {"v": None, "ts": 0}


def agent_health():
    """Real component checks for the sidebar status panel.

    Every row is an actual probe, never a hardcoded "Online" — a status light
    that is always green tells an operator nothing. Cheap enough to run behind
    a short TTL: the only network call is one non-blocking TCP connect.

    Returns [(name, ok, detail)]."""
    now = time.time()
    if _health_cache["v"] is not None and now - _health_cache["ts"] < 15:
        return _health_cache["v"]

    import socket
    rows = []

    try:
        cfg = _load_config()
    except Exception:
        cfg = None

    # Honeypot — is the SSH front door actually accepting connections? This is
    # the row that answers "is HydraPoT running at all", so it comes first.
    # Without it the panel could read all-green while nothing was listening.
    try:
        hp_host = cfg.honeypot.host
        hp_port = int(cfg.honeypot.port)
        with socket.socket() as s:
            s.settimeout(0.35)
            up = s.connect_ex((hp_host, hp_port)) == 0
        rows.append(("Honeypot", up, f"{hp_host}:{hp_port}"))
    except Exception:
        rows.append(("Honeypot", False, "not listening"))

    # Router — config parses and a routing table exists
    try:
        n = len(getattr(cfg.routing, "fi_routing", {}) or {})
        rows.append(("Router", n > 0, f"{n} FI bands"))
    except Exception:
        rows.append(("Router", False, "config error"))

    # Cowrie — is the backend actually accepting connections?
    try:
        host = cfg.agents.cowrie.host, cfg.agents.cowrie.port
        with socket.socket() as s:
            s.settimeout(0.35)
            ok = s.connect_ex((host[0], int(host[1]))) == 0
        rows.append(("Cowrie Agent", ok, f"{host[0]}:{host[1]}"))
    except Exception:
        rows.append(("Cowrie Agent", False, "unreachable"))

    # Local LLM — enabled AND the weights are actually on disk
    try:
        od = cfg.agents.on_device
        gguf = getattr(od, "gguf_file", "") or ""
        found = bool(gguf) and any(
            os.path.basename(p) == os.path.basename(gguf)
            for p in glob.glob(os.path.expanduser("~/.cache/huggingface/**/*.gguf"), recursive=True)
        )
        rows.append(("Local LLM", bool(getattr(od, "enabled", False)) and found,
                     os.path.basename(gguf) or "no model"))
    except Exception:
        rows.append(("Local LLM", False, "unavailable"))

    # Cloud LLM — enabled AND the API key is present in the environment
    try:
        cl = cfg.agents.cloud
        keyed = bool(os.environ.get(getattr(cl, "api_key_env", "") or "", ""))
        rows.append(("Cloud LLM", bool(getattr(cl, "enabled", False)) and keyed,
                     getattr(cl, "model", "") if keyed else "no API key"))
    except Exception:
        rows.append(("Cloud LLM", False, "unavailable"))

    # SIEM — an export plugin is configured and switched on
    try:
        import yaml
        ok, detail = False, "not configured"
        for fp in glob.glob(os.path.join(_HERE, "plugins", "export", "*.yml")):
            y = yaml.safe_load(open(fp)) or {}
            if y.get("enabled"):
                ok, detail = True, os.path.basename(fp).replace(".yml", "")
                break
            detail = "disabled"
        rows.append(("SIEM Export", ok, detail))
    except Exception:
        rows.append(("SIEM Export", False, "unavailable"))

    _health_cache.update(v=rows, ts=now)
    return rows


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

# The DB holds both real honeypot traffic and the NSC experiment runs, which
# share the same tables. Experiment harnesses put a run label in src_ip
# ("eval_sync_on", "partc_cloud_12580") where real traffic has an IP, so the
# label prefix is what separates them. Presentation-only: the data is untouched
# on disk, and NSC's own scripts read it exactly as before.
EXPERIMENT_SRC_PREFIXES = (
    "eval_", "parta_", "partb_", "partc_", "hrreplay_", "bench_",
    "ml4net", "cyberlab",
)


def drop_experiment_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Hide NSC experiment traffic from the dashboard.

    Without this the headline numbers are dominated by benchmark runs — 130,643
    of 132,282 rows — so "Unique Attackers" counts experiment runs rather than
    attackers."""
    if df.empty or "src_ip" not in df.columns:
        return df
    # str.startswith takes a tuple — one pass instead of one per prefix
    return df[~df["src_ip"].astype(str).str.startswith(EXPERIMENT_SRC_PREFIXES, na=False)]


def load_all() -> pd.DataFrame:
    now = time.time()
    if _cache["all_df"] is not None and (now - _cache["all_ts"]) < TTL:
        return _cache["all_df"]

    # Deliberately NOT load_raw_session_rows(): this runs on every page render,
    # and it never reads `response`. Skipping that column alone is ~460ms ->
    # ~145ms. Anything here that does need it should use storage.query_session().
    df = storage.query_all_df()
    df = drop_experiment_rows(df)
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

    data = storage.query_auth()
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

# Every dcc.Graph uses this. `responsive` is the important half: without it
# Plotly measures the container ONCE at mount and bakes that pixel width into
# the SVG. Collapsing the sidebar widens the content area via CSS, but the
# chart keeps its old width — which is why bars looked lopsided (chart offset
# inside a container that had grown around it). With responsive:True Plotly
# watches the container and re-lays out on resize.
GRAPH_CONFIG = {"displayModeBar": False, "responsive": True}


def theme_layout(fig, height=None, legend=False):
    layout_kwargs = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="JetBrains Mono, monospace", color=INK_3, size=12),
        margin=dict(t=10, b=10, l=10, r=10),
        # let the figure take its width from the container instead of pinning
        # whatever width happened to exist at first render
        autosize=True,
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

INK         = "#171512"   # primary text / borders
INK_2       = "#3A342C"
INK_3       = "#6F685C"   # muted text
PAPER       = "#FFFCF2"   # page background — the original HydraPoT cream
CARD        = "#FFFFFF"   # cards sit lighter than the page so panels lift off it
Y_50        = "#FDF6E3"
Y_100       = "#FBEFC9"
Y_200       = "#F7E3A1"
Y_300       = "#F6CF5C"
Y_400       = "#F5B21B"   # primary HydraPoT accent
Y_500       = "#E09B10"
Y_700       = "#9A6B08"
LINE        = "rgba(38, 35, 31, 0.14)"
LINE_STRONG = "rgba(38, 35, 31, 0.28)"

# Semantic colours — used ONLY for what they mean, never decoratively.
ORANGE      = "#C45A0A"   # attack / activity volume
CRITICAL    = "#D92D20"   # critical + high severity only
SUCCESS     = "#159447"   # healthy / online / savings
SIDEBAR_BG  = "#171512"   # dark charcoal rail
SIDEBAR_FG  = "#CFC7B8"
SIDEBAR_MUT = "#8A8175"
TERMINAL_BG = "#171512"

AMBER_SCALE = [Y_300, Y_500, Y_700]
AGENT_COLOR_AMBER = {"cowrie": Y_500, "on_device": Y_300, "cloud": INK, "unknown": INK_3}

# ── GeoIP ─────────────────────────────────────────────────────────────────────

_geo_reader = None
_geo_reader_loaded = False
_geo_cache: dict = {}

# Agent identity — one label and one colour per agent, shared by every panel.
# These were previously inlined in both _hydrapot_intel() and _agent_donut(),
# where the colour maps had silently diverged (cowrie grey in one, amber in
# the other, side by side on the same screen).
AGENT_LABEL = {"cowrie": "Cowrie (Traditional)",
               "on_device": "On-device LLM",
               "cloud": "Cloud LLM"}
AGENT_COLOR = {"cowrie": Y_300, "on_device": Y_400, "cloud": ORANGE}


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
      /* `clip`, NOT `hidden`. Both stop sideways scrolling, but `hidden` makes
         overflow-y compute to `auto`, which turns body into a scroll
         container — and then the sticky sidebar anchors to body (which scrolls
         away with the page) instead of the viewport, so it never sticks.
         `clip` contains the overflow without creating a scroll container, so
         sticky keeps working. */
      overflow-x: clip;
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
      width: 100%;
      max-width: 100vw;
      /* NO overflow here on purpose. `overflow-x: hidden` used to sit on this
         rule, and per spec that makes overflow-y compute to `auto` — turning
         .app-shell into a scroll container. position:sticky then resolves
         against .app-shell instead of the viewport, so the sidebar would
         scroll away exactly as before and the sticky would look broken for no
         visible reason. Horizontal overflow is still contained: .content has
         its own `overflow-x: hidden` + `min-width: 0`, which is what actually
         fixed the sideways-scrolling page. */
    }
    /* the nav sidebar must never be what widens the layout */
    .sidebar { flex-shrink: 0; }

    /* Sidebar */
    .sidebar {
  width: 260px; flex-shrink:0;
  background: var(--y-50);
  border-right: 2px solid var(--ink);
  padding: 70px 20px 24px 20px;   /* was: 24px 20px — extra top padding clears the floating button */
  display:flex; flex-direction:column; gap:14px;
  transition: width 0.2s ease, padding 0.2s ease, opacity 0.15s ease;

  /* Stick to the viewport instead of scrolling away with the page. On a long
     Summary page the nav used to disappear upward and leave a blank yellow
     column behind it.
       align-self:flex-start — REQUIRED. A flex child defaults to
         align-self:stretch, which makes the sidebar as tall as the whole
         scrolling page; sticky then has nothing to travel within and never
         engages. This one line is what makes position:sticky actually work.
       max-height/overflow-y — if the nav is ever taller than the viewport it
         scrolls on its own rather than being clipped.
       overflow-x stays hidden so the width collapse animation still clips. */
  position: sticky;
  top: 0;
  align-self: flex-start;
  /* height, NOT max-height. align-self:flex-start is required for sticky to
     engage, but it also stops the sidebar stretching to the container height —
     so with max-height the column was only as tall as its own content and the
     yellow panel + right border ended partway down the screen, leaving bare
     page below it. A fixed 100vh keeps it a full-height column at every scroll
     position (box-sizing is border-box globally, so padding is included). */
  height: 100vh;
  overflow-y: auto;
  overflow-x: hidden;

  /* Keep the overflow behaviour, hide the scrollbar chrome. On a short window
     the nav is taller than 100vh, so `overflow-y: auto` drew a second
     scrollbar down the middle of the layout next to the page's own. The nav
     still scrolls (wheel/trackpad/keyboard) — only the bar is hidden, which is
     the usual treatment for a short nav column. */
  scrollbar-width: none;        /* Firefox */
  -ms-overflow-style: none;     /* old Edge/IE */
}
.sidebar::-webkit-scrollbar { width: 0; height: 0; }   /* Chrome/Safari */
.sidebar.collapsed {
  width: 0;
  padding: 70px 0 24px 0;   /* keep top padding consistent on collapse */
  opacity: 0;
  pointer-events: none;
}
    .sidebar-logo { font-size:1.3rem; font-weight:800; display:flex; align-items:center; gap:10px; white-space:nowrap; }

    /* The logo already carries its own drop shadow, so it needs no border or
       box-shadow from us. flex-shrink:0 keeps it square while the sidebar
       animates its width on collapse — without it the mark squashes. */
    .brand-mark { width:30px; height:30px; flex-shrink:0; display:block; }
    .brand-mark-lg { width:34px; height:34px; }
    .page-title { display:flex; align-items:center; gap:11px; }
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
    /* ════════════════════════════════════════════════════════════════════
       SOC REDESIGN — appended so these rules win over the originals above.
       Layout/appearance only; no data, callback or id is affected.
       ════════════════════════════════════════════════════════════════════ */

    /* ── dark sidebar rail ────────────────────────────────────────────── */
    .sidebar {
    width: 232px;
    background: """ + SIDEBAR_BG + """;
    border-right: 1px solid """ + SIDEBAR_BG + """;
    padding: 22px 16px 18px 16px;
    overflow-x: hidden;          /* keep — needed for the collapse animation */
    transition: width 0.2s ease, padding 0.2s ease, opacity 0.15s ease;
    }
    .sidebar-logo { color: #fff; font-size: 1.18rem; }
    .sidebar-caption { color: """ + SIDEBAR_MUT + """; font-size: 0.72rem; line-height: 1.55;
                        font-family: 'Inter', sans-serif; }
    .sidebar-divider { border-top: 1px solid rgba(255,255,255,0.10); margin: 4px 0; }

    .nav-pill {
      background: transparent; color: """ + SIDEBAR_FG + """;
      border: none; border-radius: 8px;
      padding: 9px 12px; font-size: 0.87rem; font-weight: 600;
      text-align: left; width: 100%; cursor: pointer;
      display: flex; align-items: center; gap: 10px;
    }
    .nav-pill:hover { background: rgba(255,255,255,0.06); color: #fff; }
    /* active = warm dark-brown wash + gold text + gold edge, per spec */
    .nav-pill.active {
      background: rgba(245,178,27,0.13); color: """ + Y_400 + """;
      box-shadow: inset 2px 0 0 """ + Y_400 + """;
    }

    .sidebar .toggle-row { color: """ + SIDEBAR_MUT + """; font-size: 0.7rem;
                            letter-spacing: 0.08em; text-transform: uppercase; }
    .sidebar .source-cap { color: """ + SIDEBAR_MUT + """; font-size: 0.66rem; }
    .refresh-btn { background: rgba(255,255,255,0.07); color: """ + SIDEBAR_FG + """;
                    border: 1px solid rgba(255,255,255,0.12); border-radius: 8px;
                    padding: 8px 10px; font-size: 0.78rem; cursor: pointer; }
    .refresh-btn:hover { background: """ + Y_400 + """; color: """ + INK + """; }

    /* agent health box */
    .hp-status { border: 1px solid rgba(255,255,255,0.13); border-radius: 10px;
                  padding: 11px 12px; margin-top: 4px; }
    .hp-status-h { color: """ + Y_400 + """; font-size: 0.64rem; font-weight: 800;
                    letter-spacing: 0.1em; margin-bottom: 8px; }
    .hp-status-row { display:flex; align-items:center; justify-content:space-between;
                      font-size: 0.75rem; color: """ + SIDEBAR_FG + """; padding: 3px 0; }
    .hp-dot { width:7px; height:7px; border-radius:50%; display:inline-block; margin-right:7px; }
    .hp-tally { text-align:center; border:1px solid rgba(255,255,255,0.13);
                 border-radius:10px; padding:10px; margin-top:10px; }
    .hp-tally-n { font-size:1.5rem; font-weight:800; color:""" + SUCCESS + """; }
    .hp-tally-l { font-size:0.6rem; letter-spacing:0.1em; color:""" + SIDEBAR_MUT + """; }

    /* ── page chrome ──────────────────────────────────────────────────── */
    .content { padding: 20px 24px; max-width: none; }

    /* The toggle is position:fixed, so it floats over whatever is beneath it.
       It therefore has to move as the sidebar does, or it covers something:
         sidebar open      -> park it at the sidebar's right edge, clear of the
                              logo (the old 70px sidebar top-padding that used
                              to clear it is gone in this layout)
         sidebar collapsed -> back to the far left, and the content gains
                              matching left padding so it can't sit on top of
                              the page header.
       Both states use the transition already on .sidebar-toggle. */
    /* Horizontal filter chips (IOC categories, DB tables).
       These used .nav-pill, which this redesign turned into a full-width flex
       row for the vertical sidebar — so they stacked into a column. They need
       their own class: a filter row is horizontal, and reusing the nav's class
       means any future nav restyle silently breaks it again. */
    .chip-row { display:flex; flex-wrap:wrap; gap:8px; margin: 4px 0 14px; }
    .chip {
      background: """ + CARD + """; color: """ + INK_2 + """;
      border: 1.5px solid """ + LINE_STRONG + """; border-radius: 9px;
      padding: 8px 15px; font-size: 0.84rem; font-weight: 700;
      font-family: 'Inter', sans-serif; letter-spacing: 0.01em;
      cursor: pointer; white-space: nowrap; width: auto;
      display: inline-flex; align-items: center; gap: 7px; line-height: 1.1;
    }
    .chip:hover { background: """ + Y_100 + """; border-color: """ + INK + """; }
    .chip.active {
      background: """ + Y_400 + """; color: """ + INK + """;
      border-color: """ + INK + """;
    }
    .chip .chip-n { font-family:'JetBrains Mono',monospace; font-size:0.75rem;
                     font-weight:700; opacity:0.72; }

    /* Action buttons on light pages (Generate Intelligence, Export STIX).
       They previously borrowed .refresh-btn, which this redesign restyled for
       the DARK sidebar — a 7%-white fill with light-grey text, i.e. all but
       invisible on cream. Same class-sharing trap as .nav-pill.
       Light fill at rest so they read as pressable, stronger on hover. */
    .btn {
      border-radius: 9px; padding: 9px 16px; cursor: pointer;
      font-family: 'Inter', sans-serif; font-size: 0.84rem; font-weight: 700;
      display: inline-flex; align-items: center; gap: 8px; width: auto;
      border: 1.5px solid """ + INK + """; color: """ + INK + """;
      transition: background 0.15s ease, box-shadow 0.15s ease, transform 0.05s ease;
    }
    .btn:active { transform: translateY(1px); }

    /* primary — the main action on the page */
    .btn-primary { background: """ + Y_200 + """; }
    .btn-primary:hover { background: """ + Y_400 + """; box-shadow: 0 2px 0 """ + INK + """; }

    /* secondary — available, but visibly not the headline action */
    .btn-secondary { background: """ + CARD + """; border-color: """ + LINE_STRONG + """; }
    .btn-secondary:hover { background: """ + Y_100 + """; border-color: """ + INK + """;
                            box-shadow: 0 2px 0 """ + INK + """; }

    /* schema crib sheet under the SQL box */
    .sql-ref { background: """ + Y_50 + """; border: 1px solid """ + LINE + """;
                border-radius: 9px; padding: 11px 13px; margin: 4px 0 14px; }
    .sql-ref-row { display: grid; grid-template-columns: 92px 1fr; gap: 10px;
                    align-items: baseline; padding: 3px 0; }
    .sql-ref-tbl { font-family: 'JetBrains Mono', monospace; font-size: 0.74rem;
                    font-weight: 800; color: """ + INK + """; }
    .sql-ref-cols { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem;
                     color: """ + INK_3 + """; line-height: 1.6; word-break: break-word; }

    .sidebar-toggle { left: 186px; }
    .sidebar.collapsed ~ .sidebar-toggle { left: 16px; }
    .sidebar.collapsed ~ .content { padding-left: 66px; }
    /* Deliberately NOT re-declaring body's background here. The original rule
       sets `background: var(--paper)` and then a pair of radial-gradients; a
       later `background:` shorthand resets background-image, which silently
       removed the warm amber glow. --paper already carries the colour. */

    .hp-head { display:flex; align-items:center; justify-content:space-between;
                gap:16px; margin-bottom:14px; }
    .hp-range { display:flex; gap:4px; background:""" + CARD + """;
                 border:1px solid """ + LINE_STRONG + """; border-radius:9px; padding:3px; }
    .hp-range button { border:none; background:transparent; cursor:pointer;
                        font-family:'JetBrains Mono',monospace; font-size:0.72rem;
                        font-weight:700; color:""" + INK_3 + """; padding:5px 11px; border-radius:6px; }
    .hp-range button.active { background:""" + Y_400 + """; color:""" + INK + """; }

    /* ── panels ───────────────────────────────────────────────────────── */
    .pcard { background:""" + CARD + """; border:1px solid """ + LINE_STRONG + """;
              border-radius:12px; padding:14px 16px; min-width:0; }
    .pcard-h { display:flex; align-items:center; justify-content:space-between;
                gap:10px; margin-bottom:12px; }
    .pcard-t { font-size:0.72rem; font-weight:800; letter-spacing:0.09em;
                text-transform:uppercase; color:""" + INK + """;
                display:flex; align-items:center; gap:7px; }
    .pcard-t:before { content:""; width:8px; height:8px; border-radius:2px;
                       background:""" + Y_400 + """; display:inline-block; }

    /* rows — explicit minmax(0,…) so wide children can never push the page
       sideways (a plain 1fr floors at min-content and overflows) */
    .hp-row { display:grid; gap:14px; margin-bottom:14px; }
    .hp-row-feed  { grid-template-columns: minmax(0,2.45fr) minmax(0,1fr); }
    .hp-row-kpi   { grid-template-columns: repeat(4, minmax(0,1fr)) minmax(0,1.35fr); }
    .hp-row-chart { grid-template-columns: minmax(0,1.55fr) minmax(0,1fr); }
    .hp-row-bot   { grid-template-columns: minmax(0,1.25fr) minmax(0,1.1fr) minmax(0,0.9fr); }
    @media (max-width: 1400px) {
      .hp-row-kpi   { grid-template-columns: repeat(2, minmax(0,1fr)); }
      .hp-row-feed, .hp-row-chart, .hp-row-bot { grid-template-columns: minmax(0,1fr); }
    }

    /* ── KPI cards ────────────────────────────────────────────────────── */
    .kpi { background:""" + CARD + """; border:1px solid """ + LINE_STRONG + """;
            border-radius:12px; padding:13px 15px; min-width:0; }
    .kpi-top { display:flex; align-items:center; gap:9px; margin-bottom:9px; }
    .kpi-ico { width:26px; height:26px; border-radius:7px; display:flex;
                align-items:center; justify-content:center; font-size:0.82rem; flex-shrink:0; }
    .kpi-l { font-size:0.63rem; font-weight:800; letter-spacing:0.08em;
              text-transform:uppercase; color:""" + INK_3 + """; line-height:1.3; }
    .kpi-v { font-size:1.85rem; font-weight:800; letter-spacing:-0.02em; color:""" + INK + """; }
    .kpi-s { font-size:0.68rem; color:""" + INK_3 + """; margin-top:3px;
              font-family:'JetBrains Mono',monospace; }
    /* only the high-impact card carries the critical colour — everything else
       stays neutral so severity actually reads as severity */
    .kpi.kpi-crit { border-color: rgba(217,45,32,0.38); }
    .kpi.kpi-crit .kpi-v { color:""" + CRITICAL + """; }
    .kpi.kpi-crit .kpi-s { color:""" + CRITICAL + """; }

    .kpi-split { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
    .kpi-mini { border:1px solid """ + LINE + """; border-radius:9px; padding:9px 10px; }
    .kpi-mini.save { background:rgba(21,148,71,0.07); border-color:rgba(21,148,71,0.3); }
    .kpi-mini.energy { background:rgba(245,178,27,0.10); border-color:rgba(245,178,27,0.38); }
    .kpi-mini-l { font-size:0.56rem; font-weight:800; letter-spacing:0.07em;
                   text-transform:uppercase; color:""" + INK_3 + """; line-height:1.35; }
    .kpi-mini-v { font-size:1.18rem; font-weight:800; margin-top:3px; }

    /* ── critical alert ───────────────────────────────────────────────── */
    .alert-card { background:#FDF3F2; border:1px solid rgba(217,45,32,0.42);
                   border-radius:12px; padding:14px 16px; min-width:0; }
    .alert-h { display:flex; align-items:center; gap:8px; color:""" + CRITICAL + """;
                font-weight:800; font-size:0.8rem; letter-spacing:0.06em;
                border-bottom:1px solid rgba(217,45,32,0.22); padding-bottom:9px; margin-bottom:11px; }
    .alert-sub { font-size:0.68rem; font-weight:800; letter-spacing:0.09em;
                  color:""" + INK_2 + """; margin-bottom:9px; }
    .alert-grid { display:grid; grid-template-columns:1fr auto; gap:7px 12px; align-items:baseline; }
    .alert-k { font-size:0.66rem; color:""" + INK_3 + """; }
    .alert-v { font-size:1.02rem; font-weight:800; color:""" + INK + """;
                font-family:'JetBrains Mono',monospace; word-break:break-all; }
    .alert-badge { width:26px; height:26px; border-radius:50%; background:""" + CRITICAL + """;
                    color:#fff; font-weight:800; font-size:0.82rem;
                    display:flex; align-items:center; justify-content:center; }

    /* ── terminal ─────────────────────────────────────────────────────── */
    .terminal-feed { background:""" + TERMINAL_BG + """; border:1px solid """ + INK + """;
                      border-radius:12px; overflow:hidden; }
    .term-chrome { background:""" + TERMINAL_BG + """; border-bottom:1px solid rgba(255,255,255,0.09);
                    padding:11px 15px; }

    /* ── small tables inside panels ───────────────────────────────────── */
    .hp-tbl { width:100%; border-collapse:collapse; font-size:0.75rem; }
    .hp-tbl th { text-align:left; font-size:0.6rem; letter-spacing:0.07em;
                  text-transform:uppercase; color:""" + INK_3 + """; font-weight:800;
                  padding:0 8px 7px 0; border-bottom:1px solid """ + LINE + """; }
    .hp-tbl td { padding:7px 8px 7px 0; border-bottom:1px solid """ + LINE + """;
                  font-family:'JetBrains Mono',monospace; color:""" + INK_2 + """; }
    .hp-tbl tr:last-child td { border-bottom:none; }

    .hp-stat { border:1px solid """ + LINE + """; border-radius:9px; padding:9px 11px; }
    .hp-stat-l { font-size:0.57rem; font-weight:800; letter-spacing:0.07em;
                  text-transform:uppercase; color:""" + INK_3 + """; }
    .hp-stat-v { font-size:1.2rem; font-weight:800; color:""" + INK + """; margin-top:2px; }

    /* horizontal bar rows (usernames / passwords) */
    .bar-row { display:grid; grid-template-columns:74px 1fr auto; gap:8px;
                align-items:center; font-size:0.72rem; padding:3px 0; }
    .bar-row .bl { font-family:'JetBrains Mono',monospace; color:""" + INK_2 + """;
                    overflow:hidden; text-overflow:ellipsis; }
    .bar-track { height:9px; background:""" + Y_100 + """; border-radius:3px; overflow:hidden; }
    .bar-fill { height:100%; background:""" + Y_400 + """; border-radius:3px; }
    .bar-row .bn { font-family:'JetBrains Mono',monospace; color:""" + INK_3 + """; font-size:0.68rem; }

    .hp-foot { border-top:1px solid """ + LINE + """; margin-top:4px; padding:13px 2px 4px;
                display:flex; justify-content:space-between; gap:12px;
                font-size:0.68rem; color:""" + INK_3 + """; font-family:'JetBrains Mono',monospace; }
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
    html.Div(className="sidebar-logo", children=[
        html.Img(src=app.get_asset_url("hydrapot_logo.png"),
                 className="brand-mark", alt="HydraPoT"),
        html.Span("HydraPoT"),
    ]),
    html.Div(className="sidebar-caption",
             children="An Intelligent Honeypot Framework Using Large Language Models (LLM) for Interactive Attack Analysis"),
    html.Div(className="sidebar-divider"),
    html.Button("Summary", id="nav-summary", className="nav-pill active", n_clicks=0),
    html.Button("Threat Intel", id="nav-intel", className="nav-pill", n_clicks=0),
    html.Button("MITRE ATT&CK", id="nav-mitre", className="nav-pill", n_clicks=0),
    html.Button("Database", id="nav-db", className="nav-pill", n_clicks=0),
    html.Div(className="sidebar-divider"),
    html.Div(className="toggle-row", children=[
        "Auto-refresh",
        dcc.Checklist(id="auto-refresh-toggle",
                      options=[{"label": "", "value": "on"}],
                      value=["on"], inline=True),
    ]),
    html.Div(className="source-cap", children=f"Source: {storage.DB_PATH.split('/')[-1]}"),
    html.Div(id="sidebar-updated", className="source-cap"),
    # stays .refresh-btn: this one lives on the DARK sidebar, where .btn's
    # light fill would be wrong
    html.Button("🔄 Refresh", id="manual-refresh", className="refresh-btn", n_clicks=0),
    html.Div(id="geo-status"),
    # Live component health. Filled by a callback rather than at import time so
    # a probe result can never be baked into the served page.
    html.Div(id="hp-status-panel"),
    dcc.Store(id="page-store", data="Summary"),
    # Default ALL, not 24H: the window must show the data that exists, and a
    # dashboard that opens empty reads as broken rather than quiet.
    dcc.Store(id="range-store", data="ALL"),
    dcc.Interval(id="interval", interval=REFRESH_MS, n_intervals=0),
])


@app.callback(
    Output("range-store", "data"),
    Input({"type": "range-btn", "r": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _pick_range(_clicks):
    r = (ctx.triggered_id or {}).get("r")
    if not r:
        raise PreventUpdate
    return r


@app.callback(
    Output("hp-status-panel", "children"),
    Output("sidebar-updated", "children"),
    Input("interval", "n_intervals"),
)
def _render_status(_n):
    rows = agent_health()
    online = sum(1 for _, ok, _ in rows if ok)
    panel = html.Div(className="hp-status", children=[
        html.Div("HYDRAPOT STATUS", className="hp-status-h"),
        *[html.Div(className="hp-status-row", title=detail, children=[
            html.Span([html.Span(className="hp-dot",
                                 style={"background": SUCCESS if ok else CRITICAL}), name]),
            html.Span("Online" if ok else "Offline",
                      style={"color": SUCCESS if ok else CRITICAL, "fontWeight": 700}),
        ]) for name, ok, detail in rows],
        html.Div(className="hp-tally", children=[
            # colour follows reality: all-green only when everything really is up
            html.Div(f"{online} / {len(rows)}", className="hp-tally-n",
                     style={"color": SUCCESS if online == len(rows) else Y_400}),
            html.Div("COMPONENTS ONLINE", className="hp-tally-l"),
        ]),
    ])
    return panel, f"Last updated: {datetime.now().strftime('%H:%M:%S')}"
app.layout = html.Div(className="app-shell", children=[
    # NOTE: order matters. The toggle sits AFTER the sidebar so CSS can react to
    # the collapse with a sibling selector (`.sidebar.collapsed ~ .sidebar-toggle`)
    # — `~` only matches later siblings, so with the button first there was no
    # way to reposition it without another callback. It is position:fixed, so
    # DOM order has no visual effect of its own.
    sidebar,
    toggle_btn,
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

        // The sidebar animates its width over 0.2s and .content is flex:1, so
        // every chart's container keeps growing/shrinking for 200ms AFTER this
        // callback returns. Plotly re-lays out on window resize, and toggling
        // a CSS class never fires one — so the charts kept the width they were
        // first drawn at and sat off-centre in their grown container.
        // Fire during the animation so they track it, and once after it
        // settles so the final width is exact.
        [60, 140, 260].forEach(function (t) {
            setTimeout(function () {
                window.dispatchEvent(new Event("resize"));
            }, t);
        });

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
    Output("nav-db", "className"),
    Input("nav-summary", "n_clicks"),
    Input("nav-intel", "n_clicks"),
    Input("nav-mitre", "n_clicks"),
    Input("nav-db", "n_clicks"),
    prevent_initial_call=True,
)
def switch_page(n_summary, n_intel, n_mitre, n_db):
    triggered = ctx.triggered_id
    off = "nav-pill"
    on = "nav-pill active"
    if triggered == "nav-intel":
        return "Threat Intel", off, on, off, off
    if triggered == "nav-mitre":
        return "MITRE ATT&CK", off, off, on, off
    if triggered == "nav-db":
        return "Database", off, off, off, on
    return "Summary", on, off, off, off


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
    Input("range-store", "data"),
    prevent_initial_call=False,
)
def render_router(page, sensor_filter, rng):
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
    if page == "Database":
        # Not cached: the whole point is to show what is in the DB *now*, and
        # it is cheap anyway (one page of rows, not the full dataset).
        if ctx.triggered_id in ("interval", "sensor-filter-store"):
            raise PreventUpdate
        return build_database_page()
    sf = sensor_filter or "all"
    rg = rng or "ALL"
    # keyed by sensor AND range — each combination is a different page, and a
    # key that ignored either would serve the wrong one from cache
    return _cached_page(("summary", sf, rg), lambda: build_summary_page(sf, rg))


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
                                   className="btn btn-primary", n_clicks=0)]
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
    classnames = ["chip active" if bid["cat"] == selected_cat else "chip" for bid in btn_ids]
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


# ── Summary page (SOC layout) ────────────────────────────────────────────────
#
# Composition follows the agreed reference: feed + alert, KPI strip, chart +
# map, then the three analysis panels. The ordering encodes a reading order —
# what is happening, how bad, where from, what HydraPoT did about it.
#
# Every number below comes from load_all()/load_auth_log(). Where the reference
# showed a metric this system cannot source, the panel keeps its place and
# states what is unavailable rather than inventing a value.

RANGES = [("24H", 1), ("7D", 7), ("30D", 30), ("ALL", 0)]


def _apply_range(df, rng):
    """Filter to the selected window. Returns (df, note) where note explains an
    empty result — a silently blank dashboard reads as 'broken', not 'quiet'."""
    if rng in (None, "ALL") or df.empty or "timestamp" not in df.columns:
        return df, None
    days = dict(RANGES).get(rng, 0)
    if not days:
        return df, None
    cutoff = datetime.now() - timedelta(days=days)
    out = df[df["timestamp"] >= cutoff]
    if out.empty:
        newest = df["timestamp"].max()
        return out, (f"No activity in the last {rng}. Most recent event: "
                     f"{newest:%Y-%m-%d %H:%M}" if pd.notna(newest) else f"No activity in the last {rng}.")
    return out, None


def _panel(title, body, right=None, cls=""):
    return html.Div(className=f"pcard {cls}", children=[
        html.Div(className="pcard-h", children=[
            html.Div(title, className="pcard-t"),
            right if right is not None else html.Span(),
        ]),
        body,
    ])


def _kpi(label, value, sub=None, icon="", icon_bg=Y_200, critical=False):
    return html.Div(className="kpi" + (" kpi-crit" if critical else ""), children=[
        html.Div(className="kpi-top", children=[
            html.Div(icon, className="kpi-ico",
                     style={"background": icon_bg, "color": INK}),
            html.Div(label, className="kpi-l"),
        ]),
        html.Div(value, className="kpi-v"),
        html.Div(sub, className="kpi-s") if sub else html.Span(),
    ])


def _bars(series, colour=Y_400, n=5):
    """Horizontal bar rows for a value_counts() series."""
    if series is None or len(series) == 0:
        return html.Div("No data.", className="caption")
    top = series.head(n)
    mx = int(top.iloc[0]) or 1
    return html.Div([
        html.Div(className="bar-row", children=[
            html.Div(str(k), className="bl", title=str(k)),
            html.Div(className="bar-track", children=html.Div(
                className="bar-fill",
                style={"width": f"{int(v)/mx*100:.0f}%", "background": colour})),
            html.Div(f"{int(v):,}", className="bn"),
        ]) for k, v in top.items()
    ])


def _critical_alert(df):
    """Peak-threat detail. Answers *why* it is critical, not just that it is."""
    if df.empty or not (df["fi_score"] >= 3).any():
        return html.Div(className="pcard", children=[
            html.Div("PEAK THREAT", className="pcard-t"),
            html.Div("No FI≥3 activity in this window.", className="caption",
                     style={"marginTop": "10px"}),
        ])

    hi = df[df["fi_score"] >= 3]
    src = hi["src_ip"].value_counts().index[0]
    sub = df[df["src_ip"] == src]
    peak = int(sub["fi_score"].max())
    last = sub["timestamp"].max()

    return html.Div(className="alert-card", children=[
        html.Div(className="alert-h", children=["⚠", html.Span("CRITICAL ALERT")]),
        html.Div("PEAK THREAT DETECTED", className="alert-sub"),
        html.Div(className="alert-grid", children=[
            html.Div([html.Div("Source", className="alert-k"),
                      html.Div(str(src), className="alert-v")]),
            html.Div(style={"textAlign": "right"}, children=[
                html.Div("FI Severity", className="alert-k"),
                html.Div(str(peak), className="alert-badge",
                         style={"marginLeft": "auto", "marginTop": "4px"})]),
            html.Div([html.Div("Commands", className="alert-k"),
                      html.Div(f"{len(sub):,}", className="alert-v")]),
            html.Div(style={"textAlign": "right"}, children=[
                html.Div("Last Seen", className="alert-k"),
                html.Div(last.strftime("%Y-%m-%d %H:%M") if pd.notna(last) else "—",
                         className="alert-v", style={"fontSize": "0.8rem"})]),
        ]),
        html.Div(f"{int((sub['fi_score'] >= 3).sum()):,} high-impact of {len(sub):,} commands",
                 className="caption", style={"marginTop": "11px", "fontSize": "0.68rem"}),
    ])


def _events_chart(df):
    tdf = df[df["timestamp"].notna()].copy()
    if tdf.empty:
        return html.Div("No timestamp data.", className="caption")
    span_h = (tdf["timestamp"].max() - tdf["timestamp"].min()).total_seconds() / 3600.0
    freq = "1h" if span_h <= 72 else ("6h" if span_h <= 24 * 30 else "1D")
    tdf["bucket"] = tdf["timestamp"].dt.floor(freq)

    allc = tdf.groupby("bucket").size()
    high = tdf[tdf["fi_score"] >= 3].groupby("bucket").size().reindex(allc.index, fill_value=0)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=allc.index, y=allc.values, name="All Commands",
                             mode="lines", line=dict(color=ORANGE, width=2),
                             hovertemplate="%{x}<br>%{y} commands<extra></extra>"))
    fig.add_trace(go.Scatter(x=high.index, y=high.values, name="High Impact (FI≥3)",
                             mode="lines", line=dict(color=CRITICAL, width=2),
                             hovertemplate="%{x}<br>%{y} high impact<extra></extra>"))
    theme_layout(fig, height=248, legend=True)
    fig.update_layout(margin=dict(t=6, b=4, l=4, r=8),
                      legend=dict(orientation="h", yanchor="bottom", y=1.0,
                                  x=0, font=dict(size=10), bgcolor="rgba(0,0,0,0)"))
    fig.update_yaxes(gridcolor=LINE)
    return dcc.Graph(figure=fig, config=GRAPH_CONFIG)


def _hydrapot_intel(df, sav):
    """FI band -> which agent actually handled it. Measured, not the config
    table: `_is_cloud()` obfuscation detection overrides the FI band, so the
    real mapping is not one-to-one and showing the config would misrepresent it."""
    if df.empty:
        return html.Div("No data.", className="caption")

    bands = [("0 – 1", (df["fi_score"] <= 1)),
             ("2",     (df["fi_score"] == 2)),
             ("3 – 4", (df["fi_score"] >= 3))]
    label, dot = AGENT_LABEL, AGENT_COLOR

    rows = []
    for name, mask in bands:
        sub = df[mask]
        if sub.empty:
            continue
        counts = sub["agent"].value_counts()
        top = counts.index[0]
        rows.append(html.Tr([
            html.Td(name, style={"fontWeight": 700}),
            html.Td(html.Span([html.Span(className="hp-dot", style={"background": dot.get(top, INK_3)}),
                               label.get(top, top)])),
            html.Td(f"{len(sub):,}"),
            html.Td(f"{len(sub)/len(df)*100:.1f}%", style={"textAlign": "right"}),
        ]))

    table = html.Table(className="hp-tbl", children=[
        html.Thead(html.Tr([html.Th("FI SCORE"), html.Th("HANDLED MOSTLY BY"),
                            html.Th("COMMANDS"), html.Th("%", style={"textAlign": "right"})])),
        html.Tbody(rows),
    ])

    stats = html.Div(style={"display": "grid", "gridTemplateColumns": "repeat(3,1fr)",
                            "gap": "9px", "marginTop": "12px"}, children=[
        html.Div(className="hp-stat", children=[
            html.Div("CLOUD CALLS AVOIDED", className="hp-stat-l"),
            html.Div(f"{sav['cloud_avoided_pct']:.1f}%", className="hp-stat-v",
                     style={"color": SUCCESS})]),
        html.Div(className="hp-stat", children=[
            html.Div("EST. CLOUD COST SAVED", className="hp-stat-l"),
            html.Div(f"${sav['cloud_saved_usd']:.2f}", className="hp-stat-v")]),
        html.Div(className="hp-stat", children=[
            html.Div("AGENT SWITCHES", className="hp-stat-l"),
            html.Div(f"{sav['n_switches']:,}", className="hp-stat-v")]),
    ])
    return html.Div([table, stats])


def _agent_donut(df):
    if df.empty:
        return html.Div("No data.", className="caption")
    label, col = AGENT_LABEL, AGENT_COLOR
    vc = df["agent"].value_counts()

    fig = go.Figure(go.Pie(
        labels=[label.get(a, a) for a in vc.index], values=vc.values, hole=0.62,
        marker=dict(colors=[col.get(a, INK_3) for a in vc.index],
                    line=dict(color=CARD, width=2)),
        textinfo="none",
        hovertemplate="%{label}<br>%{value:,} commands (%{percent})<extra></extra>"))
    theme_layout(fig, height=170)
    fig.update_layout(margin=dict(t=4, b=4, l=4, r=4), showlegend=False)

    legend = html.Div(style={"marginTop": "8px"}, children=[
        html.Div(className="hp-status-row",
                 style={"color": INK_2, "fontSize": "0.72rem", "padding": "3px 0"},
                 children=[
                     html.Span([html.Span(className="hp-dot", style={"background": col.get(a, INK_3)}),
                                label.get(a, a)]),
                     html.Span(f"{n/len(df)*100:.1f}%", style={"fontWeight": 700}),
                 ]) for a, n in vc.items()
    ])
    total = html.Div(style={"display": "flex", "justifyContent": "space-between",
                            "borderTop": f"1px solid {LINE}", "marginTop": "10px",
                            "paddingTop": "9px", "fontSize": "0.7rem"}, children=[
        html.Span("TOTAL SESSIONS", style={"letterSpacing": "0.07em", "color": INK_3, "fontWeight": 800}),
        html.Span(f"{df['session_id'].nunique():,}", style={"fontWeight": 800}),
    ])
    return html.Div([dcc.Graph(figure=fig, config=GRAPH_CONFIG), legend, total])


def _auth_panel(df, auth_entries):
    if not auth_entries:
        return html.Div("No authentication attempts recorded.", className="caption")
    a = pd.DataFrame(auth_entries)
    pw = a[a["auth_type"] == "password"] if "auth_type" in a.columns else a
    probes = int((a["auth_type"] == "tcp_connect").sum()) if "auth_type" in a.columns else 0

    users = pw["username"].value_counts() if "username" in pw.columns else None
    pwds  = pw["password"].value_counts() if "password" in pw.columns else None
    uniq  = pw.groupby(["username", "password"]).ngroups if {"username", "password"} <= set(pw.columns) else 0

    return html.Div(style={"display": "grid", "gridTemplateColumns": "1fr 1fr",
                           "gap": "14px"}, children=[
        html.Div([html.Div("TOP USERNAMES", className="hp-stat-l",
                           style={"marginBottom": "7px"}), _bars(users)]),
        html.Div([html.Div("TOP PASSWORDS", className="hp-stat-l",
                           style={"marginBottom": "7px"}), _bars(pwds, colour=ORANGE)]),
        html.Div(style={"gridColumn": "1 / -1", "display": "grid",
                        "gridTemplateColumns": "repeat(4,1fr)", "gap": "9px"}, children=[
            html.Div(className="hp-stat", children=[
                html.Div("LOGIN ATTEMPTS", className="hp-stat-l"),
                html.Div(f"{len(pw):,}", className="hp-stat-v")]),
            html.Div(className="hp-stat", children=[
                html.Div("UNIQUE CREDENTIALS", className="hp-stat-l"),
                html.Div(f"{uniq:,}", className="hp-stat-v")]),
            html.Div(className="hp-stat", children=[
                html.Div("SOURCE IPS", className="hp-stat-l"),
                html.Div(f"{a['src_ip'].nunique():,}", className="hp-stat-v")]),
            html.Div(className="hp-stat", children=[
                html.Div("SCAN PROBES", className="hp-stat-l"),
                html.Div(f"{probes:,}", className="hp-stat-v")]),
        ]),
    ])


def _origin_map(df):
    ip_col = "public_ip" if "public_ip" in df.columns else "src_ip"
    # counted once up front: `(df[col] == ip).sum()` inside the loop rescans the
    # whole frame per unique IP, which is quadratic as traffic grows
    counts = df[ip_col].value_counts()
    geo_rows = []
    for ip in df[ip_col].dropna().unique():
        geo = geolocate(ip)
        if geo:
            geo_rows.append({"ip": ip, "lat": geo["lat"], "lon": geo["lon"],
                             "country": geo["country"], "city": geo["city"],
                             "count": int(counts.get(ip, 0))})
    if not geo_rows:
        msg = ("geoip.mmdb not found — run `hp geoip`" if _load_geo_reader() is None
               else "No geolocatable source addresses in this window "
                    "(sessions are from local/synthetic sources).")
        return html.Div([dcc.Graph(figure=empty_geo_fig(), config=GRAPH_CONFIG),
                         html.Div(msg, className="caption", style={"marginTop": "6px"})])

    g = pd.DataFrame(geo_rows)
    fig = px.scatter_geo(g, lat="lat", lon="lon", size="count", color="count",
                         hover_name="country",
                         hover_data={"ip": True, "city": True, "count": True,
                                     "lat": False, "lon": False},
                         color_continuous_scale=AMBER_SCALE, size_max=34,
                         projection="natural earth")
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        geo=dict(bgcolor="rgba(0,0,0,0)", landcolor=Y_100, oceancolor=CARD, showocean=True,
                 showland=True, lakecolor=CARD, coastlinecolor=LINE_STRONG,
                 countrycolor=LINE_STRONG, showcoastlines=True, showcountries=True),
        coloraxis_showscale=False, margin=dict(t=0, b=0, l=0, r=0), height=272)
    return html.Div([
        dcc.Graph(figure=fig, config=GRAPH_CONFIG),
        html.Div(className="caption", style={"fontSize": "0.66rem", "marginTop": "4px"},
                 children=[f"{len(g)} geolocatable source(s) · IP geolocation by ",
                           html.A("DB-IP", href="https://db-ip.com", target="_blank",
                                  style={"color": "inherit"}), " — City Lite, CC BY 4.0"]),
    ])


def build_summary_page(sensor_filter="all", rng="ALL"):
    df_all = load_all()
    auth_entries = load_auth_log()
    all_sensors = get_sensor_summary()   # pre-filter, so every sensor stays listed

    df = df_all
    if sensor_filter and sensor_filter != "all" and not df.empty:
        df = df[df["instance"] == sensor_filter]
        auth_entries = [a for a in auth_entries if a.get("instance") == sensor_filter]

    df, range_note = _apply_range(df, rng)

    # ── header ────────────────────────────────────────────────────────────
    header = html.Div(className="hp-head", children=[
        html.H3([html.Img(src=app.get_asset_url("hydrapot_logo.png"),
                          className="brand-mark brand-mark-lg", alt=""),
                 "HydraPoT Dashboard"], className="page-title"),
        html.Div(className="hp-range", children=[
            html.Button(r, id={"type": "range-btn", "r": r}, n_clicks=0,
                        className="active" if r == (rng or "ALL") else "")
            for r, _ in RANGES
        ]),
    ])

    sensor_chips = html.Div(className="hp-range", style={"marginBottom": "14px"}, children=[
        html.Button(("All Sensors" if s == "all" else s),
                    id={"type": "sensor-card-btn", "sensor": s}, n_clicks=0,
                    className="active" if sensor_filter == s else "")
        for s in ["all"] + [x["instance"] for x in all_sensors]
    ]) if all_sensors else html.Span()

    if df_all.empty:
        return [header, html.Div("No data yet. Start the honeypot with `hp run`.",
                                 className="empty-state")]

    if df.empty:
        return [header, sensor_chips,
                html.Div(className="pcard", children=[
                    html.Div(range_note or "No data in this window.", className="caption")])]

    sav = estimate_savings(df)
    n_hi = int((df["fi_score"] >= 3).sum())

    # ── row 1: feed + critical alert ──────────────────────────────────────
    row_feed = html.Div(className="hp-row hp-row-feed", children=[
        html.Div(id="live-feed-wrap", children=build_live_feed(sensor_filter)),
        _critical_alert(df),
    ])

    # ── row 2: KPI strip ──────────────────────────────────────────────────
    row_kpi = html.Div(className="hp-row hp-row-kpi", children=[
        _kpi("High Impact Commands (FI ≥ 3)", f"{n_hi:,}",
             f"{n_hi/len(df)*100:.1f}% of total", "🛡", "rgba(217,45,32,0.13)", critical=True),
        _kpi("Unique Attackers", f"{df['src_ip'].nunique():,}",
             f"across {df['instance'].nunique()} sensor(s)", "👤", Y_200),
        _kpi("Unique Sessions", f"{df['session_id'].nunique():,}",
             f"{len(df)/max(df['session_id'].nunique(),1):.0f} cmds/session avg", "▤", Y_200),
        _kpi("Total Commands", f"{len(df):,}",
             f"{sav['n_switches']:,} agent switches", "⌘", Y_200),
        html.Div(className="kpi", children=[
            html.Div("Efficiency (Cost Savings)", className="kpi-l",
                     style={"marginBottom": "9px"}),
            html.Div(className="kpi-split", children=[
                html.Div(className="kpi-mini save", children=[
                    html.Div("Cloud Cost Saved (est.)", className="kpi-mini-l"),
                    html.Div(f"${sav['cloud_saved_usd']:.2f}", className="kpi-mini-v",
                             style={"color": SUCCESS}),
                    html.Div(f"{sav['cloud_avoided_pct']:.1f}% avoided", className="kpi-s")]),
                html.Div(className="kpi-mini energy", children=[
                    html.Div("Energy Cost Saved (est.)", className="kpi-mini-l"),
                    html.Div(f"{sav['energy_saved_thb']:.2f} ฿", className="kpi-mini-v",
                             style={"color": Y_700}),
                    html.Div(f"{sav['energy_avoided_pct']:.1f}% avoided", className="kpi-s")]),
            ]),
        ]),
    ])

    # ── row 3: events + map ───────────────────────────────────────────────
    row_chart = html.Div(className="hp-row hp-row-chart", children=[
        _panel("Events Over Time", _events_chart(df)),
        _panel("Attacker Origin Map", _origin_map(df)),
    ])

    # ── row 4: analysis ───────────────────────────────────────────────────
    row_bot = html.Div(className="hp-row hp-row-bot", children=[
        _panel("Authentication Intelligence", _auth_panel(df, auth_entries)),
        _panel("HydraPoT Intelligence", _hydrapot_intel(df, sav)),
        _panel("Agent Distribution", _agent_donut(df)),
    ])

    footer = html.Div(className="hp-foot", children=[
        html.Span("HydraPoT · An Intelligent Multi-Agent Honeypot Framework"),
        html.Span(f"{len(all_sensors)} sensor(s) · window: {rng or 'ALL'}"
                  + (f" · {sensor_filter}" if sensor_filter != "all" else "")),
    ])

    return [header, sensor_chips, row_feed, row_kpi, row_chart, row_bot, footer]



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
                              config=GRAPH_CONFIG),
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
            dcc.Graph(figure=_trend(sub), config=GRAPH_CONFIG),
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
            html.Div(dcc.Graph(figure=fig_tech, config=GRAPH_CONFIG,
                               style={"width": "100%"}),
                     className="stage-body"),
        ]),
    ])


# ── Database browser ─────────────────────────────────────────────────────────
#
# Every read here goes through storage.connect_readonly(): mode=ro blocks
# writes at the engine level and an authorizer blocks ATTACH, so nothing
# entered in the SQL box can modify the database or reach another file. That
# matters because `hp dashboard --host 0.0.0.0` is a documented way to run this.

DB_PAGE_SIZE = 50


def _db_grid(columns, rows, empty_msg="No rows."):
    """One results grid, styled like the rest of the dashboard's tables."""
    if not rows:
        return html.Div(empty_msg, className="caption", style={"padding": "14px 2px"})
    # Values are rendered as text: a response blob or a NULL would otherwise
    # break the table's layout or silently render as blank.
    safe = [{c: ("" if r.get(c) is None else str(r.get(c))[:400]) for c in columns}
            for r in rows]
    return dash_table.DataTable(
        data=safe,
        columns=[{"name": c, "id": c} for c in columns],
        page_action="none",
        style_cell_conditional=[{"if": {"column_id": c}, "maxWidth": "420px"}
                                for c in columns],
        **{**TABLE_STYLE,
           "style_table": {"overflowX": "auto", "maxHeight": "60vh",
                           "overflowY": "auto"}},
    )


def build_database_page():
    tables = storage.list_tables()
    if not tables:
        return [html.H3("🗄 Database"),
                html.Div("No database yet — run the honeypot first (`hp run`).",
                         className="caption")]

    default_table = tables[0]["name"]
    chips = [
        html.Button(f"{t['name']}  ({t['rows']:,})",
                    id={"type": "db-table-btn", "table": t["name"]},
                    className="chip" + (" active" if t["name"] == default_table else ""),
                    n_clicks=0)
        for t in tables
    ]

    return [
        html.H3("🗄 Database"),
        html.Div(f"Read-only view of {os.path.basename(storage.DB_PATH)} — "
                 f"browse tables or run a SELECT. Writes are rejected by SQLite.",
                 className="caption"),

        html.Div(chips, className="chip-row"),
        dcc.Store(id="db-table-store", data=default_table),
        dcc.Store(id="db-page-store", data=0),

        html.Div(style={"display": "flex", "gap": "10px", "alignItems": "center",
                        "flexWrap": "wrap", "marginBottom": "10px"}, children=[
            dcc.Input(id="db-search", type="text", debounce=True,
                      placeholder="search all columns…",
                      style={"flex": "1", "minWidth": "220px", "padding": "8px 10px",
                             "fontFamily": "JetBrains Mono, monospace",
                             "border": f"2px solid {INK}", "borderRadius": "8px"}),
            html.Button("‹ prev", id="db-prev", className="chip", n_clicks=0),
            html.Div(id="db-page-label", className="caption",
                     style={"minWidth": "150px", "textAlign": "center"}),
            html.Button("next ›", id="db-next", className="chip", n_clicks=0),
        ]),

        html.Div(id="db-grid"),

        html.Div(className="sidebar-divider", style={"margin": "22px 0 14px"}),
        html.Div("SQL (read-only)", className="section-header"),
        dcc.Textarea(id="db-sql", value="SELECT agent, COUNT(*) AS n\nFROM sessions\nGROUP BY agent\nORDER BY n DESC",
                     style={"width": "100%", "height": "92px", "padding": "10px",
                            "fontFamily": "JetBrains Mono, monospace", "fontSize": "12.5px",
                            "border": f"2px solid {INK}", "borderRadius": "8px"}),
        html.Div(style={"display": "flex", "gap": "10px", "alignItems": "center",
                        "margin": "10px 0"}, children=[
            html.Button("▶ Run", id="db-run", className="chip active", n_clicks=0),
            html.Div(id="db-sql-status", className="caption"),
        ]),

        # Schema reference for writing queries. Every table, not just the one
        # being browsed above — the SQL box can hit any of them, and having to
        # scroll up and click a chip to remember a column name is the whole
        # reason this is repeated down here.
        html.Div(className="sql-ref", children=[
            html.Div("COLUMNS", className="hp-stat-l", style={"marginBottom": "7px"}),
            *[html.Div(className="sql-ref-row", children=[
                html.Span(t["name"], className="sql-ref-tbl"),
                html.Span(" · ".join(
                    f"{c['name']}" + (" *" if c["pk"] else "")
                    for c in storage.table_schema(t["name"])), className="sql-ref-cols"),
            ]) for t in tables],
            html.Div("* primary key · WHERE filters rows, GROUP BY summarises them",
                     className="caption",
                     style={"marginTop": "8px", "fontSize": "0.65rem"}),
        ]),

        html.Div(id="db-sql-result"),
    ]


@app.callback(
    Output("db-table-store", "data"),
    Output("db-page-store", "data"),
    Output({"type": "db-table-btn", "table": ALL}, "className"),
    Input({"type": "db-table-btn", "table": ALL}, "n_clicks"),
    State({"type": "db-table-btn", "table": ALL}, "id"),
    prevent_initial_call=True,
)
def _db_pick_table(_clicks, ids):
    picked = (ctx.triggered_id or {}).get("table")
    if not picked:
        raise PreventUpdate
    # switching table resets to page 0 — otherwise you land on page 40 of a
    # table that only has 3 rows and see an empty grid
    return picked, 0, ["chip active" if i["table"] == picked else "chip"
                       for i in ids]


@app.callback(
    Output("db-page-store", "data", allow_duplicate=True),
    Input("db-prev", "n_clicks"),
    Input("db-next", "n_clicks"),
    Input("db-search", "value"),
    State("db-page-store", "data"),
    State("db-table-store", "data"),
    prevent_initial_call=True,
)
def _db_paginate(_p, _n, _search, page, table):
    trig = ctx.triggered_id
    if trig == "db-search":
        return 0                      # a new search starts at the first page
    page = int(page or 0)
    if trig == "db-prev":
        return max(0, page - 1)
    total = storage.browse_table(table, limit=1)["total"]
    last = max(0, (total - 1) // DB_PAGE_SIZE)
    return min(last, page + 1)


@app.callback(
    Output("db-grid", "children"),
    Output("db-page-label", "children"),
    Input("db-table-store", "data"),
    Input("db-page-store", "data"),
    Input("db-search", "value"),
)
def _db_render(table, page, search):
    if not table:
        raise PreventUpdate
    page = int(page or 0)
    res = storage.browse_table(table, limit=DB_PAGE_SIZE,
                              offset=page * DB_PAGE_SIZE, search=search or None)
    if res["error"]:
        return html.Div(f"⚠ {res['error']}", className="caption"), ""

    total = res["total"]
    pages = max(1, (total + DB_PAGE_SIZE - 1) // DB_PAGE_SIZE)
    label = f"page {page + 1:,} / {pages:,}  ({total:,} rows)"

    # schema lives under the SQL box now (see .sql-ref) — one copy, next to
    # where you actually need the column names
    return (_db_grid(res["columns"], res["rows"],
                     "No rows match that search." if search else "Table is empty."),
            label)


@app.callback(
    Output("db-sql-result", "children"),
    Output("db-sql-status", "children"),
    Input("db-run", "n_clicks"),
    State("db-sql", "value"),
    prevent_initial_call=True,
)
def _db_run_sql(_n, sql):
    res = storage.run_readonly_query(sql)
    if res["error"]:
        return html.Div(f"⚠ {res['error']}", className="caption",
                        style={"color": "#C1443A"}), ""
    n = len(res["rows"])
    status = f"{n:,} row{'' if n == 1 else 's'}"
    if res["truncated"]:
        status += f" (capped at {storage.MAX_BROWSE_ROWS:,})"
    return _db_grid(res["columns"], res["rows"], "Query returned no rows."), status


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
    _cat_n = {"all": sum(by_type.values()), **dict(by_type)}
    cat_buttons = [
        html.Button(
            # label + count: "ipv4 128" tells you what filtering will do before
            # you click, which the bare category name did not
            [("All" if cat == "all" else str(cat)),
             html.Span(f"{_cat_n.get(cat, 0):,}", className="chip-n")],
            id={"type": "ioc-cat-btn", "cat": cat},
            className="chip active" if cat == "all" else "chip",
            n_clicks=0,
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
        dcc.Graph(figure=fig_type, config=GRAPH_CONFIG),
        html.Div("Top Indicators (by severity, then frequency)", className="section-header"),
        dcc.Store(id="ioc-cat-filter-store", data="all"),
        html.Div(cat_buttons, className="chip-row"),
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
                                className="btn btn-primary", n_clicks=0),
                ]),
            ),
            html.Button("⬇ Export STIX", id="export-stix-btn",
                        className="btn btn-secondary", n_clicks=0),
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
                      dcc.Graph(figure=fig_bar, config=GRAPH_CONFIG)])
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
