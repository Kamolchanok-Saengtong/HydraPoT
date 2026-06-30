"""
app.py — HydraPoT SIEM Dashboard (Plotly Dash)
Layout: live terminal | metric cards | world map | events over time | summary table

pip install dash plotly pandas geoip2
"""

import json
import os
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from dash import Dash, html, dcc, Input, Output, State, ctx, dash_table
from dash.exceptions import PreventUpdate

# ── Config ────────────────────────────────────────────────────────────────────

SESSION_DIR  = "data/logs/sessions"
AUTH_LOG     = "data/logs/auth_log.json"
REFRESH_MS   = 5000
LOGO_PATH    = "/mnt/data-partition/honeypot/production/logo.png"
MMDB_PATH    = "/mnt/data-partition/honeypot/geoip.mmdb"
MAX_SESSION_FILES = 50

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
TTL = 1.0  # seconds

def load_all() -> pd.DataFrame:
    now = time.time()
    if _cache["all_df"] is not None and (now - _cache["all_ts"]) < TTL:
        return _cache["all_df"]

    if not os.path.exists(SESSION_DIR):
        df = pd.DataFrame()
    else:
        rows = []
        files = sorted(
            (f for f in os.listdir(SESSION_DIR) if f.endswith(".json")),
            reverse=True
        )[:MAX_SESSION_FILES]
        for fname in files:
            try:
                with open(os.path.join(SESSION_DIR, fname)) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    rows.extend(data)
                elif isinstance(data, dict):
                    rows.append(data)
            except Exception:
                pass
        if not rows:
            df = pd.DataFrame()
        else:
            df = pd.DataFrame(rows)
            df["fi_score"]   = df.get("fi_score",   0).fillna(0).astype(int)
            df["latency_ms"] = df.get("latency_ms", 0).fillna(0).astype(float)
            df["agent"]      = df.get("agent",      "unknown").fillna("unknown")
            df["session_id"] = df.get("session_id", "default").fillna("default")
            df["src_ip"]     = df.get("src_ip",     "?").fillna("?")
            df["timestamp"]  = pd.to_datetime(df.get("timestamp", ""), errors="coerce")

    _cache["all_df"] = df
    _cache["all_ts"] = now
    return df

def load_auth_log() -> list:
    now = time.time()
    if _cache["auth"] is not None and (now - _cache["auth_ts"]) < TTL:
        return _cache["auth"]

    if not os.path.exists(AUTH_LOG):
        data = []
    else:
        try:
            with open(AUTH_LOG) as f:
                raw = json.load(f)
            data = raw if isinstance(raw, list) else []
        except Exception:
            data = []

    _cache["auth"] = data
    _cache["auth_ts"] = now
    return data

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
    }

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
    .threat-badge { border-radius:14px; padding:12px; text-align:center; border:2px solid var(--ink); flex:1; min-width:140px; }

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
    html.Button("Session Explorer", id="nav-session", className="nav-pill", n_clicks=0),
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
    Input("content-area", "children"),
)


# ── Page nav callback ───────────────────────────────────────────────────────────

@app.callback(
    Output("page-store", "data"),
    Output("nav-summary", "className"),
    Output("nav-session", "className"),
    Input("nav-summary", "n_clicks"),
    Input("nav-session", "n_clicks"),
    prevent_initial_call=True,
)
def switch_page(n_summary, n_session):
    triggered = ctx.triggered_id
    if triggered == "nav-session":
        return "Session Explorer", "nav-pill", "nav-pill active"
    return "Summary", "nav-pill active", "nav-pill"


# ── GeoIP status badge ──────────────────────────────────────────────────────────

@app.callback(Output("geo-status", "children"), Input("interval", "n_intervals"))
def update_geo_status(_n):
    if os.path.exists(MMDB_PATH):
        return html.Div("🌍 GeoIP ready", className="status-pill status-ok")
    return html.Div("⚠️ geoip.mmdb not found", className="status-pill status-warn")


# ── Manual refresh just clears cache so next interval tick reloads fresh ───────

@app.callback(Output("interval", "n_intervals"), Input("manual-refresh", "n_clicks"), prevent_initial_call=True)
def manual_refresh(_n):
    _cache["all_ts"] = 0
    _cache["auth_ts"] = 0
    return 0


# ── Single router callback ───────────────────────────────────────────────────

@app.callback(
    Output("content-area", "children"),
    Input("interval", "n_intervals"),
    Input("page-store", "data"),
    prevent_initial_call=False,
)
def render_router(_n, page):
    triggered = ctx.triggered_id
    if page == "Session Explorer":
        if triggered == "interval":
            raise PreventUpdate
        return build_session_explorer_page()
    return build_summary_page()


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

def build_summary_page():
    df = load_all()
    auth_entries = load_auth_log()

    if df.empty:
        return [
            html.H3("HydraPoT Dashboard"),
            html.Div("No data yet. Start the honeypot with `hp run`.", className="empty-state"),
        ]

    
    # Live terminal feed
    recent = df[df["timestamp"].notna()].sort_values("timestamp", ascending=False).head(30)

    def build_terminal_line(ts, ip, fi=None, agent=None, cmd=None, kind="cmd"):
        spans = [html.Span(f"[{ts}]", className="term-time")]
        if kind == "scan":
            spans += [html.Span(" SCAN ", className="term-fi3"), html.Span(ip, className="term-ip"),
                      html.Span(" TCP connection (port probe)", className="term-cmd")]
        elif kind == "login":
            spans += [html.Span(" LOGIN ", className="term-login"), html.Span(f" {ip} ", className="term-ip"),
                      html.Span(cmd, className="term-cmd")]
        else:
            spans += [html.Span(f" {ip} ", className="term-ip"), html.Span(f"FI:{fi} ", className=f"term-fi{fi}"),
                      html.Span(f"[{agent}] ", className=f"term-agent-{agent}"), html.Span(f"$ {cmd}", className="term-cmd")]
        return html.Div(spans, className="term-line")

    terminal_line_components = []

    for entry in auth_entries[-5:]:
        ts = entry.get("timestamp", "")
        ip = entry.get("src_ip", "?")
        auth_type = entry.get("auth_type", "")
        if auth_type == "tcp_connect":
            terminal_line_components.append(build_terminal_line(ts, ip, kind="scan"))
        else:
            user, pw = entry.get("username", "?"), entry.get("password", "?")
            terminal_line_components.append(build_terminal_line(ts, ip, cmd=f"{user}:{pw}", kind="login"))

    if terminal_line_components and not recent.empty:
        terminal_line_components.append(
            html.Div(html.Span("────────────────────────────────────────────", className="term-separator"), className="term-line")
        )

    for _, row in recent.iterrows():
        ts = row["timestamp"].strftime("%H:%M:%S") if pd.notna(row["timestamp"]) else "??:??:??"
        ip = row.get("src_ip", "?")
        cmd = str(row.get("cmd", ""))[:80]
        fi = int(row.get("fi_score", 0))
        agent = row.get("agent", "unknown")
        terminal_line_components.append(build_terminal_line(ts, ip, fi=fi, agent=agent, cmd=cmd, kind="cmd"))

    feed = html.Div(className="terminal-feed", children=[
        html.Div(className="term-chrome", children=[
            html.Span(className="term-dot dot-r"), html.Span(className="term-dot dot-y"), html.Span(className="term-dot dot-g"),
            html.Span("hydrapot — live feed", className="term-chrome-title"),
        ]),
        html.Div("▶ Live Session Feed", className="term-header"),
        html.Div(className="term-body", id="live-feed-body", children=terminal_line_components),
    ]) if terminal_line_components else None

    # Metric cards
    peak_fi = int(df["fi_score"].max())
    tl, tc, ti = THREAT_LEVEL[peak_fi]
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
    ])

    # Auth intelligence
    auth_block = build_auth_intelligence(df, auth_entries)

    children = [html.H3("🍯 HydraPoT Dashboard")]
    if feed:
        children.append(feed)
    children.append(metrics)
    children.append(html.Hr(className="divider"))
    children.append(html.Div(className="grid-2", children=[left_col, right_col]))
    children.append(html.Hr(className="divider"))
    children.append(html.Div("Auth Intelligence", className="section-header"))
    children.append(auth_block)
    return children


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
    sdf = df[df["session_id"] == selected].copy()
    if sdf.empty:
        return html.Div()

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
