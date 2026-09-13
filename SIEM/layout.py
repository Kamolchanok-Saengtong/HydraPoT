"""
SIEM/layout.py — overall page shell: sidebar, top-level nav, and the single
page router. Imports every page module's build_*_page() to route to it, so
this is deliberately the LAST SIEM module imported (see SIEM/__init__.py) --
everything it depends on must already exist.
"""
from datetime import datetime

from dash import html, dcc, Input, Output, State, ctx, ALL
from dash.exceptions import PreventUpdate

import storage

from SIEM.server import app
from SIEM.theme import SUCCESS, CRITICAL, Y_400
from SIEM.data import (_cache, _feed_cache, _page_cache, _overview_cache,
                       agent_health, _cached_page)
from SIEM.geo import MMDB_PATH
from SIEM.ioc import build_ioc_snapshot
from SIEM.pages.summary import build_summary_page
from SIEM.pages.live_feed import build_live_page
from SIEM.pages.mitre import build_mitre_page
from SIEM.pages.investigate import build_investigate_page
from SIEM.pages.database import build_database_page
from SIEM.pages.threat_intel import build_threat_intel_page

REFRESH_MS   = 1000    # safe again: the tick now refreshes ONLY the live feed
# For state that changes at human speed (alert acknowledgements), not machine
# speed. Anything that does not need sub-second freshness belongs here.
SLOW_REFRESH_MS = 5000
                       # (build_live_feed), not the whole page's figures

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
    html.Button("Investigation", id="nav-investigate", className="nav-pill", n_clicks=0),
    html.Button("Live", id="nav-live", className="nav-pill", n_clicks=0),
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
    # Always-present (top-level, not inside per-page content-area) throwaway
    # target for the WebSocket setup clientside_callback below -- a per-page
    # element like live-feed-wrap only exists while Summary is on screen, and
    # a clientside callback errors if its Output isn't in the DOM.
    html.Div(id="ws-setup-sink", style={"display": "none"}),
    dcc.Store(id="page-store", data="Summary"),
    # Default ALL, not 24H: the window must show the data that exists, and a
    # dashboard that opens empty reads as broken rather than quiet.
    dcc.Store(id="range-store", data="ALL"),
    dcc.Interval(id="interval", interval=REFRESH_MS, n_intervals=0),
    # A SECOND, slower tick. The main one runs at 1s so the live feed feels
    # live; anything hung off it round-trips 3,600 times an hour even when the
    # callback returns no_update, because no_update is decided on the SERVER.
    # Alert state moves when a person clicks a button, so it gets its own
    # interval rather than making the feed's cadence everyone's problem.
    dcc.Interval(id="slow-interval", interval=SLOW_REFRESH_MS, n_intervals=0),
])


@app.callback(
    Output("range-store", "data"),
    Input({"type": "range-btn", "r": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _pick_range(_clicks):
    # A pattern-matching Input also fires when its components are CREATED,
    # with n_clicks=0 — so a plain re-render silently re-triggered this and
    # changed state nobody clicked. Only a real click carries a truthy count.
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
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
    # Which alert the investigation page should open on, set by the Summary
    # page's open-alerts card. App-level so it survives the navigation that
    # consumes it.
    dcc.Store(id="iv-focus", data=None),
    # Written by the clientside WebSocket handler (SIEM/clientside.py's
    # real-time push callback) every time a new command lands -- purely a
    # trigger value (a counter), not the row itself. pages/live_feed.py's
    # _refresh_live_feed still does the actual fetch+render through
    # build_live_feed(), so this only changes WHEN that runs (push, not just
    # a fixed poll), so there is exactly one place that formats a feed row.
    dcc.Store(id="ws-feed-store", data=0),
])


# ── Page nav callback ───────────────────────────────────────────────────────────

@app.callback(
    Output("page-store", "data"),
    Output("nav-summary", "className"),
    Output("nav-investigate", "className"),
    Output("nav-live", "className"),
    Output("nav-intel", "className"),
    Output("nav-mitre", "className"),
    Output("nav-db", "className"),
    Input("nav-summary", "n_clicks"),
    Input("nav-investigate", "n_clicks"),
    Input("nav-live", "n_clicks"),
    Input("nav-intel", "n_clicks"),
    Input("nav-mitre", "n_clicks"),
    Input("nav-db", "n_clicks"),
    # Summary's Investigate block points at the pages that own the detail.
    # Routed through this same callback rather than a second navigation
    # mechanism, so there is one place that decides what page is showing.
    # In-page navigation (Summary's and Aggregation's Investigate blocks).
    # Pattern-matching, NOT string ids: these buttons only exist while their
    # own page is mounted, and a plain string Input pointing at an id that is
    # not in the current layout breaks the WHOLE callback ("a nonexistent
    # object was used in an Input") -- which silently killed every nav button.
    # A pattern Input matches an empty set harmlessly.
    # `src` is part of the id, not decoration: two buttons may legitimately
    # point at the same page (the open-alerts card and the Investigate block
    # both open Investigation), and Dash requires ids to be UNIQUE. Identical
    # ids do not error loudly -- the click simply stops routing, which is
    # exactly how the alert card's button silently did nothing. A pattern must
    # name every key an id carries, so ALL appears for both.
    Input({"type": "page-nav", "target": ALL, "src": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def switch_page(n_summary, n_investigate, n_live, n_intel, n_mitre, n_db, n_page_nav):
    # A pattern-matching Input also fires when its components are CREATED, with
    # n_clicks=0 -- so re-rendering the Attention Queue spawned fresh
    # "Investigate →" buttons and navigated the user to Session Explorer
    # without anyone clicking anything. Only a real click carries a truthy
    # count.
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    triggered = ctx.triggered_id
    off = "nav-pill"
    on = "nav-pill active"
    if isinstance(triggered, dict) and triggered.get("type") == "page-nav":
        target = (triggered.get("target") or "").strip()
        flags = {"Investigation": (off, on, off, off, off, off),
                 "Live": (off, off, on, off, off, off),
                 "Threat Intel": (off, off, off, on, off, off),
                 "MITRE ATT&CK": (off, off, off, off, on, off)}
        if target in flags:
            return (target,) + flags[target]
        return "Summary", on, off, off, off, off, off
    if triggered == "nav-investigate":
        return "Investigation", off, on, off, off, off, off
    if triggered == "nav-live":
        return "Live", off, off, on, off, off, off
    if triggered == "nav-intel":
        return "Threat Intel", off, off, off, on, off, off
    if triggered == "nav-mitre":
        return "MITRE ATT&CK", off, off, off, off, on, off
    if triggered == "nav-db":
        return "Database", off, off, off, off, off, on
    return "Summary", on, off, off, off, off, off


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
    _overview_cache.clear()
    return 0


# ── Single router callback ───────────────────────────────────────────────────

@app.callback(
    Output("iv-focus", "data"),
    Input({"type": "page-nav", "target": ALL, "src": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _focus_alert(_clicks):
    """Remember which alert the Summary card sent us to.

    The key rides in the button's own id ("alert:<key>") rather than in a
    companion Store. One row = one button = one id, so there is no way for the
    row an analyst clicked and the alert that opens to drift apart -- and no
    second component to keep in sync as the list re-renders.

    Separate callback from switch_page: navigation and focus are different
    concerns and switch_page already has seven outputs. Every non-alert
    page-nav button clears the focus, so a later plain navigation cannot
    silently reopen a stale alert.
    """
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    trig = ctx.triggered_id or {}
    src = trig.get("src") if isinstance(trig, dict) else None
    if not src or not str(src).startswith("alert:"):
        return None
    return str(src)[len("alert:"):] or None


@app.callback(
    Output("content-area", "children"),
    Input("page-store", "data"),
    Input("sensor-filter-store", "data"),
    Input("range-store", "data"),
    State("iv-focus", "data"),
    prevent_initial_call=False,
)
def render_router(page, sensor_filter, rng, iv_focus):
    if page == "Threat Intel":
        # Threat Intel never auto-refreshes on the interval tick — it's a
        # generated snapshot (SIEM-style), not a live feed. Only navigating
        # to the page (re)renders the shell, using whatever snapshot is
        # already in ioc-store; a NEW snapshot only comes from clicking
        # "Generate Intelligence" (see generate_intelligence() in
        # pages/threat_intel.py), which updates ioc-content directly and
        # never touches this callback.
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
    if page == "Investigation":
        # Cached like the other analysis pages: it is a reasoned view of a
        # window, not a live feed, and rebuilding it on the 5s tick would
        # discard whichever detection the analyst had open.
        if ctx.triggered_id == "interval":
            raise PreventUpdate
        # The focus is part of the cache key. Without it a cached page built
        # for one alert would be served for a request to open another.
        return _cached_page(
            ("investigate", sensor_filter or "all", rng or "ALL", iv_focus),
            lambda: build_investigate_page(sensor_filter or "all", rng or "ALL",
                                           selected=iv_focus))
    if page == "Live":
        # Wallboard. Never cached and never blocked from the interval: unlike
        # every other page here, being rebuilt constantly IS the point -- and
        # its own callback (pages/live_feed.py) is what actually refreshes the
        # feed body, so this only has to hand back the shell.
        return build_live_page(sensor_filter or "all")
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


@app.callback(
    Output("sensor-filter-store", "data"),
    Input({"type": "sensor-card-btn", "sensor": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def set_sensor_filter(_clicks):
    # A pattern-matching Input also fires when its components are CREATED,
    # with n_clicks=0 — so a plain re-render silently re-triggered this and
    # changed state nobody clicked. Only a real click carries a truthy count.
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    triggered = ctx.triggered_id
    if not triggered:
        raise PreventUpdate
    return triggered["sensor"]


# ── Auto-refresh toggle: disable/enable interval ────────────────────────────────

@app.callback(Output("interval", "disabled"), Input("auto-refresh-toggle", "value"))
def toggle_autorefresh(value):
    return "on" not in (value or [])
