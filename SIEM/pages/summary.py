"""
SIEM/pages/summary.py — Summary page (SOC layout).

Composition: attacker map + critical alert, KPI strip, events chart, then the
three analysis panels. The map leads because "who is hitting us, from where"
is the question a SOC overview exists to answer at a glance. The live terminal
that used to hold that slot now has its own full-screen Live page — a
scrolling feed is something you watch, not something you glance at.

Every number below comes from load_all()/load_auth_log(). Where the reference
showed a metric this system cannot source, the panel keeps its place and
states what is unavailable rather than inventing a value.
"""
import math
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import html, dcc, Input, Output, State, ctx, ALL, no_update
from dash.exceptions import PreventUpdate

from SIEM.server import app
from SIEM.theme import (
    theme_layout, GRAPH_CONFIG, GEO_CONFIG, empty_geo_fig,
    INK, INK_2, INK_3, Y_100, Y_200, Y_300, Y_400, Y_700, CARD, LINE, LINE_STRONG,
    ORANGE, CRITICAL, SUCCESS, AMBER_SCALE, AGENT_LABEL, AGENT_COLOR,
    # Generic layout primitives, so they live in theme.py rather than being
    # private to this page; aliased to their original private names to keep
    # this page's call sites unchanged.
    panel as _panel, kpi as _kpi, bars as _bars,
)
from SIEM.data import (load_all, load_auth_log, get_sensor_summary,
                       is_experiment_row, load_overview, load_alerts,
                       load_alert_counts)
from SIEM.cost import estimate_savings
from SIEM.geo import geolocate, _load_geo_reader
# Same tactic->colour mapping the MITRE page uses, so a tactic never changes
# colour depending on which page you are looking at.
from SIEM.pages.mitre import _tactic_color

# Window presets. ALL is the default on purpose: this capture spans 2019 to
# today, so every real duration preset lands on a nearly-empty window and a
# blank dashboard reads as broken rather than quiet.
RANGES = [("15m", 0), ("1h", 0), ("24h", 0), ("7d", 0), ("ALL", 0)]


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


# Rows before the list scrolls. Sized to fill the column beside the 560px map
# rather than to a round number: the list scrolls, so a higher cap only ever
# means less dead space at the bottom, never a taller card.
ALERT_ROWS = 12


def _alert_state(instance=None):
    """(counts, open alerts worst-first). One place decides "worst"."""
    from SIEM.investigation import SEVERITY_RANK, UNRATED_RANK
    counts = load_alert_counts(instance)
    open_alerts = [a for a in load_alerts(instance)
                   if a.get("state") in ("new", "acknowledged")]
    # Unrated sorts below every rated level: it means the behaviour ruleset had
    # nothing to read, which is neither a claim of safety nor evidence of danger.
    open_alerts.sort(key=lambda a: (-SEVERITY_RANK.get(a.get("severity"),
                                                       UNRATED_RANK),
                                    a.get("last_seen") or ""), reverse=False)
    return counts, open_alerts


def _alert_signature(instance=None):
    """What the card actually depends on.

    The refresh callback compares this instead of re-rendering blindly: the
    card sat on a 5s tick replacing its own DOM every time, which flickered and
    cost a component tree over the wire for a card that changes maybe twice an
    hour.
    """
    counts, open_alerts = _alert_state(instance)
    return (tuple(sorted(counts.items())),
            tuple((a["alert_key"], a["state"], a.get("last_seen"),
                   a.get("member_count")) for a in open_alerts[:ALERT_ROWS]))


def _open_alerts_card(instance=None):
    """Open alerts, from the alert layer — and a way into the investigation.

    REPLACES an FI-driven card that labelled any FI>=3 command a "CRITICAL
    ALERT" and badged it "FI Severity". That was wrong in two ways that now
    matter: FI is HydraPoT's routing metric (it decides which agent answers a
    command) and says nothing about attacker intent, and "alert" now means a
    specific durable record with a lifecycle. A loud FI 4 `rm` of a file the
    attacker created themselves outranked a quiet real compromise, and nothing
    on the card could be acted on.

    Shows the QUEUE, not just its top row. One alert left most of a 560px
    column empty next to the map, and "10 NEW" with only one of them visible
    made the analyst click through to find out what the other nine were. Every
    row opens that specific alert.

    Everything here is read: severity from threat_intel/severity.py, the alerts
    from alert_rules.yml. This card summarises and points; it decides nothing.
    """
    counts, open_alerts = _alert_state(instance)
    n_new = counts.get("new", 0)
    n_ack = counts.get("acknowledged", 0)
    n_closed = counts.get("closed", 0)

    def open_button(label, alert_key=None, cls="btn-cta"):
        # The alert key rides in the id, so a row opens the alert it names
        # rather than whatever sorts first on the investigation page. `src`
        # also keeps these ids UNIQUE -- two buttons targeting the same page
        # with identical ids silently stop routing in Dash.
        return html.Button(label, className=cls, n_clicks=0,
                           id={"type": "page-nav", "target": "Investigation",
                               "src": f"alert:{alert_key}" if alert_key else "alert-card"})

    if not open_alerts:
        return html.Div(className="alert-card alert-card-quiet", children=[
            html.Div(className="alert-h", children=["⚑", html.Span("OPEN ALERTS")]),
            html.Div("No open alerts. Nothing in this window met a rule in "
                     "alert_rules.yml — which is a result, not an error.",
                     className="caption", style={"marginTop": "10px", "flex": "1"}),
            html.Div(f"{n_closed:,} closed", className="caption",
                     style={"fontSize": "0.66rem"}) if n_closed else html.Span(),
            open_button("Open investigation →"),
        ])

    rows = []
    for a in open_alerts[:ALERT_ROWS]:
        sev = a.get("severity") or "unrated"
        facts = " · ".join(filter(None, [
            f"{a['member_count']:,} sessions" if a.get("member_count") else None,
            f"{a['distinct_sources']:,} src" if a.get("distinct_sources") else None,
            (a.get("last_seen") or "")[:16] or None,
        ]))
        rows.append(html.Button(
            className="alert-row" + (" acked" if a["state"] == "acknowledged" else ""),
            n_clicks=0,
            id={"type": "page-nav", "target": "Investigation",
                "src": f"alert:{a['alert_key']}"},
            children=[
                html.Div(className="alert-row-top", children=[
                    html.Span(sev.upper(), className=f"iv-sev iv-sev-{sev}"),
                    html.Span(a.get("title") or "—", className="alert-row-t"),
                    html.Span("ACK", className="iv-alert iv-alert-acknowledged")
                    if a["state"] == "acknowledged" else html.Span(),
                ]),
                html.Div(facts, className="alert-row-f"),
            ]))

    hidden = len(open_alerts) - len(rows)
    return html.Div(className="alert-card", children=[
        html.Div(className="alert-h", children=["⚑", html.Span("OPEN ALERTS")]),
        html.Div(f"{n_new} NEW · {n_ack} ACKNOWLEDGED", className="alert-sub"),
        html.Div(rows, className="alert-list"),
        html.Div(f"+{hidden} more open" if hidden > 0 else "",
                 className="caption", style={"fontSize": "0.66rem"}),
        open_button("Open investigation →"),
    ])


# Above this many buckets the data is a real time series and a continuous
# line reads best. At or below it, capture is clumpy (this honeypot's history
# is a handful of busy days years apart) and a continuous axis squeezes every
# point into a couple of pixels at the edges -- so the buckets are drawn as
# evenly spaced categories instead.
_DENSE_BUCKETS = 60
# Linear y hides a 4-command day sitting next to a 1791-command day: it
# renders as under a pixel. Past this max/min ratio the axis switches to log
# and says so in the title, rather than silently flattening small values to
# zero.
_LOG_Y_RATIO = 100
# GRAPH_CONFIG sets responsive:True, so Plotly sizes the plot to its CONTAINER
# and ignores the figure's own `height`. In a multi-column row that is
# harmless -- grid's default align-items:stretch makes every card as tall as
# the tallest sibling. Alone in a full-width row there is no sibling to
# stretch against, the card collapses to its content, and the chart rendered
# 26px tall. So the container gets the height explicitly, not just the figure.
_EVENTS_H = 248


def _events_chart(df):
    tdf = df[df["timestamp"].notna()].copy()
    if tdf.empty:
        return html.Div("No timestamp data.", className="caption")
    span_h = (tdf["timestamp"].max() - tdf["timestamp"].min()).total_seconds() / 3600.0
    freq = "1h" if span_h <= 72 else ("6h" if span_h <= 24 * 30 else "1D")
    tdf["bucket"] = tdf["timestamp"].dt.floor(freq)

    allc = tdf.groupby("bucket").size()
    high = tdf[tdf["fi_score"] >= 3].groupby("bucket").size().reindex(allc.index, fill_value=0)

    sparse = len(allc) <= _DENSE_BUCKETS
    fmt = "%Y-%m-%d" if freq == "1D" else "%Y-%m-%d %H:%M"
    x = [t.strftime(fmt) for t in allc.index] if sparse else list(allc.index)

    nz = [v for v in allc.values if v > 0]
    log_y = bool(nz) and (max(nz) / min(nz)) > _LOG_Y_RATIO

    fig = go.Figure()
    if sparse:
        # Bars on a category axis: four days spread over seven years become
        # four readable columns instead of two hairlines at the chart edges.
        fig.add_trace(go.Bar(x=x, y=allc.values, name="All Commands",
                             marker_color=ORANGE,
                             hovertemplate="%{x}<br>%{y} commands<extra></extra>"))
        fig.add_trace(go.Bar(x=x, y=high.values, name="High Impact (FI≥3)",
                             marker_color=CRITICAL,
                             hovertemplate="%{x}<br>%{y} high impact<extra></extra>"))
        fig.update_layout(barmode="group", bargap=0.35)
    else:
        fig.add_trace(go.Scatter(x=x, y=allc.values, name="All Commands",
                                 mode="lines", line=dict(color=ORANGE, width=2),
                                 hovertemplate="%{x}<br>%{y} commands<extra></extra>"))
        fig.add_trace(go.Scatter(x=x, y=high.values, name="High Impact (FI≥3)",
                                 mode="lines", line=dict(color=CRITICAL, width=2),
                                 hovertemplate="%{x}<br>%{y} high impact<extra></extra>"))

    theme_layout(fig, height=_EVENTS_H, legend=True)
    fig.update_layout(margin=dict(t=6, b=4, l=4, r=8),
                      legend=dict(orientation="h", yanchor="bottom", y=1.0,
                                  x=0, font=dict(size=10), bgcolor="rgba(0,0,0,0)"))
    if sparse:
        fig.update_xaxes(type="category")
    fig.update_yaxes(gridcolor=LINE, type="log" if log_y else "linear",
                     title_text="commands (log scale)" if log_y else None,
                     title_font=dict(size=10))
    return dcc.Graph(figure=fig, config=GRAPH_CONFIG,
                     style={"height": f"{_EVENTS_H}px"})


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
            html.Div(_pct(sav['cloud_avoided_pct']), className="hp-stat-v",
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


def _origin_map(df, big=False):
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
        return html.Div([dcc.Graph(figure=empty_geo_fig(), config=GEO_CONFIG),
                         html.Div(msg, className="caption", style={"marginTop": "6px"})])

    g = pd.DataFrame(geo_rows)

    # Shade the COUNTRY the attacks came from rather than dropping a bubble on
    # a city centroid: a filled landmass reads as "this is where it is coming
    # from" instantly, where a circle is a point you have to interpret. Counts
    # are summed per country because several source addresses commonly resolve
    # to the same one.
    by_country = (g.groupby("country", as_index=False)["count"].sum()
                   .sort_values("count", ascending=False))
    fig = go.Figure(go.Choropleth(
        locations=by_country["country"],
        # geoip gives names, not ISO codes, so match on names.
        locationmode="country names",
        z=by_country["count"],
        # pale -> deep red by attack volume. zmin pinned to 0 so a single hit
        # still paints visibly instead of washing out to white.
        colorscale=[[0.0, "#FCE3DF"], [0.45, "#E8735F"], [1.0, CRITICAL]],
        zmin=0, zmax=max(int(by_country["count"].max()), 1),
        marker_line_color=LINE_STRONG, marker_line_width=0.6,
        showscale=False,
        hovertemplate="<b>%{location}</b><br>%{z} commands<extra></extra>",
    ))
    fig.update_geos(
        # equirectangular, not natural earth: a flat rectangle fills the panel
        # edge to edge, where natural earth's curved sides leave empty corners.
        projection_type="equirectangular")
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        geo=dict(bgcolor="rgba(0,0,0,0)", landcolor=Y_100, oceancolor=CARD, showocean=True,
                 showland=True, lakecolor=CARD, coastlinecolor=LINE_STRONG,
                 countrycolor=LINE_STRONG, showcoastlines=True, showcountries=True,
                 showframe=False,
                 # Pin the view to the whole world and let it stretch to the
                 # panel. Antarctica and the empty high Arctic are cropped so
                 # the inhabited latitudes -- where every attacker actually is
                 # -- get the vertical space instead of blank ice.
                 lonaxis=dict(range=[-180, 180]),
                 lataxis=dict(range=[-56, 80]),
                 domain=dict(x=[0, 1], y=[0, 1])),
        coloraxis_showscale=False, margin=dict(t=0, b=0, l=0, r=0),
        height=560 if big else 272,
        # dragmode False stops click-drag from rotating/panning the globe;
        # GEO_CONFIG stops the scroll wheel from zooming it.
        dragmode=False)
    return html.Div([
        dcc.Graph(figure=fig, config=GEO_CONFIG),
        html.Div(className="caption", style={"fontSize": "0.66rem", "marginTop": "4px"},
                 children=[f"{len(g)} geolocatable source(s) · IP geolocation by ",
                           html.A("DB-IP", href="https://db-ip.com", target="_blank",
                                  style={"color": "inherit"}), " — City Lite, CC BY 4.0"]),
    ])


# ══════════════════════════════════════════════════════════════════════════
# SOC blocks — facts from threat_intel.aggregator.aggregate_overview().
#
# These COUNT and DISTRIBUTE only. No severity, no risk score, no judgment of
# whether something is malicious — that is a separate detection layer's job.
# Anything whose detail already has a home (MITRE page, Threat Intel page,
# Live page) is summarised here and linked to, never duplicated.
# ══════════════════════════════════════════════════════════════════════════

def _pct(value) -> str:
    """Percentage that never rounds UP into a claim it did not earn.

    `f"{99.9641:.1f}%"` renders "100.0%", which told the operator that 100% of
    cloud calls were avoided when one was not. A dashboard that rounds a near
    miss into a perfect score is worse than one that shows an awkward number:
    the awkward number is true, and the perfect one quietly is not.

    So it FLOORS to one decimal and only ever prints 100% when the value is
    actually 100. Below 0.1% it says "<0.1%" for the same reason -- "0.0%" and
    "nothing happened" are different claims.
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    if v >= 100:
        return "100%"
    if 0 < v < 0.1:
        return "<0.1%"
    return f"{math.floor(v * 10) / 10:.1f}%"


def _fmt_dur(s):
    if s is None:
        return "—"
    s = float(s)
    return f"{s:.0f}s" if s < 90 else (f"{s/60:.1f}m" if s < 5400 else f"{s/3600:.1f}h")


# ── Attention Queue ─────────────────────────────────────────────────────────
# Ranks sessions by ONE explicit, user-chosen, factual column at a time —
# never a blend. A blended rank is a risk score wearing a disguise even when
# every input is a plain count. "Recent" is last_seen, an explicit timestamp
# ordering, not a recency score. Severity stays with the detection layer,
# which is deliberately not wired.
QUEUE_CRITERIA = {
    "techniques": ("Techniques", lambda r: (r["technique_count"], r["commands"])),
    "commands":   ("Commands",   lambda r: (r["commands"],)),
    "tactics":    ("Tactics",    lambda r: (r["tactic_count"], r["commands"])),
    "recent":     ("Recent",     lambda r: (r["last_seen"] or "",)),
}
QUEUE_ROWS = 8


def _attention_queue(o, criterion="techniques"):
    label, keyfn = QUEUE_CRITERIA.get(criterion, QUEUE_CRITERIA["techniques"])
    ranked = sorted(o.get("sessions", []), key=keyfn, reverse=True)[:QUEUE_ROWS]

    rows = []
    for i, r in enumerate(ranked, 1):
        # "Why it's listed" is the counted facts themselves — nothing derived.
        facts = html.Div([
            html.Span(str(r["technique_count"]), className="q-num"), " techniques · ",
            html.Span(str(r["tactic_count"]), className="q-num"), " tactics · ",
            html.Span(f"{r['commands']:,}", className="q-num"), " cmds",
        ], style={"fontSize": "0.74rem", "marginBottom": "4px"})

        # Kill-chain order, each tactic filled with its MITRE stage colour.
        tactics = r["tactics"][:5]
        chain = []
        for n, t in enumerate(tactics):
            if n:
                chain.append(html.Span("→", className="tac-arrow"))
            chain.append(html.Span(t, className="tac-chip",
                                   style={"background": _tactic_color(t)}))
        if not tactics:
            chain = [html.Span("no tagged technique", className="caption")]

        techs = [html.Span(t, className="tech-chip") for t in r["technique_ids"][:5]]
        if len(r["technique_ids"]) > 5:
            techs.append(html.Span(f"+{len(r['technique_ids']) - 5}", className="caption"))

        rows.append(html.Tr([
            html.Td(str(i), className="caption"),
            html.Td(str(r["session_id"])[:14], style={"fontWeight": 700}),
            html.Td(str(r["src_ip"])[:20], className="caption"),
            html.Td([facts, html.Div(chain), html.Div(techs, style={"marginTop": "3px"})]),
            html.Td(r["last_seen"] or "—", className="caption"),
        ]))

    picker = html.Div(className="hp-range", children=[
        html.Button(QUEUE_CRITERIA[c][0], id={"type": "queue-rank", "c": c},
                    n_clicks=0, className="active" if c == criterion else "")
        for c in QUEUE_CRITERIA
    ])

    return _panel("Attention Queue — activity worth investigating", html.Div([
        html.Div([html.Span("Ranked by ", className="caption"), picker],
                 style={"display": "flex", "alignItems": "center", "gap": "8px"}),
        html.Table(className="hp-tbl", style={"marginTop": "10px"}, children=[
            html.Thead(html.Tr([html.Th("#"), html.Th("SESSION"), html.Th("SOURCE"),
                                html.Th("WHY IT'S LISTED"), html.Th("LAST SEEN")])),
            html.Tbody(rows)]) if rows else
        html.Div("No session activity in this window.", className="caption"),
    ]), right=html.Span(f"ordered by {label.lower()}", className="caption"))


def _activity_overview(o):
    a, f, i = o["activity"], o["funnel"], o["iocs"]
    return _panel("Activity Overview", html.Div(className="metric-row", children=[
        _kpi("Sessions", f"{a['session_count']:,}", icon="▤", icon_bg=Y_200),
        _kpi("Commands", f"{a['command_count']:,}", icon="⌘", icon_bg=Y_200),
        _kpi("Source IPs", f"{a['distinct_src_ips']:,}", icon="◈", icon_bg=Y_100),
        _kpi("IOCs", f"{i.get('distinct_total', 0):,}", icon="◆", icon_bg=Y_100),
        _kpi("Auth Attempts", f"{f['login_attempts']:,}", icon="⌸", icon_bg=Y_100),
        _kpi("Active Sessions", f"{a['active_sessions']:,}", icon="◉", icon_bg=Y_300,
             sub="within inactivity timeout"),
    ]))


def _attack_timeline(o):
    """PRIMARY chart: when did activity spike. Commands and sessions come from
    the session table, auth from the auth table -- drawn together but never
    joined (auth rows carry no session_id)."""
    tl = o["timeline"]
    if not tl:
        return _panel("Attack Activity Over Time",
                      html.Div("No activity in this window.", className="caption"))
    x = [b["bucket_start"] for b in tl]
    sparse = len(tl) <= _DENSE_BUCKETS
    fig = go.Figure()
    mk = (lambda name, key, colour:
          go.Bar(x=x, y=[b[key] for b in tl], name=name, marker_color=colour)
          if sparse else
          go.Scatter(x=x, y=[b[key] for b in tl], name=name, mode="lines",
                     line=dict(color=colour, width=2)))
    fig.add_trace(mk("Commands", "commands", ORANGE))
    fig.add_trace(mk("Login attempts", "logins", Y_400))
    fig.add_trace(mk("Sessions", "sessions", CRITICAL))
    if sparse:
        fig.update_layout(barmode="group", bargap=0.3)
        fig.update_xaxes(type="category")
    theme_layout(fig, height=_EVENTS_H, legend=True)
    # Login attempts run to tens of thousands while sessions are double
    # digits; on a linear axis the two smaller series are flat against zero
    # and the chart shows one spike. Log keeps all three readable, and the
    # axis says so rather than quietly rescaling.
    vals = [v for b in tl for v in (b["commands"], b["logins"], b["sessions"]) if v > 0]
    if vals and (max(vals) / min(vals)) > _LOG_Y_RATIO:
        fig.update_yaxes(type="log", title_text="events (log scale)",
                         title_font=dict(size=10))
    fig.update_layout(margin=dict(t=6, b=4, l=4, r=8),
                      legend=dict(orientation="h", yanchor="bottom", y=1.0, x=0,
                                  font=dict(size=10), bgcolor="rgba(0,0,0,0)"))
    fig.update_yaxes(gridcolor=LINE)
    return _panel("Attack Activity Over Time",                   body=dcc.Graph(figure=fig, config=GRAPH_CONFIG,
                            style={"height": f"{_EVENTS_H}px"}),
                  right=html.Span(f"bucket {o['window']['bucket_seconds']}s",
                                  className="caption"))


def _mitre_block(o):
    m = o["mitre"]
    cov = m["coverage"]
    pct = (100.0 * cov["tagged"] / cov["total"]) if cov["total"] else 0.0
    techs = m["techniques"][:5]
    return _panel("MITRE ATT&CK Activity", html.Div([
        _bars(m["tactics"], colour=Y_400, n=6),
        html.Div("Top techniques", className="caption", style={"marginTop": "10px"}),
        html.Table(className="hp-tbl", children=[html.Tbody([
            html.Tr([html.Td(t["technique_id"], style={"fontWeight": 700}),
                     html.Td(t["name"]),
                     html.Td(f"{t['count']:,}", style={"textAlign": "right"})])
            for t in techs])]) if techs else
        html.Div("No tagged commands in this window.", className="caption"),
    ]), right=html.Span(f"{cov['tagged']:,}/{cov['total']:,} tagged ({pct:.0f}%)",
                        className="caption"))


def _top_sources(o):
    ips = o["source_ips"][:6]
    rows = [html.Tr([
        html.Td(str(r["src_ip"]), style={"fontWeight": 700}),
        html.Td(f"{r['commands']:,} cmds"),
        html.Td(f"{r['sessions']:,} sess"),
        html.Td(", ".join(r["tactics"][:2]) or "—", className="caption"),
    ]) for r in ips]
    return _panel("Top Source Activity",                   (html.Table(className="hp-tbl", children=[html.Tbody(rows)]) if rows
                        else html.Div("No session activity in this window.",
                                      className="caption")),
                  right=html.Span("by command volume", className="caption"))


def _ioc_block(o):
    i = o["iocs"]
    by_type = i.get("by_type", {})
    creds = by_type.get("credential", 0)
    other = {k: v for k, v in by_type.items() if k != "credential"}
    compared = i.get("compared")
    return _panel("IOC Activity", html.Div([
        html.Div(className="metric-row", children=[
            _kpi("New", f"{i.get('new_vs_prev', 0):,}", icon="✦", icon_bg=Y_300,
                 sub="vs previous period" if compared else "no prior period"),
            _kpi("Recurring", f"{i.get('recurring', 0):,}", icon="↻", icon_bg=Y_100),
            _kpi("Total", f"{i.get('distinct_total', 0):,}", icon="◆", icon_bg=Y_200),
        ]),
        html.Div("Network / file indicators", className="caption",
                 style={"marginTop": "8px"}),
        _bars(other, colour=ORANGE, n=6),
        html.Div(f"credential pairs: {creds:,} (from auth attempts)",
                 className="caption", style={"marginTop": "6px"}),
    ]))


def _session_stats(o):
    s = o["session_stats"]
    return _panel("Session Statistics", html.Div([
        html.Div("Session duration", className="caption"),
        _bars(s.get("duration_bands", {}), colour=Y_400, n=4),
        html.Div(className="metric-row", style={"marginTop": "10px"}, children=[
            _kpi("Duration p50", _fmt_dur(s.get("duration_p50_s")), icon="◷", icon_bg=Y_100),
            _kpi("Duration p90", _fmt_dur(s.get("duration_p90_s")), icon="◷", icon_bg=Y_100),
            _kpi("Commands p50", f"{s.get('commands_p50') or 0:,}", icon="❯", icon_bg=Y_200),
            _kpi("Commands p90", f"{s.get('commands_p90') or 0:,}", icon="❯", icon_bg=Y_200),
        ]),
    ]))


def _auth_funnel(o):
    f = o["funnel"]
    step = lambda label, value: html.Div(className="hp-stat", children=[
        html.Div(label, className="hp-stat-l"),
        html.Div(f"{value:,}", className="hp-stat-v")])
    arrow = html.Div("↓", className="caption",
                     style={"textAlign": "center", "margin": "2px 0"})
    return _panel("Authentication Funnel", html.Div([
        step("TCP CONNECTIONS", f["connections"]), arrow,
        step("LOGIN ATTEMPTS", f["login_attempts"]), arrow,
        step("ACCEPTED", f["login_success"]),
        html.Div(style={"display": "grid", "gridTemplateColumns": "repeat(2,1fr)",
                        "gap": "9px", "marginTop": "9px"}, children=[
            step("REJECTED", f["login_failed"]),
            step("REFUSED (AT CAPACITY)", f["refused_capacity"]),
        ]),
        html.Div("Auth and session activity are parallel timelines — the auth "
                 "table carries no session_id, so they are never joined.",
                 className="caption", style={"marginTop": "10px"}),
    ]), right=html.Span(f"{f['distinct_auth_ips']:,} distinct IPs", className="caption"))


def _investigate():
    """Aggregation points at what to drill into; the detail lives on the pages
    that own it. Buttons reuse the nav ids so a click switches page through the
    existing router rather than a second navigation mechanism."""
    return _panel("Investigate", html.Div([
        html.Div("These are roll-ups. Open the page that owns the detail:",
                 className="caption"),
        html.Div(style={"marginTop": "12px", "display": "flex", "flexWrap": "wrap",
                        "gap": "10px"}, children=[
            html.Button("Investigation →", id={"type": "page-nav", "target": "Investigation", "src": "investigate"}, className="btn-cta", n_clicks=0),
            html.Button("Live Attack Feed →", id={"type": "page-nav", "target": "Live", "src": "investigate"}, className="btn-cta", n_clicks=0),
            html.Button("MITRE ATT&CK →", id={"type": "page-nav", "target": "MITRE ATT&CK", "src": "investigate"}, className="btn-cta", n_clicks=0),
            html.Button("Threat Intel / IOCs →", id={"type": "page-nav", "target": "Threat Intel", "src": "investigate"}, className="btn-cta", n_clicks=0),
        ]),
    ]))


def build_summary_page(sensor_filter="all", rng="ALL", criterion="techniques"):
    df_all = load_all()
    auth_entries = load_auth_log()
    all_sensors = get_sensor_summary()   # pre-filter, so every sensor stays listed

    inst = None if sensor_filter in (None, "all") else sensor_filter
    # ONE window drives the whole page. The SOC blocks come from
    # aggregate_overview() (facts, counted in the service layer); the map and
    # the operational panels need a DataFrame, so they are filtered to the
    # SAME resolved window rather than to a second, separately-computed one.
    # is_experiment_row is passed through so both paths agree on what counts as
    # real attacker traffic -- without it the page showed 16,409 commands in
    # one block and 2,788 in another.
    overview = load_overview(preset=rng or "ALL", instance=inst)
    win = overview["window"]

    df = df_all
    if inst and not df.empty:
        df = df[df["instance"] == inst]
        auth_entries = [a for a in auth_entries if a.get("instance") == inst]
    # Auth rows get the same window as the session rows. Without this the
    # operational panel counted every login ever (75,689) next to a funnel
    # scoped to the window (75,443) -- two different answers to one question
    # on one screen.
    auth_entries = [a for a in auth_entries
                    if a.get("timestamp") and win["start"] <= a["timestamp"] <= win["end"]
                    and not is_experiment_row(a)]
    if not df.empty and "timestamp" in df.columns:
        df = df[(df["timestamp"] >= pd.Timestamp(win["start"])) &
                (df["timestamp"] <= pd.Timestamp(win["end"]))]
    range_note = None if not df.empty else f"No activity between {win['start']} and {win['end']}."

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

    # ── row 1: attacker map + critical alert ──────────────────────────────
    # The map is the headline of this page: it answers "who is hitting us and
    # from where" at a glance, which is what a SOC overview is for. The live
    # terminal that used to sit here moved to its own full-screen Live page --
    # a scrolling feed is something you watch, not something you glance at.
    row_feed = html.Div(className="hp-row hp-row-feed", children=[
        _panel("Attacker Origin Map", _origin_map(df, big=True)),
        html.Div(_open_alerts_card(inst),
                 id={"type": "alert-card", "i": "summary"}),
    ])

    # ── operational KPI strip ─────────────────────────────────────────────
    # Sessions / commands / source IPs deliberately NOT repeated here: they are
    # the Activity Overview block below, and showing the same three numbers
    # twice on one page is noise. What is left is FI and cost -- HydraPoT
    # engine metrics, so this strip renders inside the operational section.
    row_kpi = html.Div(className="hp-row", style={
        "gridTemplateColumns": "minmax(0,1fr) minmax(0,1.35fr)"}, children=[
        _kpi("High Impact Commands (FI ≥ 3)", f"{n_hi:,}",
             f"{n_hi/len(df)*100:.1f}% of total", "🛡", "rgba(217,45,32,0.13)", critical=True),
        html.Div(className="kpi", children=[
            html.Div("Efficiency (Cost Savings)", className="kpi-l",
                     style={"marginBottom": "9px"}),
            html.Div(className="kpi-split", children=[
                html.Div(className="kpi-mini save", children=[
                    html.Div("Cloud Cost Saved (est.)", className="kpi-mini-l"),
                    html.Div(f"${sav['cloud_saved_usd']:.2f}", className="kpi-mini-v",
                             style={"color": SUCCESS}),
                    html.Div(f"{_pct(sav['cloud_avoided_pct'])} avoided",
                             className="kpi-s")]),
                html.Div(className="kpi-mini energy", children=[
                    html.Div("Energy Cost Saved (est.)", className="kpi-mini-l"),
                    html.Div(f"{sav['energy_saved_thb']:.2f} ฿", className="kpi-mini-v",
                             style={"color": Y_700}),
                    html.Div(f"{_pct(sav['energy_avoided_pct'])} avoided",
                             className="kpi-s")]),
            ]),
        ]),
    ])

    # ── SOC roll-ups (facts only, from aggregate_overview) ────────────────
    row_activity = html.Div(className="hp-row hp-row-full", children=[
        _activity_overview(overview)])
    row_queue = html.Div(id="summary-queue", className="hp-row hp-row-full",
                         children=[_attention_queue(overview, criterion)])
    row_timeline = html.Div(className="hp-row hp-row-full", children=[
        _attack_timeline(overview)])
    row_what_where = html.Div(className="hp-row", style={
        "gridTemplateColumns": "minmax(0,1fr) minmax(0,1fr)"}, children=[
        _mitre_block(overview), _top_sources(overview)])
    row_ioc = html.Div(className="hp-row hp-row-full", children=[_ioc_block(overview)])
    row_sessions_auth = html.Div(className="hp-row", style={
        "gridTemplateColumns": "minmax(0,1fr) minmax(0,1fr)"}, children=[
        _session_stats(overview), _auth_funnel(overview)])
    row_investigate = html.Div(className="hp-row hp-row-full", children=[_investigate()])

    # ── operational: HydraPoT's own engine metrics, LAST and labelled ─────
    # Deliberately below the security facts and visually separated: FI, agent
    # routing and cost describe how the honeypot ran, not what the attacker
    # did. They live here because no other page owns them.
    row_ops = html.Div([
        html.Div("HydraPoT operational metrics — engine behaviour, not security findings",
                 className="caption", style={"margin": "18px 0 6px"}),
        row_kpi,
        html.Div(className="hp-row hp-row-bot", children=[
            _panel("Authentication Intelligence", _auth_panel(df, auth_entries)),
            _panel("HydraPoT Intelligence", _hydrapot_intel(df, sav)),
            _panel("Agent Distribution", _agent_donut(df)),
        ]),
    ])

    footer = html.Div(className="hp-foot", children=[
        html.Span("HydraPoT · An Intelligent Multi-Agent Honeypot Framework"),
        html.Span(f"{len(all_sensors)} sensor(s) · window: {rng or 'ALL'}"
                  + (f" · {sensor_filter}" if sensor_filter != "all" else "")),
    ])

    return [header, sensor_chips, row_feed,
            row_activity, row_queue, row_timeline,
            row_what_where, row_ioc,
            row_sessions_auth, row_investigate, row_ops, footer]


@app.callback(
    Output("summary-queue", "children"),
    Input({"type": "queue-rank", "c": ALL}, "n_clicks"),
    State("range-store", "data"),
    State("sensor-filter-store", "data"),
    prevent_initial_call=True,
)
def _requeue(_clicks, rng, sensor_filter):
    """Re-rank the Attention Queue only — not the whole page.

    A pattern-matching Input also fires when its components are CREATED, with
    n_clicks=0, so without this guard every re-render of the queue would
    re-trigger this callback in a loop.
    """
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    trig = ctx.triggered_id or {}
    criterion = trig.get("c", "techniques") if isinstance(trig, dict) else "techniques"
    inst = None if sensor_filter in (None, "all") else sensor_filter
    o = load_overview(preset=rng or "ALL", instance=inst)
    return [_attention_queue(o, criterion)]


_last_alert_sig = {}


@app.callback(
    Output({"type": "alert-card", "i": ALL}, "children"),
    Input("slow-interval", "n_intervals"),
    State("sensor-filter-store", "data"),
)
def _refresh_open_alerts(_tick, sensor_filter):
    """Keep the open-alerts card honest against the page cache — but only when
    something actually changed.

    build_summary_page() is served from _cached_page() for PAGE_TTL, so a card
    built into it keeps showing "3 NEW" for five minutes after an analyst
    acknowledged one on the Investigation page: the summary contradicting the
    workspace. Hence a tick -- the SLOW one (5s), not the live feed's 1s tick.
    Hanging this off the fast interval round-tripped every second even when the
    answer was no_update, because no_update is decided server-side: the request
    has already happened by then.

    The signature guard is the important half. Returning a fresh card on every
    5s tick replaced the card's DOM ~720 times an hour for something that
    changes when a person clicks -- visible flicker, and a component tree over
    the wire each time. Now the tick does two indexed reads and almost always
    returns no_update.

    A PATTERN Output, not a string one: this id exists only while Summary is on
    screen, and a string Output naming an id absent from the current layout
    breaks the WHOLE callback. A pattern matches an empty set harmlessly.
    """
    n = len(ctx.outputs_list) if isinstance(ctx.outputs_list, list) else 0
    if not n:
        raise PreventUpdate

    inst = None if sensor_filter in (None, "all") else sensor_filter
    key = inst or "all"
    try:
        sig = _alert_signature(inst)
    except Exception:
        raise PreventUpdate           # a DB hiccup must not blank the card
    if _last_alert_sig.get(key) == sig:
        return [no_update] * n
    _last_alert_sig[key] = sig
    return [_open_alerts_card(inst)] * n
