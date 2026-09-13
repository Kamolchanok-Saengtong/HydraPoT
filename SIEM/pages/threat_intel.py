"""
SIEM/pages/threat_intel.py — Threat Intel page: generate-on-demand IOC
snapshot, category-filtered table, STIX export.
"""
import os
from collections import Counter
from datetime import datetime

import pandas as pd
import plotly.express as px
from dash import html, dcc, dash_table, Input, Output, State, ctx, ALL
from dash.exceptions import PreventUpdate

import storage
from threat_intel.ioc_extractor import to_stix

from SIEM.server import app
from SIEM.theme import theme_layout, GRAPH_CONFIG, TABLE_STYLE, AMBER_SCALE, Y_50
from SIEM.ioc import build_ioc_snapshot

# Human labels for the IOC scope keys used by _scope_filter_rows(). This was
# referenced by _ioc_status_text() but never defined, so every click on
# "Generate Intelligence" raised NameError after the snapshot had already been
# built — 14 seconds of work thrown away and the button appeared dead. The
# .get() fallback means an unrecognised scope degrades to its raw key rather
# than crashing again.
_SCOPE_LABEL = {
    "all":              "All collected data",
    "last_24h":         "Last 24 hours",
    "current_session":  "Current session",
    "selected_session": "Selected session",
}


def _ioc_status_text(ioc_data):
    if not ioc_data:
        return "No analysis generated yet — click \"Generate Intelligence\" to run it."
    scope = _SCOPE_LABEL.get(ioc_data.get("scope"), ioc_data.get("scope", "all"))
    return f"Last updated: {ioc_data['generated_at']}  ·  scope: {scope}"


def _ioc_table_rows(recs, hide_benign=True):
    """Table rows, benign observables suppressed by default.

    `benign` is set by threat_intel.ioc_extractor against MISP's warninglists
    (public DNS resolvers, Cisco Umbrella top 10k). Those are real observations
    — attackers curl 8.8.8.8 and google.com to test egress — but they are not
    indicators, and they were sitting at the top of the table by volume where
    they read as the honeypot's main finding. Suppressed for display only; the
    snapshot and the STIX export still contain them.
    """
    if hide_benign:
        recs = [r for r in recs if not r.get("benign")]
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


def _benign_count(recs):
    return sum(1 for r in (recs or []) if r.get("benign"))


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
    it re-renders every time you navigate to this page (SIEM/layout.py's
    render_router)."""
    from SIEM.theme import Y_700
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


# ── STIX export — reuses threat_intel.ioc_extractor.to_stix() unchanged, just
# fed the cached ioc-store records instead of a live IOCStore. Written to the
# same data/threat_intel/ directory `hp intel --format stix` uses, then served
# to the browser as a download. ─────────────────────────────────────────────
STIX_OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(storage.__file__)),
                             "data", "threat_intel")

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
    # A pattern-matching Input also fires when its components are CREATED,
    # with n_clicks=0 — so a plain re-render silently re-triggered this and
    # changed state nobody clicked. Only a real click carries a truthy count.
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
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
    rows = _ioc_table_rows(filtered)
    nb = _benign_count(filtered)
    caption = f"{len(recs)} unique indicators — showing {len(rows)}" + (
        "" if selected_cat == "all" else f" of type '{selected_cat}'")
    if nb:
        caption += (f" · {nb} known-benign suppressed "
                    f"(public DNS / Cisco Umbrella top 10k, via MISP warninglists)")
    return rows, classnames, caption
