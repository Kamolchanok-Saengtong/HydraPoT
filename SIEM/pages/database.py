"""
SIEM/pages/database.py — Database browser.

Every read here goes through storage.connect_readonly(): mode=ro blocks
writes at the engine level and an authorizer blocks ATTACH, so nothing
entered in the SQL box can modify the database or reach another file. That
matters because `hp dashboard --host 0.0.0.0` is a documented way to run this.
"""
import os

from dash import html, dcc, dash_table, Input, Output, State, ctx, ALL
from dash.exceptions import PreventUpdate

import storage

from SIEM.server import app
from SIEM.theme import TABLE_STYLE, INK

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
    # A pattern-matching Input also fires when its components are CREATED,
    # with n_clicks=0 — so a plain re-render silently re-triggered this and
    # changed state nobody clicked. Only a real click carries a truthy count.
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
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
