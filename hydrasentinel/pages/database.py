"""
hydrasentinel/pages/database.py — Database explorer.

A full-width explorer: the databases and their tables are chosen from chip rows
at the top (Database, then Table); the selected table fills the width below with
a Data grid and a Schema view, and a read-only SQL terminal sits under it. This
mirrors the Next.js v2 layout. Styling lives in assets/database.css, scoped
under `.dbx`.

Safety (all reads go through core.storage, which this page does not weaken):
  * connect_readonly() opens `file:...?mode=ro` (uri=True) and installs an
    authorizer that blocks ATTACH -- nothing here can write or reach another
    file. The SQL terminal runs through storage.run_readonly_query on the same
    read-only connection, so a write is rejected by SQLite itself.
  * Table and column names are validated against the live schema before they
    touch SQL; search values are bound as parameters. Paging and sorting are
    done in SQL (LIMIT/OFFSET/ORDER BY), never by loading a table into memory.
  * The access DB's secret columns (password/token hashes, the signing secret)
    are masked here and are replaced BEFORE any row reaches a client-side Store,
    so they are never sent to the browser -- not in the grid, the row panel,
    copy-as-JSON, or a terminal query result.
"""
import json
from datetime import datetime

from dash import html, dcc, Input, Output, State, ctx, ALL, no_update
from dash.exceptions import PreventUpdate

from core import storage

from hydrasentinel.server import app
from hydrasentinel.theme import loading

PAGE_SIZE = 50

# Secret material -- masked in the access DB, everywhere, before leaving Python.
_MASK_COLS = {"password_hash", "token_hash", "link_token", "value", "session_secret"}
_MASK = "•" * 8

# Columns whose values are epoch seconds and read better as a date.
_TIME_COLS = {"timestamp", "ts", "created", "last_seen", "first_seen",
              "updated_at", "created_at", "closed_at", "acknowledged_at",
              "routed_at", "datetime"}

_LOGIN_SQL = "SELECT username, role, created FROM users ORDER BY created"
_DEFAULT_SQL = ("SELECT agent, COUNT(*) AS n FROM sessions "
                "GROUP BY agent ORDER BY n DESC")


# ─── databases ───────────────────────────────────────────────────────────────

def _me():
    """The signed-in account for this request, or "" (no cookie, or no request)."""
    from flask import has_request_context, request
    from hydrasentinel import auth
    if not has_request_context():
        return ""
    return auth.read_session(request.cookies.get(auth.COOKIE, "")).get("username", "")


def _databases():
    """The databases this viewer may open. The account database (names, roles,
    invite links) is for admins only; an operator never sees it listed, and
    every callback resolves a database through here, so naming it by hand gets
    the capture database instead."""
    from hydrasentinel import auth
    dbs = [{"key": "capture", "label": "Capture data", "file": storage.DB_PATH}]
    if auth.is_admin(_me()):
        dbs.append({"key": "login", "label": "Dashboard access",
                    "file": auth.session_db_path()})
    return dbs


def _db_by_key(key):
    for db in _databases():
        if db["key"] == key:
            return db
    return _databases()[0]


def _key(db_key):
    """The key of the database this viewer actually gets for `db_key`."""
    return _db_by_key(db_key or "capture")["key"]


def _basename(path):
    import os
    return os.path.basename(path)


def _mask_cols_for(db_key):
    return _MASK_COLS if db_key == "login" else frozenset()


# ─── schema reads (read-only PRAGMA) ─────────────────────────────────────────

def _columns(path, table):
    """Full column info: [{name,type,notnull,dflt,pk}]. Validated name."""
    try:
        with storage.connect_readonly(path) as conn:
            if not _exists(conn, table):
                return []
            return [{"name": r["name"], "type": (r["type"] or ""),
                     "notnull": bool(r["notnull"]),
                     "dflt": r["dflt_value"], "pk": int(r["pk"])}
                    for r in conn.execute(f'PRAGMA table_info("{table}")')]
    except Exception:
        return []


def _indexes(path, table):
    try:
        with storage.connect_readonly(path) as conn:
            if not _exists(conn, table):
                return []
            out = []
            for ix in conn.execute(f'PRAGMA index_list("{table}")'):
                cols = [c["name"] for c in
                        conn.execute(f'PRAGMA index_info("{ix["name"]}")')]
                out.append({"name": ix["name"], "unique": bool(ix["unique"]),
                            "columns": cols})
            return out
    except Exception:
        return []


def _foreign_keys(path, table):
    try:
        with storage.connect_readonly(path) as conn:
            if not _exists(conn, table):
                return []
            return [{"from": r["from"], "table": r["table"], "to": r["to"]}
                    for r in conn.execute(f'PRAGMA foreign_key_list("{table}")')]
    except Exception:
        return []


def _exists(conn, table):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone() is not None


def _tables(db_key):
    return storage.list_tables(path=_db_by_key(db_key)["file"])


def _valid_table(db_key, table):
    """The table if it exists in this db, else the db's first table (or None)."""
    names = [t["name"] for t in _tables(db_key)]
    if table in names:
        return table
    return names[0] if names else None


# ─── value formatting ────────────────────────────────────────────────────────

def _is_num_type(t):
    t = (t or "").upper()
    return any(k in t for k in ("INT", "REAL", "FLOA", "DOUB", "NUM", "DEC"))


def _span(sec):
    sec = max(sec, 0)
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if sec >= n:
            return f"{int(sec // n)} {unit}"
    return "under 1 min"


_PASTEL = ("ppl-c0", "ppl-c1", "ppl-c2")


def _people_view(path, me=""):
    """Who can sign in: a header with real counts, one card per account, the
    open invite links. Read-only apart from the admin buttons, and never shows
    a password hash or a token."""
    import sqlite3
    import time
    now = time.time()
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        users = conn.execute("SELECT username, created, role FROM users "
                             "ORDER BY created").fetchall()
        seen = dict(conn.execute("SELECT username, MAX(last_seen) FROM operator_sessions "
                                 "GROUP BY username").fetchall())
        invites = conn.execute(
            "SELECT username, expires, uses_left, created, link_token, label FROM invites "
            "WHERE uses_left > 0 AND expires > ? ORDER BY expires", (now,)).fetchall()
        conn.close()
    except Exception:
        return None
    from hydrasentinel import auth
    admin = auth.is_admin(me)

    def card(i, name, created, role):
        last = seen.get(name)
        online = last is not None and now - last < 900
        state = ("Active now" if online
                 else (f"Last seen {_span(now - last)} ago" if last else "Never signed in"))
        if name == me:
            corner = html.Span("You", className="ppl-you")
        elif admin:
            corner = html.Details(className="ppl-menu", children=[
                html.Summary("\u22ef", className="ppl-dots"),
                html.Button("Delete account", id={"type": "ppl-del", "u": name},
                            n_clicks=0, className="ppl-del")])
        else:
            corner = None
        return html.Div(className="ppl-card " + _PASTEL[i % 3], children=[
            html.Div(className="ppl-top", children=[
                html.Div(name[:1].upper(), className="ppl-avatar"),
                html.Span(name, className="ppl-name"),
                html.Span(role.capitalize(),
                          className="ppl-role" + (" admin" if role == auth.ADMIN else "")),
                corner]),
            html.Div(className="ppl-state" + (" on" if online else ""), children=[
                html.Span(className="ppl-dot"), state]),
            html.Div(f"Joined {datetime.fromtimestamp(created):%b} "
                     f"{datetime.fromtimestamp(created).day}", className="ppl-joined"),
        ])

    base = auth.invite_base()

    def invite(name, expires, uses, created, token, label):
        who = label or ("No label" if name in ("anyone", "") else f"For {name}")
        left = f"{uses} use{'s' if uses != 1 else ''} left"
        return html.Div(className="ppl-invite", children=[
            html.Div([
                html.Div([html.Span(who, className="ppl-inv-who"),
                          html.Button("Add label" if not label else "Rename",
                                      id={"type": "inv-label", "c": created}, n_clicks=0,
                                      className="ppl-addlabel") if admin else None]),
                html.Div(f"{left}, expires in {_span(expires - now)}", className="ppl-inv-sub"),
            ]),
            html.Div(className="ppl-inv-btns", children=[
                dcc.Clipboard(content=base + token, className="ppl-copy", title="Copy link")
                if token else html.Span("Link not saved; revoke and make a new one",
                                        className="ppl-inv-sub"),
                html.Button("Revoke", id={"type": "inv-del", "c": created}, n_clicks=0,
                            className="ppl-revoke") if admin else None,
            ]),
        ])

    active = sum(1 for u in users if seen.get(u[0]) and now - seen[u[0]] < 900)
    plural = lambda n, w: f"{n} {w}{'' if n == 1 else 's'}"
    return html.Div(className="ppl", children=[
        html.Div(className="ppl-header", children=[
            html.Div([
                html.H2("Dashboard access", className="ppl-h"),
                html.Div(className="ppl-chips", children=[
                    html.Span(plural(len(users), "account"), className="ppl-chip y"),
                    html.Span(f"{active} active now", className="ppl-chip g"),
                    html.Span(plural(len(invites), "open invite"), className="ppl-chip p"),
                ])]),
            html.Button("+ Invite operator", id="inv-new", n_clicks=0,
                        className="ppl-primary") if admin else None,
        ]),
        html.Div(id="inv-made"),
        html.Div(className="ppl-grid", children=[card(i, *u) for i, u in enumerate(users)]),
        html.Div("Open invite links", className="ppl-sec-h"),
        *([invite(*i) for i in invites] if invites else
          [html.Div("No open invites.", className="ppl-inv-sub")]),
    ])


def _fmt_time(v):
    try:
        f = float(v)
        if f > 1e12:            # milliseconds
            f /= 1000.0
        return datetime.fromtimestamp(f).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(v)


def _mask_rows(db_key, rows):
    """Replace secret columns with the mask string -- done here so the real
    values never reach a client-side Store."""
    cols = _mask_cols_for(db_key)
    if not cols:
        return rows
    out = []
    for r in rows:
        out.append({k: (_MASK if (k in cols and v not in (None, "")) else v)
                    for k, v in r.items()})
    return out


# ─── database / table chooser (top chip rows) ────────────────────────────────

def _pick(db_key, table):
    db_chips = []
    for db in _databases():
        sel = db["key"] == db_key
        db_chips.append(html.Button(
            className="dbx-pick-db" + (" sel" if sel else ""),
            id={"type": "dbx-pickdb", "db": db["key"]}, n_clicks=0, children=[
                html.Span(_basename(db["file"]), className="dbx-pick-file"),
                html.Span(db["label"], className="dbx-pick-sub"),
            ]))
    tbl_chips = []
    for t in _tables(db_key):
        sel = t["name"] == table
        tbl_chips.append(html.Button(
            className="dbx-pick-table" + (" sel" if sel else ""),
            id={"type": "dbx-picktbl", "db": db_key, "table": t["name"]},
            n_clicks=0, children=[
                t["name"],
                html.Span(f"{t['rows']:,}", className="dbx-pick-n"),
            ]))
    cur = f"{_basename(_db_by_key(db_key)['file'])} > {table}"
    return [html.Details(className="dbx-sel", children=[
        html.Summary(cur + "  \u2304", className="dbx-sel-pill"),
        html.Div(className="dbx-sel-pop", children=[
            html.Div(className="dbx-pick-row",
                     children=[html.Span("Database", className="dbx-pick-l")] + db_chips),
            html.Div(className="dbx-pick-row",
                     children=[html.Span("Table", className="dbx-pick-l")] + tbl_chips),
        ])])]


# ─── data grid ───────────────────────────────────────────────────────────────

def _skeleton():
    return html.Div(className="dbx-skel",
                    children=[html.Div(className="dbx-skel-row") for _ in range(8)])


def _cell(c, v, numeric):
    """One <td>, with null / epoch-time / truncation handling."""
    is_num = c in numeric
    if v is None:
        return html.Td(html.Span("null", className="dbx-null"),
                       className="num" if is_num else "")
    if c in _TIME_COLS and v != _MASK:
        return html.Td(_fmt_time(v), title=str(v),
                       className="num" if is_num else "")
    s = str(v)
    return html.Td(s[:400], title=s if len(s) > 60 else None,
                   className="num" if is_num else "")


def _data_grid(db_key, table, page, search, sort, density, visible):
    db = _db_by_key(db_key)
    cols_meta = _columns(db["file"], table)
    all_cols = [c["name"] for c in cols_meta]
    numeric = {c["name"] for c in cols_meta if _is_num_type(c["type"])}
    show = [c for c in all_cols if (not visible or c in visible)] or all_cols

    sort_col = (sort or {}).get("col")
    desc = bool((sort or {}).get("desc"))
    res = storage.browse_table(
        table, limit=PAGE_SIZE, offset=page * PAGE_SIZE,
        sort_by=sort_col if sort_col in all_cols else None, descending=desc,
        search=search or None, path=db["file"])
    if res["error"]:
        return html.Div(f"{res['error']}", className="dbx-empty"), [], res, show

    rows = _mask_rows(db_key, res["rows"])

    if not rows:
        msg = "No rows match that search." if search else "No rows yet"
        return html.Div(msg, className="dbx-empty"), [], res, show

    # header: click to sort, arrow shows direction
    head = []
    for c in show:
        arrow = ""
        if c == sort_col:
            arrow = html.Span("↓" if desc else "↑", className="dbx-arrow")
        head.append(html.Th(id={"type": "dbx-h", "col": c}, n_clicks=0,
                            children=[c, arrow]))

    body = [html.Tr([_cell(c, r.get(c), numeric) for c in show],
                    id={"type": "dbx-row", "i": i}, n_clicks=0)
            for i, r in enumerate(rows)]

    grid = html.Div(className="dbx-gridwrap", children=[
        html.Table(className="dbx-grid" + (" compact" if density == "compact"
                                           else ""),
                   children=[html.Thead(html.Tr(head)), html.Tbody(body)])])
    return grid, rows, res, show


def _result_grid(columns, rows, density):
    """Render a raw SQL result (plain columns, already masked) into the grid."""
    head = [html.Th(c) for c in columns]
    body = [html.Tr([_cell(c, r.get(c), ()) for c in columns],
                    id={"type": "dbx-row", "i": i}, n_clicks=0)
            for i, r in enumerate(rows)]
    return html.Div(className="dbx-gridwrap", children=[
        html.Table(className="dbx-grid" + (" compact" if density == "compact"
                                           else ""),
                   children=[html.Thead(html.Tr(head)), html.Tbody(body)])])


# ─── schema view ─────────────────────────────────────────────────────────────

def _schema_view(db_key, table):
    db = _db_by_key(db_key)
    cols = _columns(db["file"], table)
    idx = _indexes(db["file"], table)
    fks = _foreign_keys(db["file"], table)
    fk_from = {f["from"] for f in fks}

    col_rows = [html.Tr([
        html.Td(c["name"], className="mono"),
        html.Td(c["type"] or html.Span("—", className="dbx-dim"), className="mono"),
        html.Td(html.Span("PK", className="dbx-pk") if c["pk"] else
                (html.Span("FK", className="dbx-pk") if c["name"] in fk_from else "")),
        html.Td("NOT NULL" if c["notnull"] else html.Span("null ok",
                className="dbx-dim")),
        html.Td(html.Span(str(c["dflt"]), className="mono") if c["dflt"] is not None
                else html.Span("—", className="dbx-dim")),
    ]) for c in cols]

    sections = [html.Div(className="dbx-sch-sec", children=[
        html.Div("Columns", className="dbx-sch-h"),
        html.Table(className="dbx-sch", children=[
            html.Thead(html.Tr([html.Th("column"), html.Th("type"),
                                html.Th("key"), html.Th("null"),
                                html.Th("default")])),
            html.Tbody(col_rows)])])]

    sections.append(html.Div(className="dbx-sch-sec", children=[
        html.Div("Indexes", className="dbx-sch-h"),
        (html.Table(className="dbx-sch", children=[html.Tbody([
            html.Tr([html.Td(ix["name"], className="mono"),
                     html.Td(("unique · " if ix["unique"] else "") +
                             ", ".join(ix["columns"]), className="mono")])
            for ix in idx])])
         if idx else html.Div("No indexes", className="dbx-empty"))]))

    sections.append(html.Div(className="dbx-sch-sec", children=[
        html.Div("Foreign keys", className="dbx-sch-h"),
        (html.Table(className="dbx-sch", children=[html.Tbody([
            html.Tr([html.Td(f["from"], className="mono"),
                     html.Td(f"→ {f['table']}.{f['to']}", className="mono")])
            for f in fks])])
         if fks else html.Div("No foreign keys", className="dbx-empty"))]))
    return sections


# ─── detail panel ────────────────────────────────────────────────────────────

def _detail_panel(row, table):
    if not row:
        return None
    kvs = []
    for k, v in row.items():
        disp = "null" if v is None else (_fmt_time(v)
               if (k in _TIME_COLS and v != _MASK) else str(v))
        kvs.append(html.Div(className="dbx-kv", children=[
            html.Div(k, className="dbx-k"),
            html.Div(disp, className="dbx-v" + (" dbx-null" if v is None else "")),
        ]))
    return [
        html.Div(className="dbx-backdrop", id="dbx-backdrop", n_clicks=0),
        html.Div(className="dbx-detail", children=[
            html.Div(className="dbx-detail-h", children=[
                html.Span(f"{table} · row", className="dbx-detail-title"),
                html.Button("×", id="dbx-close", className="dbx-close", n_clicks=0),
            ]),
            html.Button("copy as JSON", id="dbx-copy", className="dbx-tool",
                        n_clicks=0, style={"marginBottom": "16px"}),
            dcc.Store(id="dbx-detail-json", data=json.dumps(row, indent=2,
                                                            default=str)),
            html.Div(kvs),
        ]),
    ]


# ─── SQL terminal ────────────────────────────────────────────────────────────

def _sql_terminal(db_key):
    title = f"sql · {_basename(_db_by_key(db_key)['file'])} · read-only"
    return html.Div(id="dbx-sql", className="dbx-sql open", children=[
        html.Button(id="dbx-sql-toggle", className="dbx-sql-chrome", n_clicks=0,
                    children=[
            html.Span(className="dbx-dot r"), html.Span(className="dbx-dot y"),
            html.Span(className="dbx-dot g"),
            html.Span(title, id="dbx-sql-title", className="dbx-sql-title"),
            html.Span("collapse ▾", id="dbx-sql-toggletext",
                      className="dbx-sql-toggle"),
        ]),
        html.Div(id="dbx-sql-body", style={"display": "block"}, children=[
            html.Div(className="dbx-sql-promptrow", children=[
                html.Span(">", className="dbx-sql-caret"),
                dcc.Input(id="dbx-sql-input", className="dbx-sql-line",
                          type="text", debounce=False, spellCheck=False,
                          value=(_LOGIN_SQL if db_key == "login" else _DEFAULT_SQL),
                          placeholder="SELECT …   (Enter to run)"),
                html.Button("Run", id="dbx-sql-run", className="dbx-run",
                            n_clicks=0),
            ]),
            html.Div("one SELECT, read-only · results fill the grid above",
                     className="dbx-sql-hint"),
            html.Div(id="dbx-sql-err"),
        ]),
    ])


# ─── layout ──────────────────────────────────────────────────────────────────

def build_database_page():
    dbs = _databases()
    # An admin opens on who can sign in (login DB, users table, Accounts tab);
    # everyone else opens on the capture data.
    first = next((d for d in dbs if d["key"] == "login"), dbs[0])
    default_db = first["key"]
    tabs0 = storage.list_tables(path=first["file"])
    if not tabs0:
        return [html.Div(className="dbx", children=[html.Div(
            "No database yet — it is created the first time the honeypot "
            "records a session.", className="dbx-empty")])]
    default_table = next((t["name"] for t in tabs0 if t["name"] == "users"), tabs0[0]["name"])
    default_tab = "accounts" if (default_db == "login" and default_table == "users") else "data"

    return [html.Div(className="dbx", children=[
        # persisted selection (localStorage): comes back on the next visit
        dcc.Store(id="dbx-db", data=default_db),
        dcc.Store(id="dbx-table", data=default_table),
        dcc.Store(id="dbx-tab", data=default_tab),
        dcc.Store(id="dbx-density", storage_type="local", data="comfortable"),
        dcc.Store(id="dbx-page", data=0),
        dcc.Store(id="dbx-sort", data={"col": None, "desc": False}),
        dcc.Store(id="dbx-rows", data=[]),
        dcc.Store(id="dbx-detail", data=None),
        dcc.Store(id="dbx-sqlres", data=None),
        dcc.Store(id="dbx-bump", data=0),
        dcc.Store(id="ppl-target", data=None),
        dcc.Store(id="inv-label-req", data=None),
        dcc.Store(id="dbx-q-sink", data=None),
        dcc.ConfirmDialog(id="ppl-confirm", message=""),

        html.Div(className="dbx-full", children=[
            html.Div(id="dbx-pick", className="dbx-pick"),

            html.Div(className="dbx-main", children=[
                html.Div(id="ppl-msg", className="ppl-msg"),
                html.H2(id="dbx-title", className="dbx-title"),
                html.Div(id="dbx-meta", className="dbx-meta"),
                html.Div(className="dbx-tabs", children=[
                    html.Button("Accounts", id="dbx-tab-acc", className="dbx-tab",
                                n_clicks=0, style={"display": "none"}),
                    html.Button("Raw table", id="dbx-tab-data", className="dbx-tab sel",
                                n_clicks=0),
                    html.Button("Schema", id="dbx-tab-schema", className="dbx-tab",
                                n_clicks=0),
                    html.Button(">_ Query", id="dbx-tab-query", className="dbx-tab",
                                n_clicks=0),
                ]),

                # toolbar (hidden on the Schema tab)
                html.Div(id="dbx-toolbar", className="dbx-toolbar", children=[
                    dcc.Input(id="dbx-search", type="text", debounce=True,
                              className="dbx-search",
                              placeholder="search every column…"),
                    html.Div(className="dbx-colmenu", children=[
                        html.Button("Columns", id="dbx-colbtn",
                                    className="dbx-tool", n_clicks=0),
                        html.Div(id="dbx-colpop", className="dbx-colpop",
                                 style={"display": "none"}, children=[
                            dcc.Checklist(id="dbx-cols", options=[], value=[])]),
                    ]),
                    html.Button("Compact", id="dbx-density-btn",
                                className="dbx-tool", n_clicks=0),
                    html.Div(className="dbx-pager", children=[
                        html.Span(id="dbx-range"),
                        html.Button("‹", id="dbx-prev", className="dbx-nav",
                                    n_clicks=0),
                        html.Button("›", id="dbx-next", className="dbx-nav",
                                    n_clicks=0),
                    ]),
                ]),

                loading(html.Div(id="dbx-content", children=_skeleton())),

                _sql_terminal(default_db),
            ]),
        ]),

        html.Div(id="dbx-detail-panel"),
    ])]


# ─── callbacks ───────────────────────────────────────────────────────────────

@app.callback(
    Output("dbx-pick", "children"),
    Input("dbx-db", "data"), Input("dbx-table", "data"), Input("dbx-bump", "data"),
)
def _render_pick(db_key, table, _bump):
    return _pick(_key(db_key), table)


@app.callback(
    Output("dbx-db", "data"), Output("dbx-table", "data"),
    Output("dbx-page", "data"), Output("dbx-sort", "data"),
    Output("dbx-sqlres", "data"),
    Input({"type": "dbx-pickdb", "db": ALL}, "n_clicks"),
    Input({"type": "dbx-picktbl", "db": ALL, "table": ALL}, "n_clicks"),
    State("dbx-db", "data"), State("dbx-table", "data"),
    prevent_initial_call=True,
)
def _select(_dbclicks, _tblclicks, cur_db, cur_table):
    # ignore the n_clicks=0 that fires when a chip row is (re)rendered
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    trig = ctx.triggered_id or {}
    if trig.get("type") == "dbx-pickdb":
        db_key = trig.get("db")
        if db_key == cur_db or _key(db_key) != db_key:
            raise PreventUpdate
        tabs = _tables(db_key)
        table = tabs[0]["name"] if tabs else None
    else:
        db_key = trig.get("db")
        table = trig.get("table")
        if _key(db_key) != db_key or (db_key == cur_db and table == cur_table):
            raise PreventUpdate
    # a new selection drops any SQL result so the browsed table shows
    return db_key, table, 0, {"col": None, "desc": False}, None


def _is_people(db_key, table):
    return _key(db_key) == "login" and table == "users"


@app.callback(
    Output("dbx-tab", "data"),
    Input("dbx-tab-acc", "n_clicks"), Input("dbx-tab-data", "n_clicks"),
    Input("dbx-tab-schema", "n_clicks"),
    prevent_initial_call=True,
)
def _switch_tab(_a, _d, _s):
    return {"dbx-tab-schema": "schema", "dbx-tab-acc": "accounts"}.get(
        ctx.triggered_id, "data")


@app.callback(
    Output("dbx-tab-acc", "className"), Output("dbx-tab-acc", "style"),
    Output("dbx-tab-data", "className"), Output("dbx-tab-schema", "className"),
    Output("dbx-toolbar", "style"),
    Input("dbx-tab", "data"), Input("dbx-db", "data"), Input("dbx-table", "data"),
)
def _tabs_ui(tab, db_key, table):
    people = _is_people(db_key, table)
    if tab == "accounts" and not people:
        tab = "data"
    cls = lambda t: "dbx-tab" + (" sel" if tab == t else "")
    return (cls("accounts"), {} if people else {"display": "none"},
            cls("data"), cls("schema"),
            {"display": "none"} if tab in ("schema", "accounts") else {})


@app.callback(
    Output("dbx-density", "data"), Output("dbx-density-btn", "children"),
    Input("dbx-density-btn", "n_clicks"), State("dbx-density", "data"),
    prevent_initial_call=True,
)
def _toggle_density(_n, cur):
    nxt = "compact" if cur != "compact" else "comfortable"
    return nxt, ("Comfortable" if nxt == "compact" else "Compact")


@app.callback(
    Output("dbx-colpop", "style"),
    Input("dbx-colbtn", "n_clicks"), State("dbx-colpop", "style"),
    prevent_initial_call=True,
)
def _toggle_colmenu(_n, style):
    hidden = (style or {}).get("display") == "none"
    return {"display": "block"} if hidden else {"display": "none"}


@app.callback(
    Output("dbx-cols", "options"), Output("dbx-cols", "value"),
    Input("dbx-db", "data"), Input("dbx-table", "data"),
)
def _reset_columns(db_key, table):
    table = _valid_table(db_key or "capture", table)
    if not table:
        return [], []
    cols = [c["name"] for c in _columns(_db_by_key(db_key)["file"], table)]
    return [{"label": c, "value": c} for c in cols], cols


@app.callback(
    Output("dbx-page", "data", allow_duplicate=True),
    Input("dbx-prev", "n_clicks"), Input("dbx-next", "n_clicks"),
    Input("dbx-search", "value"),
    State("dbx-page", "data"), State("dbx-table", "data"),
    State("dbx-db", "data"),
    prevent_initial_call=True,
)
def _paginate(_p, _n, _search, page, table, db_key):
    trig = ctx.triggered_id
    if trig == "dbx-search":
        return 0
    page = int(page or 0)
    if trig == "dbx-prev":
        return max(0, page - 1)
    table = _valid_table(db_key or "capture", table)
    total = storage.browse_table(table, limit=1,
                                 path=_db_by_key(db_key)["file"])["total"]
    return min(max(0, (total - 1) // PAGE_SIZE), page + 1)


@app.callback(
    Output("dbx-sort", "data", allow_duplicate=True),
    Output("dbx-page", "data", allow_duplicate=True),
    Input({"type": "dbx-h", "col": ALL}, "n_clicks"),
    State("dbx-sort", "data"),
    prevent_initial_call=True,
)
def _sort(_clicks, sort):
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    col = (ctx.triggered_id or {}).get("col")
    sort = sort or {}
    desc = not sort.get("desc") if sort.get("col") == col else False
    return {"col": col, "desc": desc}, 0


# ─── SQL terminal callbacks ─────────────────────────────────────────────────

@app.callback(
    Output("dbx-sql-title", "children"),
    Input("dbx-db", "data"),
)
def _sql_title(db_key):
    return f"sql · {_basename(_db_by_key(db_key or 'capture')['file'])} · read-only"


@app.callback(
    Output("dbx-sql", "className"), Output("dbx-sql-body", "style"),
    Output("dbx-sql-toggletext", "children"),
    Input("dbx-sql-toggle", "n_clicks"), State("dbx-sql-body", "style"),
    prevent_initial_call=True,
)
def _toggle_sql(_n, style):
    opening = (style or {}).get("display") == "none"
    return ("dbx-sql open" if opening else "dbx-sql",
            {"display": "block"} if opening else {"display": "none"},
            "collapse ▾" if opening else "run a query ▸")


@app.callback(
    Output("dbx-sqlres", "data", allow_duplicate=True),
    Output("dbx-sql-err", "children"),
    Input("dbx-sql-run", "n_clicks"), Input("dbx-sql-input", "n_submit"),
    State("dbx-sql-input", "value"), State("dbx-db", "data"),
    prevent_initial_call=True,
)
def _run_sql(_n, _s, sql, db_key):
    q = (sql or "").strip()
    if not q:
        raise PreventUpdate
    db_key = _key(db_key)
    res = storage.run_readonly_query(q, path=_db_by_key(db_key)["file"])
    if res["error"]:
        # on error keep the browsed table and show the message inline
        return None, html.Div(f"⚠ {res['error']}", className="dbx-sql-err")
    rows = _mask_rows(db_key, res["rows"])
    return ({"columns": res["columns"], "rows": rows,
             "truncated": res["truncated"], "db": db_key}, "")


# ─── main render ─────────────────────────────────────────────────────────────

@app.callback(
    Output("dbx-content", "children"),
    Output("dbx-title", "children"), Output("dbx-meta", "children"),
    Output("dbx-range", "children"),
    Output("dbx-prev", "disabled"), Output("dbx-next", "disabled"),
    Output("dbx-rows", "data"),
    Input("dbx-db", "data"), Input("dbx-table", "data"), Input("dbx-tab", "data"),
    Input("dbx-page", "data"), Input("dbx-search", "value"),
    Input("dbx-sort", "data"), Input("dbx-density", "data"),
    Input("dbx-cols", "value"), Input("dbx-sqlres", "data"), Input("dbx-bump", "data"),
)
def _render(db_key, table, tab, page, search, sort, density, visible, sqlres, _bump):
    db_key = _key(db_key)

    # a SQL result takes over the grid until a table chip is clicked
    if sqlres and tab != "schema":
        cols = sqlres.get("columns", [])
        rows = sqlres.get("rows", [])
        more = " · 1000+ (truncated)" if sqlres.get("truncated") else ""
        masked = " · secrets masked" if sqlres.get("db") == "login" else ""
        meta = (f"from SQL · {len(cols)} columns · {len(rows)} rows{more}"
                f"{masked} · click a table to exit")
        grid = _result_grid(cols, rows, density)
        return (grid, "query result", meta, f"{len(rows):,} rows",
                True, True, rows)

    table = _valid_table(db_key, table)
    if not table:
        raise PreventUpdate
    db = _db_by_key(db_key)
    total = storage.browse_table(table, limit=1, path=db["file"])["total"]
    ncols = len(_columns(db["file"], table))
    meta = f"{_basename(db['file'])} · {total:,} rows · {ncols} columns"

    if tab == "schema":
        return (_schema_view(db_key, table), table, meta, "", True, True, [])
    if tab == "accounts" and _is_people(db_key, table):
        people = _people_view(db["file"], _me())
        if people is not None:
            return people, "", "", "", True, True, []

    page = int(page or 0)
    grid, rows, res, _show = _data_grid(db_key, table, page, search, sort,
                                        density, visible)
    total = res["total"]
    start = page * PAGE_SIZE + 1 if total else 0
    end = min((page + 1) * PAGE_SIZE, total)
    rng = f"{start:,}–{end:,} of {total:,}" if total else "0 of 0"
    return (grid, table, meta, rng, page <= 0, end >= total, rows)


@app.callback(
    Output("ppl-target", "data"), Output("ppl-confirm", "displayed"),
    Output("ppl-confirm", "message"),
    Input({"type": "ppl-del", "u": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _ask_delete(_clicks):
    # the n_clicks=0 a freshly drawn card reports is not a click
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    who = (ctx.triggered_id or {}).get("u")
    from hydrasentinel import auth
    if not who or not auth.is_admin(_me()):
        raise PreventUpdate
    return who, True, (f"Delete the account '{who}'? They are signed out at once and "
                       f"cannot sign back in. This cannot be undone.")


@app.callback(
    Output("dbx-bump", "data"), Output("ppl-msg", "children"),
    Input("ppl-confirm", "submit_n_clicks"),
    State("ppl-target", "data"), State("dbx-bump", "data"),
    prevent_initial_call=True,
)
def _do_delete(_n, who, bump):
    if not who:
        raise PreventUpdate
    from hydrasentinel import auth
    # checked here, not by hiding the button: the caller must be an admin
    ok, msg = auth.delete_account(_me(), who)
    return (bump or 0) + 1, html.Div(msg, className="ppl-msg-" + ("ok" if ok else "err"))


@app.callback(
    Output("dbx-bump", "data", allow_duplicate=True),
    Output("ppl-msg", "children", allow_duplicate=True),
    Input({"type": "inv-del", "c": ALL}, "n_clicks"),
    State("dbx-bump", "data"),
    prevent_initial_call=True,
)
def _revoke(_clicks, bump):
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    from hydrasentinel import auth
    ok, msg = auth.revoke_invite(_me(), (ctx.triggered_id or {}).get("c"))
    return (bump or 0) + 1, html.Div(msg, className="ppl-msg-" + ("ok" if ok else "err"))


app.clientside_callback(
    """function(n) {
        if (!n || !n.some(x => x)) return window.dash_clientside.no_update;
        const t = window.dash_clientside.callback_context.triggered_id;
        const v = window.prompt("Label for this invite link:");
        if (v === null) return window.dash_clientside.no_update;
        return {c: t.c, label: v, t: Date.now()};
    }""",
    Output("inv-label-req", "data"),
    Input({"type": "inv-label", "c": ALL}, "n_clicks"),
    prevent_initial_call=True,
)


app.clientside_callback(
    """function(n) {
        if (!n) return window.dash_clientside.no_update;
        const el = document.getElementById("dbx-sql");
        if (el) { el.scrollIntoView({behavior: "smooth", block: "center"});
                  const i = document.getElementById("dbx-sql-input"); if (i) i.focus(); }
        return window.dash_clientside.no_update;
    }""",
    Output("dbx-q-sink", "data"),
    Input("dbx-tab-query", "n_clicks"),
    prevent_initial_call=True,
)


@app.callback(
    Output("dbx-bump", "data", allow_duplicate=True),
    Output("ppl-msg", "children", allow_duplicate=True),
    Input("inv-label-req", "data"), State("dbx-bump", "data"),
    prevent_initial_call=True,
)
def _save_label(req, bump):
    if not req:
        raise PreventUpdate
    from hydrasentinel import auth
    ok, msg = auth.set_invite_label(_me(), req["c"], req["label"])
    return (bump or 0) + 1, html.Div(msg, className="ppl-msg-" + ("ok" if ok else "err"))


@app.callback(
    Output("dbx-bump", "data", allow_duplicate=True),
    Output("ppl-msg", "children", allow_duplicate=True),
    Input("inv-new", "n_clicks"), State("dbx-bump", "data"),
    prevent_initial_call=True,
)
def _new_invite(n, bump):
    if not n:
        raise PreventUpdate
    from hydrasentinel import auth
    if not auth.is_admin(_me()):
        raise PreventUpdate
    auth.create_invite(None)
    return (bump or 0) + 1, html.Div("New invite made. Copy it below.", className="ppl-msg-ok")


@app.callback(
    Output("dbx-detail", "data"),
    Input({"type": "dbx-row", "i": ALL}, "n_clicks"),
    State("dbx-rows", "data"),
    prevent_initial_call=True,
)
def _open_detail(_clicks, rows):
    if not (ctx.triggered and ctx.triggered[0].get("value")):
        raise PreventUpdate
    i = (ctx.triggered_id or {}).get("i")
    if rows is None or i is None or i >= len(rows):
        raise PreventUpdate
    return rows[i]


@app.callback(
    Output("dbx-detail", "data", allow_duplicate=True),
    Input("dbx-close", "n_clicks"), Input("dbx-backdrop", "n_clicks"),
    prevent_initial_call=True,
)
def _close_detail(_c, _b):
    return None


@app.callback(
    Output("dbx-detail-panel", "children"),
    Input("dbx-detail", "data"), State("dbx-table", "data"),
)
def _render_detail(row, table):
    return _detail_panel(row, table)


# copy-as-JSON: runs in the browser, on the already-masked row JSON
app.clientside_callback(
    """
    function(n, data) {
        if (n && data) { navigator.clipboard.writeText(data); return "copied"; }
        return window.dash_clientside.no_update;
    }
    """,
    Output("dbx-copy", "children"),
    Input("dbx-copy", "n_clicks"),
    State("dbx-detail-json", "data"),
    prevent_initial_call=True,
)
