"""
SIEM/pages/live_feed.py — the terminal-style live session feed.

Two consumers, one renderer:
  * Summary embeds it as a small panel (30 lines)
  * the Live page renders it full-screen as a wallboard (`big=True`)

Both go through build_live_feed() so a feed line is formatted in exactly one
place, and both mount it under the same `live-feed-wrap` id so the single
refresh callback below drives either one unchanged. Only one page is mounted
at a time, so the shared id never collides.

The refresh has two triggers — the 1s interval as a fallback, and the
real-time WebSocket push from api_server.py (`ws-feed-store`). It refreshes
ONLY this block: re-rendering the whole page also tore down and rebuilt every
Plotly figure and the geo map, which is what made the dashboard feel sluggish.
"""
import pandas as pd
from dash import html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate

from SIEM.server import app
from SIEM.data import load_feed_rows, load_auth_log, _feed_cache

# Pages that mount a live feed. The refresh callback bails on anything else,
# so a tick/push never rebuilds a feed nobody is looking at.
FEED_PAGES = ("Live",)

PANEL_LINES, PANEL_FETCH = 30, None      # None -> data.py's FEED_ROWS default
BIG_LINES, BIG_FETCH = 100, 200


def _drop_feed_cache(instance):
    """Expire every cached feed for this sensor.

    load_feed_rows() keys its cache on (instance, limit), and the panel and the
    big screen ask for different limits — so clearing one key would leave the
    other view serving a pre-push snapshot."""
    key = instance or "all"
    for k in [k for k in _feed_cache if isinstance(k, tuple) and k[0] == key]:
        _feed_cache.pop(k, None)


def build_live_feed(sensor_filter="all", big=False):
    n_lines = BIG_LINES if big else PANEL_LINES
    rows = load_feed_rows(None if sensor_filter in (None, "all") else sensor_filter,
                          limit=BIG_FETCH if big else PANEL_FETCH)
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

    recent = df[df["timestamp"].notna()].sort_values("timestamp", ascending=False).head(n_lines)

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

    out = []
    for e in auth_entries[-(10 if big else 5):]:
        ts, ip = e.get("timestamp", ""), e.get("src_ip", "?")
        if e.get("auth_type") == "tcp_connect":
            out.append(line(ts, ip, kind="scan"))
        else:
            out.append(line(ts, ip, cmd=f"{e.get('username','?')}:{e.get('password','?')}", kind="login"))

    if out and not recent.empty:
        out.append(html.Div(html.Span("────────────────────────────────────────────",
                                      className="term-separator"), className="term-line"))

    # Commands are truncated so one absurd dropper one-liner can't push the
    # timestamp column off screen; the big view has room for more of it.
    cmd_width = 160 if big else 80
    for _, r in recent.iterrows():
        ts = r["timestamp"].strftime("%H:%M:%S") if pd.notna(r["timestamp"]) else "??:??:??"
        out.append(line(ts, r.get("src_ip", "?"), fi=int(r.get("fi_score", 0)),
                        agent=r.get("agent", "unknown"), cmd=str(r.get("cmd", ""))[:cmd_width]))

    if not out:
        return None

    newest = recent["timestamp"].max() if not recent.empty else None
    title = "hydrapot — live attack feed" if big else "hydrapot — live feed"
    header = ("▶ Live Attack Feed" +
              (f"   ·   last event {newest:%Y-%m-%d %H:%M:%S}" if pd.notna(newest) else "")
              ) if big else "▶ Live Session Feed"

    return html.Div(className="terminal-feed" + (" terminal-big" if big else ""), children=[
        html.Div(className="term-chrome", children=[
            html.Span(className="term-dot dot-r"), html.Span(className="term-dot dot-y"),
            html.Span(className="term-dot dot-g"),
            html.Span(title, className="term-chrome-title"),
        ]),
        html.Div(header, className="term-header"),
        html.Div(className="term-body", id="live-feed-body", children=out),
    ])


def build_live_page(sensor_filter="all"):
    """Full-screen wallboard: just the feed, nothing competing with it."""
    feed = build_live_feed(sensor_filter, big=True)
    return [
        html.Div(id="live-feed-wrap",
                 children=feed if feed is not None else
                 html.Div("Waiting for attacker activity…", className="empty-state")),
    ]


@app.callback(Output("live-feed-wrap", "children"),
              Input("interval", "n_intervals"),
              Input("ws-feed-store", "data"),
              State("page-store", "data"),
              State("sensor-filter-store", "data"),
              prevent_initial_call=True)
def _refresh_live_feed(_n, _ws_tick, page, sensor_filter):
    # Two triggers, one body: the 1s interval is a fallback net (in case the
    # WebSocket is down) -- ws-feed-store fires the moment api_server.py's
    # /ws/events actually sees a new row, which is the real push path. Either
    # way this re-fetches through build_live_feed(), so there is no second
    # rendering path to keep in sync.
    if page not in FEED_PAGES:
        raise PreventUpdate
    if ctx.triggered_id == "ws-feed-store":
        # load_feed_rows() has its own 4s TTL (FEED_TTL) so a plain interval
        # tick can reuse a slightly-stale cache without anyone noticing. A
        # WebSocket tick means a NEW row genuinely just landed -- serving a
        # cached snapshot from before that row existed would silently defeat
        # the whole point of pushing instead of polling.
        _drop_feed_cache(sensor_filter)
    return build_live_feed(sensor_filter or "all", big=(page == "Live"))
