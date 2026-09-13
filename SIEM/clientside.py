"""
SIEM/clientside.py — all app.clientside_callback JS blocks: sidebar toggle,
live-feed scroll preservation, and the real-time WebSocket push.

Kept as one module since these are small, self-contained JS snippets with no
Python logic of their own — splitting them further would just scatter three
short blocks across three files for no benefit.
"""
from dash import Input, Output, State

from SIEM.server import app

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

# ── Real-time push (clientside) ──────────────────────────────────────────────
# Opens api_server.py's /ws/events once per page load (guarded the same way
# the sidebar toggle guards its own listener above -- a flag on window, not
# reliance on the callback firing exactly once). Every message just bumps
# ws-feed-store's counter; it does NOT carry the row into the DOM itself --
# _refresh_live_feed already knows how to fetch+render a feed
# (build_live_feed()), so this only adds a second, faster trigger for that
# same function rather than a second place that formats a row.
#
# ws:// not wss:// when the page itself is http:, and vice versa -- matches
# whatever host:port/scheme served this page (including over an SSH tunnel),
# so nothing here hardcodes host or port.
app.clientside_callback(
    """
    function(_n) {
        if (!window.__hpWsOpened) {
            window.__hpWsOpened = true;
            const proto = (location.protocol === "https:") ? "wss:" : "ws:";
            function connect() {
                const ws = new WebSocket(proto + "//" + location.host + "/ws/events");
                ws.onmessage = function() {
                    window.dash_clientside.set_props(
                        "ws-feed-store", {data: (window.__hpWsTick || 0) + 1});
                    window.__hpWsTick = (window.__hpWsTick || 0) + 1;
                };
                // Server restart / network blip -- reconnect rather than
                // silently falling back to the interval poll forever.
                ws.onclose = function() { setTimeout(connect, 2000); };
            }
            connect();
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output("ws-setup-sink", "children"),
    Input("interval", "n_intervals"),
)
