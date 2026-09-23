"""
api_server.py — FastAPI front door for HydraPoT's dashboard.

Replaces Flask's dev server as the thing that actually listens on the
network. Dash itself is completely untouched -- dash_app.server is still
the exact same Flask app Dash always built; it's mounted here via a2wsgi
rather than served directly. Every existing dashboard.py callback keeps
working exactly as before, no callback changes, no async rewrite.

What this file serves:
  /api/v1/*   the versioned REST contract -- see api/v1/, which owns it.
              Nothing under /api is unversioned any more; /api/<anything else>
              gets a JSON 404, or a 410 naming its replacement.
  /ws/events  WebSocket, poll-and-push (see the note above ws_events for why
              polling, not a live main.py hook)
  /docs       Swagger, re-themed to the dashboard's palette
  /           the existing Dash app, unchanged, mounted last so it doesn't
              swallow /api or /ws first

Run via `hp dashboard` (hp.py's _serve_dashboard calls uvicorn on this file)
or directly for testing:
    uvicorn api_server:api --host 127.0.0.1 --port 8050
"""
import asyncio
import re

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from a2wsgi import WSGIMiddleware

from SIEM import app as dash_app
from SIEM.theme import INK, PAPER, Y_400, Y_500
import storage

# docs_url=None disables FastAPI's default (blue) /docs route so the
# hand-themed one below can take over the same path -- /openapi.json and
# /redoc are untouched.
api = FastAPI(title="HydraPoT API", docs_url=None)


@api.on_event("startup")
def _warm():
    """Fill the dashboard's heavy caches on a daemon thread at boot, so the
    first click on a sensor is not the one that pays for it."""
    from SIEM.data import warm_caches
    warm_caches(background=True)

# Swagger UI ships blue by default; this overrides just the color-bearing
# rules with HydraPoT's real palette (SIEM/theme.py), not a copy of it.
_SWAGGER_THEME_CSS = f"""
<style>
  body {{ background: {PAPER}; }}
  .swagger-ui .topbar {{ background-color: {INK}; }}
  .swagger-ui .info .title, .swagger-ui .info a {{ color: {INK}; }}
  .swagger-ui .btn.authorize {{ color: {Y_500}; border-color: {Y_500}; }}
  .swagger-ui .btn.authorize svg {{ fill: {Y_500}; }}
  .swagger-ui .btn.execute {{ background-color: {Y_400}; border-color: {Y_400}; color: {INK}; }}
  .swagger-ui select {{ border-color: {Y_400}; }}
  .swagger-ui .opblock-summary-method {{ background: {Y_400} !important; color: {INK} !important; }}
  .swagger-ui .opblock.opblock-get {{ background: rgba(245,178,27,0.08); border-color: {Y_400}; }}
  .swagger-ui .opblock.opblock-get .opblock-summary {{ border-color: {Y_400}; }}
</style>
"""


@api.get("/docs", include_in_schema=False)
async def hydrapot_docs():
    resp = get_swagger_ui_html(openapi_url=api.openapi_url, title=f"{api.title} - Docs")
    html = resp.body.decode("utf-8").replace("</head>", _SWAGGER_THEME_CSS + "</head>")
    return HTMLResponse(html)


# ── REST ─────────────────────────────────────────────────────────────────
# Five unversioned routes used to sit here -- /api/stats, /api/sessions,
# /api/sessions/{id}, /api/windows, /api/feed. Removed: nothing referenced
# them (the Dash dashboard calls SIEM/data.py directly, not over HTTP) and
# /api/v1 answers all five, with a version contract they never had:
#
#   /api/stats            -> /api/v1/health
#   /api/sessions         -> /api/v1/sessions
#   /api/sessions/{id}    -> /api/v1/sessions/{id}
#   /api/windows          -> /api/v1/overview  (window + timeline)
#   /api/feed             -> /ws/events, the live push path that replaced it
#
# Normalized export used to sit here too, as /api/ocsf/events and
# /api/ocsf/findings. Moved to /api/v1/export -- ONE route, `?class=` picking
# which records and `?format=` picking the wire format. Two routes covered two
# of the three classes normalize.py produces; Authentication (3002) had none,
# because adding a class meant adding a route. It is a filter, not a resource.
#
# Named /export rather than /ocsf: OCSF is the canonical shape inside, but the
# route also emits CEF and ECS, and naming it after one of its four formats
# made the other three look like they lived somewhere else.

# ── WebSocket ────────────────────────────────────────────────────────────
# main.py (the live honeypot) and this process share only the SQLite DB --
# no pub/sub, no IPC, verified nothing else exists between them. So "push"
# here means: poll storage.query_recent() on a short interval and forward
# only rows newer than the last one already sent, keyed by the DB's
# autoincrement `id` (present in every row -- query_recent does SELECT *).
#
# asyncio.to_thread is required for the storage call, unlike the REST
# routes above: this IS an async def running on the event loop, so a direct
# blocking sqlite3 call here would stall every other connection this
# process is serving, not just this one client.
POLL_INTERVAL_S = 1.0
POLL_BATCH = 50   # generous vs. how many commands land in one poll interval


@api.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    last_id = None
    try:
        while True:
            rows = await asyncio.to_thread(storage.query_recent, POLL_BATCH)
            rows = list(reversed(rows))   # query_recent is newest-first; send oldest-first
            if last_id is not None:
                rows = [r for r in rows if r.get("id", 0) > last_id]
            for r in rows:
                await websocket.send_json(r)
            if rows:
                last_id = rows[-1].get("id", last_id)
            await asyncio.sleep(POLL_INTERVAL_S)
    except WebSocketDisconnect:
        pass


# ── REST API v1 ──────────────────────────────────────────────────────────
# The versioned, public contract. Registered BEFORE Dash so /api/v1/* resolves
# here rather than falling through to the dashboard's catch-all. A future v2
# mounts alongside it without touching either.
from api.v1 import router as v1_router
api.include_router(v1_router)


# Endpoints removed when v1 took over, and what answers them now. Kept as data
# so the 410 below can name the replacement instead of just refusing.
_RETIRED = {
    "/api/stats":     "/api/v1/health",
    "/api/sessions":  "/api/v1/sessions",
    "/api/windows":   "/api/v1/overview",
    "/api/feed":      "/ws/events",
    "/api/ocsf/events":   "/api/v1/export?class=process",
    "/api/ocsf/findings": "/api/v1/export?class=finding",
    # Renamed: it serves CEF and ECS too, so naming it after one format
    # pointed the other three somewhere that did not exist.
    "/api/v1/ocsf":       "/api/v1/export",
    # Counted the same categories /overview already reports, one HTTP call
    # further away.
    "/api/v1/threats/categories": "/api/v1/overview",
}

# The /investigations/* namespace. Each one was a second URL for a thing that
# already had one, and the resource endpoint now serves the full picture --
# measured at ~1ms more than the metadata alone, because the expensive work is
# per-window and cached. Two doors into one room, removed.
_RETIRED_PATTERNS = [
    (re.compile(r"^/api/v1/alerts/(?P<id>.+)/related$"),
     "/api/v1/alerts/{id}"),
    (re.compile(r"^/api/v1/sessions/(?P<id>[^/]+)/related$"),
     "/api/v1/sessions/{id}"),
    (re.compile(r"^/api/v1/investigations/session/(?P<id>.+)$"),
     "/api/v1/sessions/{id}"),
    (re.compile(r"^/api/v1/investigations/alert/(?P<id>.+)$"),
     "/api/v1/alerts/{id}"),
    (re.compile(r"^/api/v1/investigations/ioc/(?P<id>.+)$"),
     "/api/v1/threats/iocs/{id}"),
    (re.compile(r"^/api/v1/investigations/ip/(?P<id>.+)$"),
     "/api/v1/sources/{id}"),
]


def _replacement_for(path: str):
    """The path a retired endpoint moved to, or None if it never existed.

    Kept as data rather than dead routes: a 410 naming where to go is the whole
    difference between "we moved this" and "your client is broken".
    """
    for retired, replacement in _RETIRED.items():
        if path == retired or path.startswith(retired + "/"):
            return retired, replacement
    for pattern, template in _RETIRED_PATTERNS:
        match = pattern.match(path)
        if match:
            return path, template.format(**match.groupdict())
    return None


@api.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
               include_in_schema=False)
def api_fallback(rest: str):
    """Anything under /api/ that no route above claimed.

    Without this, Dash's mount catches it and returns the dashboard's HTML with
    200 -- so a typo'd path or a retired endpoint looks like success to a client
    that then tries to parse HTML as JSON. Registered after every real route and
    before the mount, so it only ever sees genuine misses.
    """
    path = "/api/" + rest
    moved = _replacement_for(path)
    if moved:
        retired, replacement = moved
        return JSONResponse(status_code=410, content={
            "detail": f"{retired} was removed; use {replacement}",
            "replacement": replacement,
        })
    return JSONResponse(status_code=404,
                        content={"detail": f"no such endpoint: {path}",
                                 "docs": "/docs"})


# ── Mount Dash last -- catches everything /api and /ws don't ─────────────
api.mount("/", WSGIMiddleware(dash_app.server))
