"""
api/api_server.py — FastAPI front door for HydraPoT's dashboard.

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

Run via `hp --dashboard` (hp.py's _serve_dashboard calls uvicorn on this file)
or directly for testing:
    uvicorn api.api_server:api --host 127.0.0.1 --port 8050
"""
import asyncio
import hmac
import re
from urllib.parse import quote

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               Response)
from a2wsgi import WSGIMiddleware

from console import app as dash_app
from console import auth as dash_auth
from console import login_page
from console.theme import INK, PAPER, Y_400, Y_500
from core import storage

# docs_url=None disables FastAPI's default (blue) /docs route so the
# hand-themed one below can take over the same path -- /openapi.json and
# /redoc are untouched.
api = FastAPI(title="HydraPoT API", docs_url=None)


@api.on_event("startup")
def _warm():
    """Fill the dashboard's heavy caches on a daemon thread at boot, so the
    first click on a sensor is not the one that pays for it."""
    from console.data import warm_caches
    warm_caches(background=True)

# Swagger UI ships blue by default; this overrides just the color-bearing
# rules with HydraPoT's real palette (console/theme.py), not a copy of it.
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
# them (the Dash dashboard calls console/data.py directly, not over HTTP) and
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
    # Gated HERE rather than in the session middleware above, because HTTP
    # middleware never runs for a WebSocket scope -- it would have looked
    # protected from the outside while streaming every command to anyone who
    # opened a socket. Closed before accept(), so an unauthenticated client
    # gets a handshake failure and never a single frame.
    if not dash_auth.read_session(websocket.cookies.get(dash_auth.COOKIE, "")):
        await websocket.close(code=1008)      # 1008 = policy violation
        return
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


# ── Operator login ───────────────────────────────────────────────────────
# ONE gate for the whole operator surface: the Dash UI, /docs, and the
# Database page's SQL console. Attached as middleware rather than as a
# dependency per route, for the same reason api/v1 attaches its key check to
# the router rather than to each endpoint -- a page added later is protected
# by existing, not by someone remembering.
#
# Three things are exempt, and only these: the login/logout routes, /assets/*
# so the login page can load its own logo, and /api/v1/* which carries its own
# X-API-Key gate (api/auth.py) so a SIEM never needs a browser cookie. The
# list is regexes in config.yaml -- see DashboardAuthCfg.open_paths.


def _safe_next(raw: str) -> str:
    """A path to return to after login, or "/" if it isn't one.

    Only same-origin, absolute PATHS survive. Without this the `next`
    parameter is an open redirect: a link to our own trusted login page could
    bounce the operator to an attacker's copy of it the moment they
    authenticate. "//evil.test" is rejected too -- browsers read a
    protocol-relative URL as another host.
    """
    value = (raw or "").strip()
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or "\n" in value or "\r" in value:
        return "/"
    return value


def _client_ip(request: Request) -> str:
    """The address the throttle counts against.

    request.client.host, which uvicorn rewrites from X-Forwarded-For only when
    started with --forwarded-allow-ips. That is the right default: trusting the
    header unconditionally would let any client pick its own throttle bucket by
    sending a different one each try.
    """
    return (request.client.host if request.client else "") or ""


def _secure_cookies(request: Request) -> bool:
    """Whether to mark cookies Secure.

    Not hardcoded True: the documented loopback deployment is plain HTTP over
    an SSH tunnel, and a Secure cookie is simply never sent there, which
    presents as "login succeeds, then bounces straight back to the form".
    """
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    return (proto or request.url.scheme) == "https"


def _set_session_cookie(response: Response, value: str, request: Request):
    response.set_cookie(
        dash_auth.COOKIE, value,
        max_age=int(dash_auth.cfg().session_lifetime_minutes) * 60,
        httponly=True,            # a stolen XSS cannot read it
        samesite="lax",           # not sent on a cross-site POST: CSRF lock #1
        secure=_secure_cookies(request),
        path="/")


def _wants_html(request: Request) -> bool:
    """A browser navigation, as opposed to Dash's own fetch() calls.

    The distinction decides 302-to-login versus 401: a redirect is what the
    operator wants in the address bar, and JSON is the only thing Dash's
    callback endpoint can do anything sensible with.
    """
    return "text/html" in request.headers.get("accept", "")


@api.middleware("http")
async def require_operator_session(request: Request, call_next):
    path = request.url.path

    # No account yet: serve one page saying how to make one, and nothing else.
    # /api/v1 keeps working -- it has an independent gate and an existing SIEM
    # must not break because the dashboard has not been set up yet.
    if not dash_auth.configured():
        # Same regex list as below, not a second hardcoded copy: an exempt
        # path that stopped being exempt before setup would mean the API
        # breaks exactly until someone creates a dashboard account.
        if dash_auth.is_open_path(path):
            return await call_next(request)
        return HTMLResponse(login_page.no_account(), status_code=503)

    if dash_auth.is_open_path(path):
        return await call_next(request)

    if dash_auth.read_session(request.cookies.get(dash_auth.COOKIE, "")):
        return await call_next(request)

    if _wants_html(request):
        target = f"{dash_auth.LOGIN_PATH}?next={quote(path, safe='/')}"
        return RedirectResponse(target, status_code=302)
    return JSONResponse(status_code=401,
                        content={"detail": "operator session required",
                                 "login": dash_auth.LOGIN_PATH})


@api.get(dash_auth.LOGIN_PATH, include_in_schema=False)
async def login_form(request: Request, next: str = "/"):
    if not dash_auth.configured():
        return HTMLResponse(login_page.no_account(), status_code=503)
    # Already signed in: nothing to ask for.
    if dash_auth.read_session(request.cookies.get(dash_auth.COOKIE, "")):
        return RedirectResponse(_safe_next(next), status_code=302)

    cfg = dash_auth.cfg()
    if dash_auth.locked_out(_client_ip(request)):
        return HTMLResponse(login_page.locked(int(cfg.lockout_minutes)),
                            status_code=429)

    # The form has no session yet, so its CSRF protection is a double submit:
    # the same random value in a cookie and in a hidden field, which must
    # match on POST. An attacker can forge the field but cannot set a cookie
    # on this origin, so they cannot make the two agree.
    token = dash_auth.new_form_token()
    response = HTMLResponse(login_page.login(token, next_path=_safe_next(next)))
    response.set_cookie(dash_auth.CSRF_COOKIE, token, httponly=True,
                        samesite="lax", secure=_secure_cookies(request),
                        max_age=900, path="/")
    return response


@api.post(dash_auth.LOGIN_PATH, include_in_schema=False)
async def login_submit(request: Request,
                       username: str = Form(""),
                       password: str = Form(""),
                       csrf_token: str = Form(""),
                       next: str = Form("/")):
    if not dash_auth.configured():
        return HTMLResponse(login_page.no_account(), status_code=503)

    cfg = dash_auth.cfg()
    ip = _client_ip(request)
    target = _safe_next(next)

    # Throttle first. Checked before the password so a locked-out address
    # cannot keep testing guesses, and before the scrypt call so it cannot be
    # used to burn ~100ms of CPU per request either.
    if dash_auth.locked_out(ip):
        return HTMLResponse(login_page.locked(int(cfg.lockout_minutes)),
                            status_code=429)

    if not dash_auth.form_token_ok(request.cookies.get(dash_auth.CSRF_COOKIE, ""),
                                   csrf_token):
        # Not counted as a failed password: a missing token is usually a stale
        # form or a blocked cookie, not an attacker.
        return HTMLResponse(
            login_page.login(dash_auth.new_form_token(), next_path=target,
                             error="This form expired. Please try again."),
            status_code=400)

    cred = dash_auth.load_credential()
    # Both checks always run. Returning early on an unknown username would
    # make the response time a username oracle, since only the password path
    # pays for scrypt.
    name_ok = hmac.compare_digest(username or "", cred.get("username", ""))
    pass_ok = dash_auth.verify_password(password or "",
                                        cred.get("password_hash", ""))
    if not (name_ok and pass_ok):
        dash_auth.record_failure(ip)
        left = dash_auth.attempts_remaining(ip)
        if left <= 0:
            return HTMLResponse(login_page.locked(int(cfg.lockout_minutes)),
                                status_code=429)
        token = dash_auth.new_form_token()
        response = HTMLResponse(
            login_page.login(token, next_path=target,
                             error="Incorrect operator name or password.",
                             attempts_left=left),
            status_code=401)
        response.set_cookie(dash_auth.CSRF_COOKIE, token, httponly=True,
                            samesite="lax", secure=_secure_cookies(request),
                            max_age=900, path="/")
        return response

    dash_auth.clear_failures(ip)
    dash_auth.prune_sessions()
    cookie = dash_auth.open_session(cred["username"], ip)
    response = RedirectResponse(target, status_code=302)
    _set_session_cookie(response, cookie, request)
    response.delete_cookie(dash_auth.CSRF_COOKIE, path="/")
    return response


@api.get(dash_auth.LOGOUT_PATH, include_in_schema=False)
async def logout_confirm(request: Request):
    """GET only confirms. The actual revocation is the POST below, so that a
    third-party page cannot sign the operator out with an <img> tag."""
    session = dash_auth.read_session(request.cookies.get(dash_auth.COOKIE, ""))
    if not session:
        return RedirectResponse(dash_auth.LOGIN_PATH, status_code=302)
    cookie = request.cookies.get(dash_auth.COOKIE, "")
    return HTMLResponse(login_page.confirm_logout(
        dash_auth.csrf_token(cookie), session.get("username", "")))


@api.post(dash_auth.LOGOUT_PATH, include_in_schema=False)
async def logout_submit(request: Request, csrf_token: str = Form("")):
    cookie = request.cookies.get(dash_auth.COOKIE, "")
    if not dash_auth.csrf_ok(cookie, csrf_token):
        return RedirectResponse(dash_auth.LOGOUT_PATH, status_code=302)
    # Deleted from the store, not just from the browser. Clearing the cookie
    # alone would leave a copied value working until it expired on its own.
    dash_auth.close_session(cookie)
    response = HTMLResponse(login_page.signed_out())
    response.delete_cookie(dash_auth.COOKIE, path="/")
    return response


# ── Mount Dash last -- catches everything /api and /ws don't ─────────────
api.mount("/", WSGIMiddleware(dash_app.server))
