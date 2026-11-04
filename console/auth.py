"""
console/auth.py — operator login for the dashboard.

WHY THIS EXISTS AT ALL. The dashboard shows every credential the honeypot ever
collected and ships a read-only SQL console over the capture database. Until
this file, `hp --dashboard` refused any non-loopback bind for exactly that
reason -- the only protection was "nothing is listening". That works for one
analyst on one laptop and stops being an answer the moment the console is
something a team opens.

NOT MODELLED ON api/auth.py, deliberately. That file is one shared secret,
off until a key exists, because its consumer is a SIEM or a script that can be
handed a header. This one's consumer is a browser, so it needs a form, a
session and a logout -- and it has no off switch, because "open" is not a state
a SQL console over harvested credentials should be able to reach.

NO WEB-BASED FIRST-RUN SETUP. Serving a "create the admin account" page would
hand the account to whoever reached the port first; on an internet-facing
sensor that is the wrong race to run. The account is created from the CLI
(`hp --dashboard-passwd`), because anyone who can run `hp` already owns the
box -- the CLI is an authenticated channel for free. Until an account exists
the dashboard serves one page saying so.

    hp --dashboard-passwd       create or rotate the operator account

STATE LIVES IN SQLITE, IN ITS OWN FILE. Two of the four things this module owes
-- invalidating a session on logout, and throttling login attempts across
uvicorn workers -- are impossible for a stateless signed cookie, because
workers are separate processes with separate memory. One small database solves
both.

That database is NOT core/storage.py's capture DB. The dashboard's Database
page runs `connect_readonly()` against that one, so operator sessions stored
there would be selectable from the very UI they gate. Sessions are also stored
as a SHA-256 of the token, never the token, so a leaked file yields nothing a
browser could present.
"""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time

from itsdangerous import BadSignature, URLSafeSerializer

from core.config_loader import load_config

# Repo root, not console/ -- a cwd-relative path would put the credential file
# wherever the dashboard happened to be started from, and a fresh empty one
# reads as "no account configured", i.e. a locked-out operator.
_HERE = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))
_CONFIG_PATH = os.path.join(_HERE, "config.yaml")

COOKIE = "hp_session"
CSRF_FIELD = "csrf_token"
LOGIN_PATH = "/_hp/login"
LOGOUT_PATH = "/_hp/logout"

# Env overrides for the two file paths. Containers mount secrets at a path they
# choose, and the tests need a temp dir; both beat editing config.yaml. Same
# precedence as every other secret in HydraPoT -- a real env var wins.
ENV_CREDENTIAL = "HYDRAPOT_DASHBOARD_CREDENTIAL"
ENV_SESSION_DB = "HYDRAPOT_DASHBOARD_SESSION_DB"


def cfg():
    """The dashboard.auth section. Read per call, not captured at import, so
    rotating the credential path or a timeout takes effect on the next request
    rather than at the next restart."""
    return load_config(_CONFIG_PATH).dashboard.auth


def _abs(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(_HERE, path)


def credential_path() -> str:
    return _abs(os.environ.get(ENV_CREDENTIAL) or cfg().credential_file)


def session_db_path() -> str:
    return _abs(os.environ.get(ENV_SESSION_DB) or cfg().session_db)


# ─── Password hashing ────────────────────────────────────────────────────────
# scrypt from hashlib: memory-hard, in the standard library since 3.6, and no
# new dependency to vet. bcrypt/argon2 would both be defensible and both would
# be a package.

_HASH_FORMAT = "scrypt${n}${r}${p}${salt}${hash}"


def hash_password(password: str, *, n=None, r=None, p=None,
                  salt: bytes = None) -> str:
    """A self-describing hash string: the parameters travel with it.

    Storing n/r/p in the hash rather than reading them from config at verify
    time is what lets the cost be raised later without locking out the account
    that was hashed under the old cost.
    """
    c = cfg()
    n = int(n or c.scrypt_n)
    r = int(r or c.scrypt_r)
    p = int(p or c.scrypt_p)
    salt = salt or secrets.token_bytes(16)
    # maxmem must be stated explicitly: OpenSSL's default is 32MB and n=16384,
    # r=8 needs ~16MB, so a raised cost would otherwise fail at the library
    # rather than at a parameter check.
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            maxmem=256 * 1024 * 1024, dklen=32)
    return _HASH_FORMAT.format(
        n=n, r=r, p=p,
        salt=base64.b64encode(salt).decode(),
        hash=base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    """Constant-time compare against a hash produced above."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                n=int(n), r=int(r), p=int(p),
                                maxmem=256 * 1024 * 1024,
                                dklen=len(expected))
    except Exception:
        # A malformed or truncated credential file must read as "wrong
        # password", never as "no password required".
        return False
    return hmac.compare_digest(digest, expected)


# ─── Credential file ─────────────────────────────────────────────────────────

def load_credential() -> dict:
    """The stored account, or {} when none exists."""
    try:
        with open(credential_path(), encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) and data.get("username") else {}


def configured() -> bool:
    """True once an operator account exists. The gate is unconditional; this
    only distinguishes "sign in" from "no account yet, run the CLI"."""
    return bool(load_credential())


def write_credential(username: str, password: str, *, rotate: bool = False) -> str:
    """Create the operator account atomically. Returns the path written.

    Atomic in both senses that matter:

    - the file is never observed half-written, because it is written to a
      temp file in the same directory, fsync'd, and then os.replace()d, which
      is atomic within a filesystem;
    - two concurrent creations cannot both believe they won, because the final
      name is claimed with os.link(), which fails if it already exists. A
      plain "exists? then write" has a window between the two.

    rotate=True is the deliberate overwrite, i.e. changing a known password.

    Mode 0600 before any content is written -- not chmod'd afterwards, which
    would leave the hash briefly world-readable.
    """
    path = credential_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    payload = {
        "username": username,
        "password_hash": hash_password(password),
        # The cookie-signing key. Generated here, with the account, so sessions
        # survive a restart and are shared by every uvicorn worker -- a
        # per-process random key would log everyone out on reload and make
        # workers reject each other's cookies.
        "session_secret": secrets.token_urlsafe(32),
        "created": int(time.time()),
    }
    blob = json.dumps(payload, indent=2).encode("utf-8")

    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        if rotate:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise FileExistsError(
                    f"an operator account already exists at {path}; "
                    f"pass rotate=True to change the password") from None
            os.unlink(tmp)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    # Every existing session was signed with the OLD secret and authenticated
    # the OLD password. A password change must not leave them usable.
    _reset_store()
    return path


def _signing_secret() -> bytes:
    secret = load_credential().get("session_secret")
    if not secret:
        raise RuntimeError("no operator account: nothing to sign sessions with")
    return secret.encode("utf-8")


# ─── Session + throttle store ────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created    REAL NOT NULL,
    last_seen  REAL NOT NULL,
    src_ip     TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    ts     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(src_ip, ts);
"""


def _connect() -> sqlite3.Connection:
    """A WAL-mode connection, fresh per call -- sqlite3 connections are not
    thread-safe and uvicorn dispatches the mounted WSGI app across a pool.

    WAL is what makes the cross-worker story work: several processes reading
    and writing this file concurrently is the normal case, not the exception.
    """
    path = session_db_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # 0600 from creation. sqlite3.connect() would make it 0644, and this file
    # holds session material.
    if not os.path.exists(path):
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            pass
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    return conn


@contextlib.contextmanager
def _store():
    """A committed, CLOSED connection.

    `with sqlite3.connect(...)` commits but does not close, so using the
    connection itself as the context manager leaks a file descriptor per
    request -- which a dashboard polling on an interval reaches surprisingly
    quickly.
    """
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _reset_store():
    """Drop every session and every recorded attempt."""
    with _store() as conn:
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM login_attempts")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def open_session(username: str, src_ip: str = "") -> str:
    """Record a new session and return the signed cookie value."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _store() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, username, created, last_seen, "
            "src_ip) VALUES (?,?,?,?,?)",
            (_token_hash(token), username, now, now, src_ip))
    # Signed as well as stored. The signature is what stops a flood of
    # guessed cookies from reaching SQLite at all -- a forgery is rejected on
    # arithmetic, before any I/O.
    return URLSafeSerializer(_signing_secret(), salt="hp-session").dumps(token)


def read_session(cookie_value: str) -> dict:
    """Validate a cookie. Returns the session row as a dict, or {}.

    Checks, in order: the account exists, the signature holds, the session is
    on record (so logout really revokes), and neither the absolute lifetime
    nor the idle timeout has passed. Any failure is indistinguishable to the
    caller -- there is no "expired" vs "forged" distinction to leak.
    """
    if not cookie_value or not configured():
        return {}
    try:
        token = URLSafeSerializer(_signing_secret(),
                                  salt="hp-session").loads(cookie_value)
    except (BadSignature, RuntimeError):
        return {}

    c = cfg()
    now = time.time()
    hard = float(c.session_lifetime_minutes) * 60
    idle = float(c.session_idle_minutes) * 60
    th = _token_hash(token)
    with _store() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token_hash=?", (th,)).fetchone()
        if row is None:
            return {}
        if now - row["created"] > hard or now - row["last_seen"] > idle:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
            return {}
        conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?",
                     (now, th))
        return dict(row)


def close_session(cookie_value: str) -> bool:
    """Revoke one session. True if a session was actually removed.

    This is the reason sessions are stored at all: a signed cookie alone
    cannot be withdrawn, so "log out" would mean "please stop using it".
    """
    if not cookie_value:
        return False
    try:
        token = URLSafeSerializer(_signing_secret(),
                                  salt="hp-session").loads(cookie_value)
    except (BadSignature, RuntimeError):
        return False
    with _store() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE token_hash=?",
                           (_token_hash(token),))
        return cur.rowcount > 0


def prune_sessions() -> int:
    """Delete sessions past either timeout. Returns how many went."""
    c = cfg()
    now = time.time()
    with _store() as conn:
        cur = conn.execute(
            "DELETE FROM sessions WHERE ? - created > ? OR ? - last_seen > ?",
            (now, float(c.session_lifetime_minutes) * 60,
             now, float(c.session_idle_minutes) * 60))
        return cur.rowcount


# ─── CSRF ────────────────────────────────────────────────────────────────────
# Derived from the session token, not stored. An HMAC over the token means any
# request that can prove it holds the session can also produce the right token,
# while a cross-site attacker -- who can cause a request to be SENT with the
# cookie but cannot READ the cookie -- cannot.
#
# SameSite=Lax on the cookie already blocks the cross-site POST in a current
# browser. This is the second lock, for the browser that doesn't honour it and
# for the same-site-but-untrusted case.

def csrf_token(cookie_value: str) -> str:
    """The CSRF token that pairs with this cookie. "" when there is none."""
    if not cookie_value:
        return ""
    try:
        return hmac.new(_signing_secret(), b"csrf:" + cookie_value.encode(),
                        hashlib.sha256).hexdigest()
    except RuntimeError:
        return ""


def csrf_ok(cookie_value: str, presented: str) -> bool:
    expected = csrf_token(cookie_value)
    if not expected or not presented:
        return False
    return hmac.compare_digest(expected, presented)


# The login form has no session yet, so it cannot use the token above. It gets
# a double-submit pair instead: one random value placed in BOTH a cookie and a
# hidden field, which must match on POST. An attacker can forge the field but
# cannot set a cookie on this origin, so they cannot make the two agree.
CSRF_COOKIE = "hp_csrf"


def new_form_token() -> str:
    return secrets.token_urlsafe(32)


def form_token_ok(cookie_value: str, presented: str) -> bool:
    if not cookie_value or not presented:
        return False
    return hmac.compare_digest(cookie_value, presented)


# ─── Login throttle ──────────────────────────────────────────────────────────
# In SQLite rather than a module-level dict, because uvicorn workers are
# separate processes: an in-memory counter divides the real limit by the worker
# count, so `--workers 4` with max_attempts=5 would allow 20.

def attempts_remaining(src_ip: str) -> int:
    """How many failures this IP may still make before the lockout."""
    c = cfg()
    cutoff = time.time() - float(c.lockout_minutes) * 60
    with _store() as conn:
        conn.execute("DELETE FROM login_attempts WHERE ts < ?", (cutoff,))
        used = conn.execute(
            "SELECT COUNT(*) n FROM login_attempts WHERE src_ip=? AND ts>=?",
            (src_ip or "", cutoff)).fetchone()["n"]
    return max(0, int(c.max_attempts) - int(used))


def locked_out(src_ip: str) -> bool:
    return attempts_remaining(src_ip) <= 0


def record_failure(src_ip: str):
    with _store() as conn:
        conn.execute("INSERT INTO login_attempts (src_ip, ts) VALUES (?,?)",
                     (src_ip or "", time.time()))


def clear_failures(src_ip: str):
    """Called on a successful login, so a typo earlier in the day does not
    count toward a lockout hours later."""
    with _store() as conn:
        conn.execute("DELETE FROM login_attempts WHERE src_ip=?",
                     (src_ip or "",))


# ─── Which paths skip the session gate ───────────────────────────────────────

def _open_patterns():
    """Compiled once per call from config -- the list is four entries and this
    is not the hot path, and reading it live means a deployment can open a
    path without a restart."""
    return [re.compile(p) for p in cfg().open_paths]


def is_open_path(path: str) -> bool:
    """True for paths served without a session cookie.

    Regex, from config, rather than a hardcoded prefix list: `/assets/` has to
    stay open so the login page can load the logo, and a prefix test would
    silently open anything that happened to share a prefix with it.
    """
    return any(p.search(path or "") for p in _open_patterns())
