"""
cli/dashboard_tls.py -- the HTTPS front for the dashboard, run by `hp`.

The dashboard login and its SQL console must never cross a network in clear,
so plain HTTP is not something an operator can pick. The app listens on
loopback only and the Caddy that `hp --dashboard` starts is the only way in.
Scheme and bind address are not settings; the port and an organisation's own
certificate are (config.yaml: dashboard.https_port / tls_cert / tls_key).
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import time

# Where the app itself listens. A constant on purpose: loopback only.
INTERNAL_HOST = "127.0.0.1"
INTERNAL_PORT = 8050
_UNSAFE = re.compile(r'[\s{}"\'`$\\]')   # nothing that could escape a Caddyfile line


def in_container() -> bool:
    """True only inside the compose `dashboard` service, where a separate proxy
    container terminates TLS and this process serves its internal port."""
    return os.path.exists("/.dockerenv") and os.environ.get("SERVICE") == "dashboard"


def find_caddy(hp_dir: str):
    """`caddy` on PATH, else the copy the project keeps in data/bin/."""
    for candidate in (shutil.which("caddy"), os.path.join(hp_dir, "data", "bin", "caddy")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _paths(hp_dir: str) -> dict:
    data = os.path.join(hp_dir, "data")
    return {"pid": os.path.join(data, "caddy.pid"), "log": os.path.join(data, "caddy.log"),
            "dir": os.path.join(data, "caddy"),
            "file": os.path.join(data, "caddy", "Caddyfile")}


def caddyfile(https_port: int, cert: str = "", key: str = "") -> str:
    if bool(cert) != bool(key):
        raise ValueError("dashboard.tls_cert and dashboard.tls_key go together")
    if not 1 <= int(https_port) <= 65535:
        raise ValueError(f"dashboard.https_port {https_port!r} is not a port")
    if cert:
        for path in (cert, key):
            if _UNSAFE.search(path) or not os.path.isfile(path):
                raise ValueError(f"TLS file not found or has unsafe characters: {path}")
        tls = f"tls {cert} {key}"
    else:
        tls = "tls internal"          # Caddy's own local CA, no outside calls
    port = int(https_port)
    return f"""{{
	admin off
	skip_install_trust
	auto_https disable_redirects
}}

https://localhost:{port}, https://{INTERNAL_HOST}:{port} {{
	bind {INTERNAL_HOST}
	{tls}
	reverse_proxy {INTERNAL_HOST}:{INTERNAL_PORT}
	encode gzip
	header Strict-Transport-Security "max-age=31536000"
}}
"""


def running_pid(hp_dir: str):
    """PID of our Caddy, or None. Checks the name so a recycled PID is never
    mistaken for it (and later terminated)."""
    import psutil
    try:
        pid = int(open(_paths(hp_dir)["pid"]).read().strip())
        if psutil.pid_exists(pid) and psutil.Process(pid).name().lower().startswith("caddy"):
            return pid
    except Exception:
        pass
    return None


def start(hp_dir: str, caddy: str, https_port: int, cert: str = "", key: str = "") -> int:
    """Start Caddy in front of the dashboard; return its pid, raise on failure."""
    existing = running_pid(hp_dir)
    if existing:
        return existing
    p = _paths(hp_dir)
    os.makedirs(p["dir"], exist_ok=True)
    with open(p["file"], "w") as fh:
        fh.write(caddyfile(https_port, cert, key))
    # Keep Caddy's CA and state inside the project, not in the user's home
    env = dict(os.environ, XDG_DATA_HOME=os.path.join(p["dir"], "data"),
               XDG_CONFIG_HOME=os.path.join(p["dir"], "config"))
    log = open(p["log"], "ab", buffering=0)
    detach = ({"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}
              if sys.platform == "win32" else {"start_new_session": True})
    proc = subprocess.Popen([caddy, "run", "--config", p["file"], "--adapter", "caddyfile"],
                            stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                            cwd=hp_dir, env=env, **detach)
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex((INTERNAL_HOST, int(https_port))) == 0:
                with open(p["pid"], "w") as fh:
                    fh.write(str(proc.pid))
                return proc.pid
        time.sleep(0.2)
    try:
        tail = open(p["log"], "rb").read()[-600:].decode("utf-8", "replace").strip()
    except OSError:
        tail = "(no log)"
    try:
        proc.kill()
    except OSError:
        pass
    raise RuntimeError(f"Caddy did not start:\n{tail}")


def stop(hp_dir: str):
    """Stop our Caddy; return its pid, or None if it was not running."""
    import psutil
    pid = running_pid(hp_dir)
    if pid:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
    try:
        os.remove(_paths(hp_dir)["pid"])
    except OSError:
        pass
    return pid
