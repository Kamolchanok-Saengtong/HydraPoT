"""
cli/hp.py — HydraPoT CLI entry point.

Registered as `hp` command via pyproject.toml.

ONE COMMAND, FLAGS ONLY -- there are no subcommands. Every action is a `--`
flag on `hp` itself, and exactly one action flag may be given per invocation.

Usage:
    hp --init             # run setup wizard
    hp --run              # start the honeypot
    hp --dashboard        # open the dashboard
    hp --dashboard-stop   # stop a detached dashboard
    hp --config           # show the active configuration
    hp --version          # show version

    hp --dashboard --port 8050 --host 127.0.0.1
    hp --run --host 0.0.0.0 --port 2222

--host and --port are SHARED by --run and --dashboard, so neither can carry
its own default at the parser level. They default to None and each action
fills in its own: --run falls back to config.yaml, --dashboard to
127.0.0.1:8050.
"""

import os
import sys
import click

# Ensure the project root is importable even when `hp` runs from an editable
# install's entry point (whose finder only exposes packages declared in
# pyproject.toml). Lets local packages like threat_intel/ import without a
# reinstall after being added.
# Repo root, not cli/ -- this is what gets put on sys.path.
_ROOT = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False

try:
    from importlib.metadata import version as _pkg_version
    VERSION = _pkg_version("HydraPoT")
except Exception:
    VERSION = "1.0.0"      # not installed yet; keep in step with pyproject

_HERE = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    with open(os.path.join(_HERE, "license"), encoding="utf-8") as _f:
        LICENSE_TEXT = _f.read().strip()
except FileNotFoundError:
    LICENSE_TEXT = ""

_HP_DIR       = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))
DASHBOARD_PID = os.path.join(_HP_DIR, "data", "dashboard.pid")
DASHBOARD_LOG = os.path.join(_HP_DIR, "data", "dashboard.log")

# Defaults live here rather than in the click options: --host/--port are shared
# by two actions that want different ones. Read from config.yaml's dashboard
# section -- loopback and 8050 below are the fallback for an unreadable config,
# not the setting.
def _dash_defaults():
    try:
        from core.config_loader import load_config
        d = load_config(os.path.join(_HP_DIR, "config.yaml")).dashboard
        return d.host, int(d.port)
    except Exception:
        return "127.0.0.1", 8050


DASH_HOST, DASH_PORT = _dash_defaults()


class LicenseCommand(click.Command):
    """Prints the epilog as-is, skipping click's default rewrap — click's
    textwrap splits on whitespace only, which mangles Thai text (no spaces
    between words)."""
    def format_epilog(self, ctx, formatter):
        if self.epilog:
            formatter.write_paragraph()
            formatter.write(self.epilog + "\n")


# ── actions ─────────────────────────────────────────────────────────────────

def _init():
    """Run the setup wizard to configure HydraPoT."""
    from cli.setup_wizard import run_wizard
    run_wizard()


def _run(host, port):
    """Start the honeypot server."""
    if not os.path.exists("config.yaml"):
        click.echo("❌ No config.yaml found. Run `hp --init` first.")
        sys.exit(1)

    from core.config_loader import load_config
    config = load_config()

    # apply CLI overrides if given
    if host:
        config.honeypot.host = host
    if port:
        config.honeypot.port = port

    if console:
        from rich.panel import Panel
        from rich.text import Text
        info = Text()
        info.append(f"  Listening:   {config.honeypot.host}:{config.honeypot.port}\n")
        info.append(f"  Hostname:    {config.honeypot.hostname}\n")
        info.append(f"  Cowrie:      {config.agents.cowrie.host}:{config.agents.cowrie.port}\n")
        od = config.agents.on_device
        info.append(f"  On-device:   {od.model if od.enabled else 'disabled'}\n")
        cl = config.agents.cloud
        info.append(f"  Cloud:       {cl.provider + ' / ' + cl.model if cl.enabled else 'disabled'}\n")
        info.append(f"  Logs:        {config.logging.session_dir}\n")
        console.print(Panel(info, title="[bold yellow] HydraPoT v" + VERSION + "[/bold yellow]",
                            border_style="yellow", width=56))
        console.print("  Press Ctrl+C to stop.\n", style="dim")
    else:
        click.echo(f"HydraPoT v{VERSION}")
        click.echo(f"  Listening: {config.honeypot.host}:{config.honeypot.port}")
        click.echo(f"  Press Ctrl+C to stop.\n")

    import main as honeypot_main
    honeypot_main.main()


def _dash_pid():
    """PID of a live background dashboard, or None (stale pidfile is cleaned).

    psutil rather than os.kill(pid, 0): on Windows os.kill ignores the signal
    and calls TerminateProcess, so the "does it exist" check would KILL the
    dashboard instead of asking about it.
    """
    try:
        pid = int(open(DASHBOARD_PID).read().strip())
    except Exception:
        return None

    import psutil
    if psutil.pid_exists(pid):
        return pid
    try:
        os.remove(DASHBOARD_PID)
    except OSError:
        pass
    return None


def _serve_dashboard(host, port, debug):
    # First-run: make sure the geolocation DB exists so the world map works
    # out of the box. No-op if it's already present; never blocks startup on
    # failure (map just stays empty if offline).
    try:
        from console.geoip_fetch import ensure_geoip
        ensure_geoip()
    except Exception:
        pass
    # Werkzeug logs one line per HTTP request, and Dash fires several per
    # interval tick — so an idle dashboard scrolls the terminal forever with
    # "GET /_dash-update-component 200". Only surface real problems. uvicorn
    # has the same chattiness at its own "access" logger.
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

    # FastAPI (api_server.py) is now what actually listens on the socket --
    # Dash/Flask is mounted underneath it, completely unchanged (still the
    # same dash_app.server, still every existing callback as-is). This is
    # what gives the dashboard real /api/* REST endpoints and a real
    # /ws/events WebSocket alongside the same Dash UI.
    #
    # uvicorn's own thread pool is what a2wsgi dispatches the mounted Flask
    # app onto, same role threaded=True played for Flask's own dev server
    # before this change (the Threat Intel "Generate Intelligence" button's
    # ~11s regex extraction must not block every other request).
    import uvicorn
    uvicorn.run("api.api_server:api", host=host, port=port, reload=debug)


def _is_loopback(host: str) -> bool:
    """True for addresses only reachable from this machine.

    Anything else is world-reachable as far as this check is concerned: it is
    better to make an operator type --i-accept-public-exposure for a LAN bind
    than to guess which private ranges are actually private in their network.
    """
    import ipaddress
    h = (host or "").strip()
    if h in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _dashboard_passwd():
    """Create or rotate the dashboard's operator account.

    THE ONLY WAY AN ACCOUNT IS CREATED. A web setup page would belong to
    whoever reached the port first; running this command already requires
    shell access to the sensor, so the CLI authenticates the operator for
    free. See console/auth.py.
    """
    from console import auth

    existing = auth.load_credential()
    if existing:
        click.echo(f"\n  Rotating the password for '{existing['username']}'.")
        click.echo("  Every signed-in session will be revoked.\n")
    else:
        click.echo("\n  Creating the dashboard operator account.\n")

    username = click.prompt("  Operator username",
                            default=existing.get("username") or "admin")

    # Stated BEFORE the prompt, not after a rejection: finding out the rule by
    # breaking it means typing a password twice for nothing.
    minimum = int(auth.cfg().min_password_length)
    click.echo(f"\n  Password: at least {minimum} characters. Any characters "
               f"-- letters, digits,\n  symbols, spaces, non-English text. No "
               f"required mix, because length is\n  what actually costs an "
               f"attacker. A short phrase you can remember beats a\n  short "
               f"one you cannot.\n")

    # hide_input + confirmation_prompt: the password is never echoed and never
    # reaches the shell history, which is the other reason this is a prompt
    # rather than an argument.
    while True:
        password = click.prompt("  Password", hide_input=True,
                                confirmation_prompt="  Password (again)")
        if len(password) >= minimum:
            break
        # Re-prompt rather than exit: throwing away the whole command over a
        # short password means re-running it and retyping the username too.
        click.echo(click.style(
            f"  Too short — {len(password)} of {minimum} characters. "
            f"Try again.\n", fg="red"))

    path = auth.write_credential(username, password, rotate=bool(existing))
    click.echo(click.style(f"\n  ✓ {'Rotated' if existing else 'Created'} "
                           f"'{username}'", fg="green", bold=True))
    click.echo(f"    stored (mode 0600, hashed with scrypt): {path}")
    if existing:
        click.echo("    all previous sessions revoked")
    click.echo(f"\n  Start the dashboard with: hp --dashboard\n")


def _ensure_operator_account():
    """Make sure an account exists before the dashboard starts.

    Offers to create one right here, so first run costs one prompt rather
    than a failed start and a second command. Without a terminal to prompt on
    -- systemd, a container, CI -- it names the command and stops, because the
    alternative is a dashboard that serves nothing and says so in a log file
    nobody is reading yet.
    """
    from console import auth
    if auth.configured():
        return

    click.echo(click.style(
        "\n  No operator account yet.", fg="yellow", bold=True))
    click.echo("  The dashboard shows captured credentials and runs a SQL "
               "console over them,\n  so it will not serve anything until "
               "there is an account to sign in as.\n")

    if not sys.stdin.isatty():
        click.echo("  Create one on the sensor host:\n")
        click.echo(click.style("      hp --dashboard-passwd\n", fg="green"))
        raise SystemExit(2)

    if not click.confirm("  Create one now?", default=True):
        click.echo("\n  Nothing started. Run: hp --dashboard-passwd\n")
        raise SystemExit(2)
    _dashboard_passwd()


def _dashboard(port, host, debug, foreground, i_accept_public_exposure):
    """Start the analytics dashboard in the background.

    Binds loopback only by default. View it from another machine with an SSH
    tunnel rather than by exposing the port:

        ssh -N -L 8050:127.0.0.1:8050 user@sensor -p <admin-port>
    """
    # There is a login now (console/auth.py), so this is no longer the only
    # thing standing between the SQL console and the internet -- but it stays,
    # because a login is not TLS. On plain HTTP the password crosses the wire
    # in clear, so loopback remains the default and exposure stays deliberate.
    _ensure_operator_account()

    from core.config_loader import load_config
    allowed = load_config(os.path.join(_HP_DIR, "config.yaml")
                          ).dashboard.allow_public_bind
    if not _is_loopback(host) and not (allowed or i_accept_public_exposure):
        click.echo(click.style(
            f"\n  Refusing to bind {host}: a public bind is a deliberate "
            f"choice, not a default.\n", fg="red", bold=True))
        click.echo("  Use an SSH tunnel instead (nothing listens publicly):\n")
        click.echo(click.style(
            f"      ssh -N -L {port}:127.0.0.1:{port} <user>@<sensor-host> -p <admin-ssh-port>\n",
            fg="green"))
        click.echo(f"  then open http://localhost:{port} on your own machine.\n")
        click.echo("  If you genuinely need a public bind, put it behind a reverse")
        click.echo("  proxy with TLS and either set dashboard.allow_public_bind")
        click.echo("  in config.yaml or re-run with:")
        click.echo(f"      hp --dashboard --host {host} --i-accept-public-exposure\n")
        raise SystemExit(2)

    if not _is_loopback(host):
        click.echo(click.style(
            f"  WARNING: binding {host} — the login protects the UI, but "
            f"nothing encrypts it.\n  Put TLS in front of it, or the password "
            f"crosses the network in clear.", fg="yellow", bold=True))

    if foreground:
        click.echo(f"🍯 Dashboard on http://{host}:{port}  (Ctrl+C to stop)")
        _serve_dashboard(host, port, debug)
        return

    running = _dash_pid()
    if running:
        click.echo(f"🍯 Dashboard already running (pid {running}) → http://{host}:{port}")
        click.echo("   Stop it with: hp --dashboard-stop")
        return

    os.makedirs(os.path.dirname(DASHBOARD_PID), exist_ok=True)
    # Re-invoke this same CLI in --foreground mode as a detached child, so the
    # parent can return your shell prompt immediately. start_new_session
    # detaches it from this terminal's process group, so closing the terminal
    # (or Ctrl+C in it) doesn't take the dashboard down with it.
    import subprocess
    # start_new_session is POSIX-only and silently ignored on Windows, where
    # detaching needs creationflags instead -- without them the dashboard dies
    # with the terminal that launched it.
    if sys.platform == "win32":
        detach = {"creationflags": subprocess.DETACHED_PROCESS
                                   | subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        detach = {"start_new_session": True}

    log = open(DASHBOARD_LOG, "ab", buffering=0)
    proc = subprocess.Popen(
        [sys.argv[0], "--dashboard", "--foreground",
         "--host", str(host), "--port", str(port)]
        + (["--debug"] if debug else [])
        + (["--i-accept-public-exposure"] if i_accept_public_exposure else []),
        stdout=log, stderr=log, stdin=subprocess.DEVNULL,
        cwd=_HP_DIR, **detach,
    )
    # Wait until it's actually serving before reporting success. Without this
    # a child that dies immediately (port already in use, import error) still
    # got a pidfile and a cheerful "started" message, and you'd only discover
    # it when the browser showed nothing.
    import socket
    import time as _time
    deadline = _time.time() + 25
    up = False
    while _time.time() < deadline:
        if proc.poll() is not None:
            break                                  # child exited — failed
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex((host, port)) == 0:
                up = True
                break
        _time.sleep(0.3)

    if not up:
        try:
            with open(DASHBOARD_LOG, "rb") as f:
                tail = f.read()[-800:].decode("utf-8", "replace").strip()
        except OSError:
            tail = "(no log)"
        click.echo("❌ Dashboard failed to start:", err=True)
        for line in tail.splitlines()[-8:]:
            click.echo(f"   {line}", err=True)
        try:
            proc.kill()
        except OSError:
            pass
        sys.exit(1)

    with open(DASHBOARD_PID, "w") as f:
        f.write(str(proc.pid))

    click.echo(f"🍯 Dashboard started (pid {proc.pid}) → http://{host}:{port}")
    click.echo(f"   logs: {DASHBOARD_LOG}")
    click.echo("   stop: hp --dashboard-stop")


def _dashboard_stop():
    """Stop the background dashboard."""
    import psutil

    pid = _dash_pid()
    if not pid:
        click.echo("No dashboard is running.")
        return

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        click.echo("No dashboard is running.")
        return

    # psutil.terminate() is SIGTERM on Unix and TerminateProcess on Windows,
    # so one call works on both. Escalate if it is ignored (asyncio/Flask
    # servers sometimes are), otherwise the port stays bound and the next
    # `hp --dashboard` fails with "address already in use".
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except psutil.TimeoutExpired:
        proc.kill()
        click.echo(f"   (pid {pid} ignored terminate — force-killed)")
    except psutil.NoSuchProcess:
        pass

    try:
        os.remove(DASHBOARD_PID)
    except OSError:
        pass
    click.echo(f"🛑 Dashboard stopped (pid {pid}).")


def _version():
    """Show HydraPoT version."""
    click.echo(f"HydraPoT v{VERSION}")


def _config():
    """Show current configuration."""
    if not os.path.exists("config.yaml"):
        click.echo("❌ No config.yaml found. Run `hp --init` first.")
        return

    from core.config_loader import load_config
    cfg = load_config()

    if console:
        from rich.panel import Panel
        from rich.text import Text

        info = Text()
        info.append(f"  Hostname:    {cfg.honeypot.hostname}\n")
        info.append(f"  OS:          {cfg.honeypot.os}\n")
        info.append(f"  Bind:        {cfg.honeypot.host}:{cfg.honeypot.port}\n\n")
        info.append(f"  Cowrie:      {cfg.agents.cowrie.host}:{cfg.agents.cowrie.port}\n")
        od = cfg.agents.on_device
        info.append(f"  On-device:   {od.model if od.enabled else 'disabled'}\n")
        if od.enabled:
            info.append(f"    quant:     {od.quantization}\n")
            info.append(f"    temp:      {od.temperature}\n")
            info.append(f"    tokens:    {od.max_tokens}\n")
        cl = cfg.agents.cloud
        info.append(f"  Cloud:       {cl.provider + ' / ' + cl.model if cl.enabled else 'disabled'}\n\n")
        info.append(f"  Logs:        {cfg.logging.session_dir}\n")
        info.append(f"  FI thresh:   {cfg.logging.fi_threshold}\n")

        console.print(Panel(info, title="[bold]Current Config[/bold]",
                            border_style="cyan", width=56))
    else:
        click.echo(f"Hostname: {cfg.honeypot.hostname}")
        click.echo(f"Bind: {cfg.honeypot.host}:{cfg.honeypot.port}")
        click.echo(f"On-device: {cfg.agents.on_device.model if cfg.agents.on_device.enabled else 'disabled'}")
        click.echo(f"Cloud: {'enabled' if cfg.agents.cloud.enabled else 'disabled'}")


# ── entry point ─────────────────────────────────────────────────────────────

@click.command(cls=LicenseCommand, epilog=LICENSE_TEXT)
@click.option("--init", "do_init", is_flag=True,
              help="Run the setup wizard to configure HydraPoT")
@click.option("--run", "do_run", is_flag=True,
              help="Start the honeypot server")
@click.option("--dashboard", "do_dashboard", is_flag=True,
              help="Start the analytics dashboard in the background")
@click.option("--dashboard-stop", "do_dashboard_stop", is_flag=True,
              help="Stop the background dashboard")
@click.option("--dashboard-passwd", "do_dashboard_passwd", is_flag=True,
              help="Create or rotate the dashboard's operator account")
@click.option("--config", "do_config", is_flag=True,
              help="Show the active configuration")
@click.option("--version", "do_version", is_flag=True,
              help="Show HydraPoT version")
@click.option("--host", default=None,
              help="Bind address. --run: overrides config.yaml. --dashboard: "
                   "defaults to 127.0.0.1; keep it and reach the dashboard over "
                   "an SSH tunnel, since --host 0.0.0.0 needs "
                   "--i-accept-public-exposure")
@click.option("--port", default=None, type=int,
              help="Port. --run: overrides config.yaml. --dashboard: defaults to 8050")
@click.option("--debug/--no-debug", default=False,
              help="--dashboard: enable Flask debug/reloader")
@click.option("--foreground", is_flag=True,
              help="--dashboard: run in this terminal (blocking) instead of the background")
@click.option("--i-accept-public-exposure", is_flag=True,
              help="--dashboard: required to bind a non-loopback address. Read the warning.")
@click.pass_context
def main(ctx, do_init, do_run, do_dashboard, do_dashboard_stop,
         do_dashboard_passwd, do_config, do_version, host, port, debug,
         foreground, i_accept_public_exposure):
    """HydraPoT: Multi Agent Honeypot System

    One command, flags only. Pick exactly one action flag.
    """
    actions = [
        ("--init", do_init),
        ("--run", do_run),
        ("--dashboard", do_dashboard),
        ("--dashboard-stop", do_dashboard_stop),
        ("--dashboard-passwd", do_dashboard_passwd),
        ("--config", do_config),
        ("--version", do_version),
    ]
    chosen = [name for name, on in actions if on]

    if not chosen:
        click.echo(ctx.get_help())
        return

    # Two actions in one invocation has no sensible order (does --run come
    # before or after --dashboard? does either block?), so refuse rather than
    # silently picking one.
    if len(chosen) > 1:
        raise click.UsageError(
            f"pick one action, got {len(chosen)}: {' '.join(chosen)}")

    action = chosen[0]
    if action == "--init":
        _init()
    elif action == "--run":
        _run(host, port)
    elif action == "--dashboard":
        _dashboard(port if port is not None else DASH_PORT,
                   host if host is not None else DASH_HOST,
                   debug, foreground, i_accept_public_exposure)
    elif action == "--dashboard-stop":
        _dashboard_stop()
    elif action == "--dashboard-passwd":
        _dashboard_passwd()
    elif action == "--config":
        _config()
    elif action == "--version":
        _version()


if __name__ == "__main__":
    main()
