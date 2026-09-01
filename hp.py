"""
hp.py — HydraPoT CLI entry point.

Registered as `hp` command via pyproject.toml.

Usage:
    hp init        # run setup wizard
    hp run         # start the honeypot
    hp dashboard   # open streamlit dashboard
    hp logs        # view recent session logs
    hp logs --auth # view auth attempt logs
    hp version     # show version
"""

import os
import sys
import click

# Ensure the project root is importable even when `hp` runs from an editable
# install's entry point (whose finder only exposes packages declared in
# pyproject.toml). Lets local packages like threat_intel/ import without a
# reinstall after being added.
_ROOT = os.path.dirname(os.path.abspath(__file__))
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

VERSION = "0.1.0"

_HERE = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(_HERE, "license"), encoding="utf-8") as _f:
        LICENSE_TEXT = _f.read().strip()
except FileNotFoundError:
    LICENSE_TEXT = ""


class LicenseGroup(click.Group):
    """Prints the epilog as-is, skipping click's default rewrap — click's
    textwrap splits on whitespace only, which mangles Thai text (no spaces
    between words)."""
    def format_epilog(self, ctx, formatter):
        if self.epilog:
            formatter.write_paragraph()
            formatter.write(self.epilog + "\n")


@click.group(cls=LicenseGroup, invoke_without_command=True, epilog=LICENSE_TEXT)
@click.pass_context
def main(ctx):
    """HydraPoT: Multi Agent Honeypot System"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

@main.command()
@click.option("--force", is_flag=True, help="(kept for compatibility)")
def init(force):
    """Run the setup wizard to configure HydraPoT."""
    from setup_wizard import run_wizard
    run_wizard()


@main.command()
@click.option("--host", default=None, help="Override bind address from config")
@click.option("--port", default=None, type=int, help="Override port from config")
def run(host, port):
    """Start the honeypot server."""
    # check config exists
    if not os.path.exists("config.yaml"):
        click.echo("❌ No config.yaml found. Run `hp init` first.")
        sys.exit(1)

    from config_loader import load_config
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

_HP_DIR       = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_PID = os.path.join(_HP_DIR, "data", "dashboard.pid")
DASHBOARD_LOG = os.path.join(_HP_DIR, "data", "dashboard.log")


def _dash_pid():
    """PID of a live background dashboard, or None (stale pidfile is cleaned)."""
    try:
        pid = int(open(DASHBOARD_PID).read().strip())
    except Exception:
        return None
    try:
        os.kill(pid, 0)          # signal 0 = existence check, doesn't touch it
        return pid
    except OSError:
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
        from geoip_fetch import ensure_geoip
        ensure_geoip()
    except Exception:
        pass
    # Werkzeug logs one line per HTTP request, and Dash fires several per
    # interval tick — so an idle dashboard scrolls the terminal forever with
    # "GET /_dash-update-component 200". Only surface real problems.
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    from dashboard import app as dash_app
    # threaded=True: Flask's dev server is single-request-at-a-time by
    # default. The Threat Intel "Generate Intelligence" button runs a real
    # ~11s regex extraction (build_ioc_snapshot over all sessions) — without
    # threading, THAT ONE request blocks the entire dashboard (every tab,
    # every page, the auto-refresh interval) until it finishes.
    dash_app.run(host=host, port=port, debug=debug, threaded=True)


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


@main.command()
@click.option("--port", default=8050, type=int, help="Dash port")
@click.option("--host", default="127.0.0.1",
              help="Bind address. Keep 127.0.0.1 and reach it over an SSH "
                   "tunnel; --host 0.0.0.0 needs --i-accept-public-exposure")
@click.option("--debug/--no-debug", default=False, help="Enable Flask debug/reloader")
@click.option("--foreground", is_flag=True,
              help="Run in this terminal (blocking) instead of the background")
@click.option("--i-accept-public-exposure", is_flag=True,
              help="Required to bind a non-loopback address. Read the warning.")
def dashboard(port, host, debug, foreground, i_accept_public_exposure):
    """Start the analytics dashboard in the background (stop: hp dashboard-stop).

    Binds loopback only by default. View it from another machine with an SSH
    tunnel rather than by exposing the port:

        ssh -N -L 8050:127.0.0.1:8050 user@sensor -p <admin-port>
    """
    # The dashboard has NO authentication and its Database page includes a
    # read-only SQL console over the capture database. Read-only is not the
    # same as harmless: `SELECT username, password FROM auth` returns every
    # credential the honeypot ever collected, plus every attacker IP and
    # command. Binding it to the internet publishes all of that to anyone who
    # finds the port.
    #
    # So a public bind has to be typed out deliberately. The tunnel costs one
    # command and leaves nothing listening to find.
    if not _is_loopback(host) and not i_accept_public_exposure:
        click.echo(click.style(
            f"\n  Refusing to bind {host}: the dashboard has no login and "
            f"exposes a SQL console\n  over your captured credentials.\n",
            fg="red", bold=True))
        click.echo("  Use an SSH tunnel instead (nothing listens publicly):\n")
        click.echo(click.style(
            f"      ssh -N -L {port}:127.0.0.1:{port} <user>@<sensor-host> -p <admin-ssh-port>\n",
            fg="green"))
        click.echo(f"  then open http://localhost:{port} on your own machine.\n")
        click.echo("  If you genuinely need a public bind, put it behind a reverse")
        click.echo("  proxy with TLS and auth, and re-run with:")
        click.echo(f"      hp dashboard --host {host} --i-accept-public-exposure\n")
        raise SystemExit(2)

    if not _is_loopback(host):
        click.echo(click.style(
            f"  WARNING: binding {host} — dashboard is unauthenticated and "
            f"exposes a SQL console.", fg="yellow", bold=True))

    if foreground:
        click.echo(f"🍯 Dashboard on http://{host}:{port}  (Ctrl+C to stop)")
        _serve_dashboard(host, port, debug)
        return

    running = _dash_pid()
    if running:
        click.echo(f"🍯 Dashboard already running (pid {running}) → http://{host}:{port}")
        click.echo("   Stop it with: hp dashboard-stop")
        return

    os.makedirs(os.path.dirname(DASHBOARD_PID), exist_ok=True)
    # Re-invoke this same CLI in --foreground mode as a detached child, so the
    # parent can return your shell prompt immediately. start_new_session
    # detaches it from this terminal's process group, so closing the terminal
    # (or Ctrl+C in it) doesn't take the dashboard down with it.
    import subprocess
    log = open(DASHBOARD_LOG, "ab", buffering=0)
    proc = subprocess.Popen(
        [sys.argv[0], "dashboard", "--foreground",
         "--host", str(host), "--port", str(port)]
        + (["--debug"] if debug else [])
        + (["--i-accept-public-exposure"] if i_accept_public_exposure else []),
        stdout=log, stderr=log, stdin=subprocess.DEVNULL,
        start_new_session=True, cwd=_HP_DIR,
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
    click.echo("   stop: hp dashboard-stop")


@main.command("dashboard-stop")
def dashboard_stop():
    """Stop the background dashboard."""
    import signal
    import time as _time

    pid = _dash_pid()
    if not pid:
        click.echo("No dashboard is running.")
        return

    os.kill(pid, signal.SIGTERM)
    # Give it a moment to close the socket; escalate if it ignores SIGTERM
    # (asyncio/Flask servers sometimes do), otherwise the port stays bound and
    # the next `hp dashboard` fails with "address already in use".
    for _ in range(20):
        _time.sleep(0.1)
        try:
            os.kill(pid, 0)
        except OSError:
            break
    else:
        os.kill(pid, signal.SIGKILL)
        click.echo(f"   (pid {pid} ignored SIGTERM — force-killed)")

    try:
        os.remove(DASHBOARD_PID)
    except OSError:
        pass
    click.echo(f"🛑 Dashboard stopped (pid {pid}).")


@main.command()
@click.option("--update", "force_update", is_flag=True,
              help="Re-download even if the database already exists (refresh to the latest month)")
def geoip(force_update):
    """Download / refresh the DB-IP geolocation database for the dashboard map."""
    from geoip_fetch import update_geoip, ensure_geoip, DEFAULT_MMDB
    if force_update:
        click.echo("🌍 Refreshing DB-IP geolocation database...")
        ok = update_geoip(DEFAULT_MMDB)
    else:
        if os.path.exists(DEFAULT_MMDB):
            click.echo(f"🌍 Geolocation database already present: {DEFAULT_MMDB}")
            click.echo("   Use `hp geoip --update` to refresh to the latest month.")
            return
        ok = ensure_geoip(DEFAULT_MMDB)
    click.echo("✅ Done." if ok else "⚠️  Could not download (offline?). Map will be unavailable.")


@main.command()
@click.option("--out", "out_dir", default="data/threat_intel",
              help="Directory to write the IOC report into")
@click.option("--format", "fmt", type=click.Choice(["all", "json", "csv", "stix"]),
              default="all", help="Export format(s)")
@click.option("--min-fi", default=0, type=int,
              help="Only include IOCs whose max FI score is >= this")
def intel(out_dir, fmt, min_fi):
    """Extract Indicators of Compromise (IOCs) from the logs into a threat feed."""
    import json, glob
    from config_loader import load_config
    from threat_intel.ioc_extractor import build_iocs, to_json, to_csv, to_stix

    import storage

    load_config()   # validates config / applies the active sensor profile

    # Both come from SQLite now — the sensor no longer writes JSON logs.
    # Sessions include `response`: IOCs are extracted from command output too.
    rows = storage.query_all()
    auth = storage.query_auth()

    if not rows and not auth:
        click.echo("No logs found yet — run the honeypot first (`hp run`).")
        return

    store = build_iocs(rows, auth)
    recs = [r for r in store.records() if r["max_fi"] >= min_fi]

    os.makedirs(out_dir, exist_ok=True)
    written = []
    if fmt in ("all", "json"):
        written.append(to_json(store, os.path.join(out_dir, "iocs.json")))
    if fmt in ("all", "csv"):
        written.append(to_csv(store, os.path.join(out_dir, "iocs.csv")))
    if fmt in ("all", "stix"):
        written.append(to_stix(store, os.path.join(out_dir, "iocs_stix.json")))

    from collections import Counter
    by_type = Counter(r["type"] for r in recs)
    click.echo(f"\n🔎 Extracted {len(recs)} unique IOCs from {len(rows)} commands "
               f"+ {len(auth)} auth attempts")
    click.echo("   " + "  ".join(f"{t}:{n}" for t, n in by_type.most_common()))
    click.echo("\n   Top indicators (by severity, then frequency):")
    for r in recs[:10]:
        click.echo(f"     [{r['type']:10}] {r['value'][:48]:48} "
                   f"×{r['count']} (FI {r['max_fi']}, {r['session_count']} sessions)")
    click.echo("\n   Files written:")
    for w in written:
        click.echo(f"     {w}")


@main.command()
@click.option("--auth", is_flag=True, help="Show auth log instead of session log")
@click.option("-n", "--lines", default=20, help="Number of recent entries to show")
def logs(auth, lines):
    """View recent log entries."""
    import json

    from config_loader import load_config
    config = load_config()

    import storage

    if auth:
        data = storage.query_auth()
        title = "Auth Attempts"
        if not data:
            click.echo("No auth attempts recorded yet.")
            return
    else:
        # Sessions live in SQLite. Ask for the newest rows and show the session
        # they belong to, instead of picking the alphabetically-last filename —
        # which was never reliably the most recent session anyway.
        import storage
        newest = storage.query_recent(1)
        if not newest:
            click.echo("No session logs found — run the honeypot first (`hp run`).")
            return
        sid = newest[0]["session_id"]
        data = storage.query_session(sid, instance=newest[0].get("instance"))
        title = f"Session: {sid}"

    entries = data[-lines:]

    if console and HAS_RICH:
        table = Table(title=title, box=box.SIMPLE, show_lines=False)

        if auth:
            table.add_column("Time",     style="dim",    max_width=19)
            table.add_column("IP",       style="cyan",   max_width=16)
            table.add_column("User",     style="yellow", max_width=12)
            table.add_column("Password", style="red",    max_width=20)
            for e in entries:
                table.add_row(
                    e.get("timestamp", "?"),
                    e.get("src_ip", "?"),
                    e.get("username", "?"),
                    e.get("password", "?"),
                )
        else:
            table.add_column("Time",    style="dim",    max_width=10)
            table.add_column("IP",      style="cyan",   max_width=16)
            table.add_column("Agent",   style="yellow", max_width=10)
            table.add_column("FI",      style="red",    max_width=4)
            table.add_column("Command", style="white",  max_width=50)
            for e in entries:
                fi = e.get("fi_score", 0)
                fi_style = "red bold" if fi >= 3 else "yellow" if fi >= 2 else "dim"
                table.add_row(
                    e.get("timestamp", "?")[-8:],   # just HH:MM:SS
                    e.get("src_ip", "?"),
                    e.get("agent", "?"),
                    str(fi),
                    e.get("cmd", "?"),
                )

        console.print(table)
    else:
        click.echo(f"\n── {title} (last {len(entries)}) ──")
        for e in entries:
            if auth:
                click.echo(f"  {e.get('timestamp','?')}  {e.get('src_ip','?')}  "
                           f"{e.get('username','?')}:{e.get('password','?')}")
            else:
                click.echo(f"  {e.get('timestamp','?')[-8:]}  FI={e.get('fi_score',0)}  "
                           f"[{e.get('agent','?')}]  $ {e.get('cmd','?')}")
        click.echo()


@main.command()
def version():
    """Show HydraPoT version."""
    click.echo(f"HydraPoT v{VERSION}")


@main.command()
def config():
    """Show current configuration."""
    if not os.path.exists("config.yaml"):
        click.echo("❌ No config.yaml found. Run `hp init` first.")
        return

    from config_loader import load_config
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


if __name__ == "__main__":
    main()