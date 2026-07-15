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

@main.command()
@click.option("--port", default=8050, type=int, help="Dash port")
@click.option("--host", default="127.0.0.1", help="Bind address (use 0.0.0.0 to expose externally)")
@click.option("--debug/--no-debug", default=False, help="Enable Flask debug/reloader")
def dashboard(port, host, debug):
    """Open the analytics dashboard."""
    click.echo(f"🍯 Opening dashboard on http://{host}:{port} ...")
    from dashboard import app as dash_app
    dash_app.run(host=host, port=port, debug=debug)


@main.command()
@click.option("--auth", is_flag=True, help="Show auth log instead of session log")
@click.option("-n", "--lines", default=20, help="Number of recent entries to show")
def logs(auth, lines):
    """View recent log entries."""
    import json

    from config_loader import load_config
    config = load_config()

    if auth:
        path = config.logging.auth_log
        title = "Auth Attempts"
    else:
        # find most recent session log
        session_dir = config.logging.session_dir
        if not os.path.exists(session_dir):
            click.echo(f"No logs found in {session_dir}")
            return
        files = sorted(
            [f for f in os.listdir(session_dir) if f.endswith(".json")],
            reverse=True
        )
        if not files:
            click.echo("No session logs found.")
            return
        path = os.path.join(session_dir, files[0])
        title = f"Session: {files[0]}"

    if not os.path.exists(path):
        click.echo(f"Log file not found: {path}")
        return

    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = []
    except Exception:
        click.echo(f"Error reading {path}")
        return

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