"""
replay.py — Animated SSH honeypot session replay viewer
Usage:
    python replay.py                          # latest session
    python replay.py --session abc123         # specific session ID
    python replay.py --file session_log.json  # specific file
    python replay.py --speed 2                # 2x speed (default 1)
    python replay.py --no-animate             # instant, no delays
"""

import argparse
import json
import time
import sys
import os
from datetime import datetime
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import box
from rich.columns import Columns
from rich.padding import Padding

console = Console()

# ── Styling constants ──────────────────────────────────────────────────────────
AGENT_STYLE = {
    "cowrie":    ("COWRIE",    "bold green"),
    "on_device": ("ON-DEVICE", "bold yellow"),
    "cloud":     ("CLOUD",     "bold magenta"),
    "static":    ("STATIC",    "bold cyan"),
    "unknown":   ("UNKNOWN",   "bold white"),
}

FI_STYLE = {
    0: ("FI:0", "dim white",   "●"),
    1: ("FI:1", "bold white",  "●"),
    2: ("FI:2", "bold yellow", "●"),
    3: ("FI:3", "bold orange3","●"),
    4: ("FI:4", "bold red",    "●"),
}

FI_LABEL = {
    0: "Read/Display",
    1: "Create/Install",
    2: "Modify/Navigate",
    3: "Service/Elevate",
    4: "High Impact ⚠",
}

TYPING_SPEED   = 0.03   # seconds per char for attacker command
RESPONSE_DELAY = 0.4    # pause before showing response
COMMAND_PAUSE  = 0.8    # pause between commands


# ── Data loading ───────────────────────────────────────────────────────────────

def load_log(filepath: str) -> list[dict]:
    with open(filepath) as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


def group_by_session(entries: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for e in entries:
        sid = e.get("session_id", "default")
        groups[sid].append(e)
    return dict(groups)


def pick_session(groups: dict, session_id: str | None) -> tuple[str, list[dict]]:
    if session_id:
        if session_id not in groups:
            console.print(f"[red]Session '{session_id}' not found.[/red]")
            sys.exit(1)
        return session_id, groups[session_id]
    # Default: latest session (last entry's session_id)
    sid = list(groups.keys())[-1]
    return sid, groups[sid]


# ── Banner ─────────────────────────────────────────────────────────────────────


def print_banner():
    console.clear()
    banner = Text(justify="center")
    banner.append("██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ██████╗  ██████╗ ████████╗\n", style="bold red")
    banner.append("██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝\n", style="bold red")
    banner.append("███████║ ╚████╔╝ ██║  ██║██████╔╝███████║██████╔╝██║   ██║   ██║   \n", style="bold yellow")
    banner.append("██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║██╔═══╝ ██║   ██║   ██║   \n", style="bold yellow")
    banner.append("██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║     ╚██████╔╝   ██║   \n", style="bold green")
    banner.append("╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝    ╚═╝   \n", style="bold green")
    banner.append("\n  AI-Powered Multi-Tier SSH Honeypot  —  Session Replay\n", style="dim cyan")
    console.print(Align.center(banner))
    console.print(Rule(style="dim"))
    console.print()


# ── Session selector (if multiple sessions) ────────────────────────────────────

def select_session_interactively(groups: dict) -> tuple[str, list[dict]]:
    sids = list(groups.keys())
    if len(sids) == 1:
        return sids[0], groups[sids[0]]

    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    t.add_column("#",           width=4,  justify="right")
    t.add_column("Session ID",  width=20)
    t.add_column("Commands",    width=10, justify="right")
    t.add_column("Start Time",  width=22)
    t.add_column("Peak FI",     width=10, justify="center")

    for i, (sid, entries) in enumerate(groups.items(), 1):
        ts   = entries[0].get("timestamp", "—")
        cmds = len(entries)
        peak = max((e.get("fi_score", 0) for e in entries), default=0)
        fi_color = FI_STYLE[peak][1]
        t.add_row(str(i), sid[:18], str(cmds), ts[:19], f"[{fi_color}]{peak}[/{fi_color}]")

    console.print(t)
    while True:
        raw = input(f"  Select session [1–{len(sids)}] or Enter for latest: ").strip()
        if raw == "":
            sid = sids[-1]
            break
        if raw.isdigit() and 1 <= int(raw) <= len(sids):
            sid = sids[int(raw) - 1]
            break
    return sid, groups[sid]


# ── Session stats header ───────────────────────────────────────────────────────

def print_session_header(sid: str, entries: list[dict]):
    start = entries[0].get("timestamp",  "—")
    end   = entries[-1].get("timestamp", "—")
    peak  = max((e.get("fi_score", 0) for e in entries), default=0)
    total = len(entries)
    impactful = sum(1 for e in entries if e.get("fi_score", 0) >= 2)

    agent_counts: dict[str, int] = defaultdict(int)
    for e in entries:
        agent_counts[e.get("agent", "unknown")] += 1

    # Stats row
    stats = Table.grid(expand=True, padding=(0, 2))
    stats.add_column(justify="left")
    stats.add_column(justify="left")
    stats.add_column(justify="left")
    stats.add_column(justify="left")
    stats.add_row(
        f"[dim]Session:[/dim] [bold cyan]{sid[:16]}[/bold cyan]",
        f"[dim]Commands:[/dim] [bold]{total}[/bold]",
        f"[dim]Impactful (FI≥2):[/dim] [bold yellow]{impactful}[/bold yellow]",
        f"[dim]Peak FI:[/dim] [{FI_STYLE[peak][1]}]{peak} — {FI_LABEL[peak]}[/{FI_STYLE[peak][1]}]",
    )
    stats.add_row(
        f"[dim]Start:[/dim]   [white]{start[:19]}[/white]",
        f"[dim]End:[/dim]     [white]{end[:19]}[/white]",
        f"[dim]Agents:[/dim]  " + "  ".join(
            f"[{AGENT_STYLE[a][1]}]{a}:{n}[/{AGENT_STYLE[a][1]}]"
            for a, n in agent_counts.items()
        ),
        "",
    )

    console.print(Panel(stats, title="[bold]SESSION INFO[/bold]", border_style="cyan", box=box.HEAVY))
    console.print()


# ── Single command renderer ────────────────────────────────────────────────────

def render_command(entry: dict, idx: int, total: int, speed: float, animate: bool):
    cmd       = entry.get("cmd", "")
    response  = entry.get("response", "")
    agent     = entry.get("agent", "unknown")
    fi        = entry.get("fi_score", 0)
    latency   = entry.get("latency_ms", None)
    timestamp = entry.get("timestamp", "")

    fi_label, fi_color, fi_dot = FI_STYLE.get(fi, FI_STYLE[0])
    agent_label, agent_color   = AGENT_STYLE.get(agent, AGENT_STYLE["unknown"])

    # ── Progress line ──
    progress = f"[dim][{idx}/{total}][/dim]"
    ts_short = timestamp[11:19] if len(timestamp) >= 19 else ""
    lat_str  = f"[dim]{latency:.0f}ms[/dim]" if latency else ""
    fi_str   = f"[{fi_color}]{fi_dot} {fi_label} — {FI_LABEL[fi]}[/{fi_color}]"
    ag_str   = f"[{agent_color}]▶ {agent_label}[/{agent_color}]"

    meta = Text()
    meta.append(f" {progress}  ")
    meta.append(f"{ts_short}  ", style="dim")
    meta.append(f"{fi_dot} {fi_label}  ", style=fi_color)
    meta.append(f"▶ {agent_label}  ", style=agent_color)
    if latency:
        meta.append(f"{latency:.0f}ms", style="dim")
    console.print(meta)

    # ── Attacker line (animated typing) ──
    attacker_prefix = Text("  ┌─[attacker@unknown]─$ ", style="bold red")
    console.print(attacker_prefix, end="")

    if animate:
        for ch in cmd:
            console.print(ch, end="", style="bold white")
            sys.stdout.flush()
            time.sleep(TYPING_SPEED / speed)
        console.print()
        time.sleep(RESPONSE_DELAY / speed)
    else:
        console.print(cmd, style="bold white")

    # ── Honeypot response ──
    if response.strip():
        lines = response.strip().splitlines()
        for i, line in enumerate(lines):
            prefix = "  │  " if i < len(lines) - 1 else "  └─ "
            if animate and i == 0:
                time.sleep(0.05 / speed)
            console.print(f"  [dim]│[/dim]", end="")
            console.print(f"  {line}", style="bold green")
    else:
        console.print("  [dim]│  (no output)[/dim]")

    console.print()

    # ── FI warning banner for high-impact commands ──
    if fi >= 3:
        warn_text = "⚠  HIGH IMPACT COMMAND DETECTED" if fi == 4 else "⚡  ELEVATED THREAT COMMAND"
        warn_style = "bold red on dark_red" if fi == 4 else "bold yellow on dark_orange3"
        console.print(Align.center(f"[{warn_style}]  {warn_text}  [/{warn_style}]"))
        console.print()
        if animate:
            time.sleep(0.6 / speed)

    if animate:
        time.sleep(COMMAND_PAUSE / speed)


# ── Summary screen ─────────────────────────────────────────────────────────────

def print_summary(entries: list[dict]):
    console.print(Rule("[bold cyan]SESSION SUMMARY[/bold cyan]"))
    console.print()

    # FI distribution table
    fi_counts: dict[int, int] = defaultdict(int)
    for e in entries:
        fi_counts[e.get("fi_score", 0)] += 1

    ft = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", title="FI Score Distribution")
    ft.add_column("FI", justify="center", width=5)
    ft.add_column("Meaning",  width=20)
    ft.add_column("Count",   justify="right", width=8)
    ft.add_column("Bar",     width=30)

    total = len(entries)
    for fi in range(5):
        n = fi_counts[fi]
        _, color, dot = FI_STYLE[fi]
        bar_len = int((n / total) * 28) if total else 0
        bar = f"[{color}]{'█' * bar_len}[/{color}][dim]{'░' * (28 - bar_len)}[/dim]"
        ft.add_row(f"[{color}]{fi}[/{color}]", FI_LABEL[fi], str(n), bar)

    console.print(ft)
    console.print()

    # Top dangerous commands
    dangerous = sorted(
        [e for e in entries if e.get("fi_score", 0) >= 2],
        key=lambda x: x.get("fi_score", 0),
        reverse=True
    )[:5]

    if dangerous:
        dt = Table(box=box.SIMPLE, show_header=True, header_style="bold red", title="Top Dangerous Commands")
        dt.add_column("FI", justify="center", width=5)
        dt.add_column("Command", width=40)
        dt.add_column("Agent",   width=12)
        dt.add_column("Latency", justify="right", width=10)

        for e in dangerous:
            fi = e.get("fi_score", 0)
            _, color, dot = FI_STYLE[fi]
            lat = f"{e['latency_ms']:.0f}ms" if e.get("latency_ms") else "—"
            _, ag_color = AGENT_STYLE.get(e.get("agent", "unknown"), AGENT_STYLE["unknown"])
            dt.add_row(
                f"[{color}]{fi}[/{color}]",
                e.get("cmd", "")[:38],
                f"[{ag_color}]{e.get('agent','?')[:10]}[/{ag_color}]",
                lat,
            )
        console.print(dt)
        console.print()

    # Agent usage
    agent_counts: dict[str, int] = defaultdict(int)
    for e in entries:
        agent_counts[e.get("agent", "unknown")] += 1

    at = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", title="Agent Usage")
    at.add_column("Agent",    width=14)
    at.add_column("Commands", justify="right", width=10)
    at.add_column("Share",    width=26)

    for agent, n in sorted(agent_counts.items(), key=lambda x: -x[1]):
        _, color = AGENT_STYLE.get(agent, AGENT_STYLE["unknown"])
        bar_len = int((n / total) * 24) if total else 0
        bar = f"[{color}]{'█' * bar_len}[/{color}][dim]{'░' * (24 - bar_len)}[/dim]"
        at.add_row(f"[{color}]{agent}[/{color}]", str(n), bar)

    console.print(at)
    console.print()
    console.print(Rule(style="dim"))


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot Session Replay Viewer")
    parser.add_argument("--file",       default="session_log.json", help="Path to session log JSON")
    parser.add_argument("--session",    default=None,               help="Session ID to replay")
    parser.add_argument("--speed",      type=float, default=1.0,    help="Replay speed multiplier (default 1)")
    parser.add_argument("--no-animate", action="store_true",        help="Disable animations")
    parser.add_argument("--summary",    action="store_true",        help="Show summary only, no replay")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        console.print(f"[red]File not found: {args.file}[/red]")
        sys.exit(1)

    animate = not args.no_animate

    print_banner()

    entries = load_log(args.file)
    groups  = group_by_session(entries)

    if args.session:
        sid, session_entries = pick_session(groups, args.session)
    else:
        sid, session_entries = select_session_interactively(groups)

    print_session_header(sid, session_entries)

    if args.summary:
        print_summary(session_entries)
        return

    # ── Replay loop ──
    console.print(Rule("[bold]REPLAY START[/bold]"))
    console.print()

    if animate:
        console.print(Align.center("[dim]Press Ctrl+C to skip to summary[/dim]"))
        console.print()
        time.sleep(1)

    try:
        for i, entry in enumerate(session_entries, 1):
            render_command(entry, i, len(session_entries), args.speed, animate)
    except KeyboardInterrupt:
        console.print("\n[dim]Skipped to summary...[/dim]\n")

    print_summary(session_entries)


if __name__ == "__main__":
    main()