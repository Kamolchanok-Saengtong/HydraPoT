"""
shell/screen.py -- full-screen programs (top, watch) drawn from the host's own state.

`top` was stock Cowrie's one frozen snapshot: a different uptime, RAM and process list
from `ps`, `free` and `uptime`, and it returned to the prompt at once. A frame is now
built from the same process rows and memory numbers those commands read, and redrawn
while the attacker watches. The SSH layer (core/fullscreen.py) owns the loop and keys.
"""
import posixpath

# %CPU a process may show on a quiet box: most are 0.0, a few tick over now and then
_BUSY_COMM = ("rsyslogd", "systemd-journal", "dbus-daemon", "systemd", "sshd")
_RT = ("migration/", "watchdog", "idle_inject/")


def comm(cmd: str) -> str:
    """The name top shows: the kernel's 15-character process name."""
    if cmd.startswith("["):
        return cmd.strip("[]")[:15]
    first = cmd.lstrip("-").split()[0] if cmd.split() else cmd
    first = first.rstrip(":")
    return posixpath.basename(first)[:15] or first[:15]


def _hundredths(seconds: float) -> str:
    total = int(seconds * 100)
    return f"{total // 6000}:{(total // 100) % 60:02d}.{total % 100:02d}"


def _mem(kb: float) -> str:
    """VIRT/RES/SHR as top prints them: KiB, then m and g for large values."""
    if kb < 100_000:
        return str(int(kb))
    mb = kb / 1024
    return f"{mb:.0f}m" if mb < 10_000 else f"{mb / 1024:.1f}g"


def render_top(rows, hw, uptime_line, tick, noise, delay, height, sort="cpu", user_fmt=None):
    """One frame of `top` as text.

    rows: the process table (rulecore._rows); hw: system_state.hardware;
    noise(name, lo, hi): a seeded integer, so a frame is repeatable for a session.
    """
    mem = hw["memory_kb"]
    mib = lambda kb: kb / 1024
    buff_cache = mem["buffers"] + mem["cached"] + mem["sreclaimable"]
    used = mem["total"] - mem["free"] - buff_cache
    swap_used = mem["swap_total"] - mem["swap_free"]

    # CPU split: a few tenths busy, the rest idle
    us, sy = noise(f"us{tick}", 2, 9), noise(f"sy{tick}", 1, 6)
    wa, si = noise(f"wa{tick}", 0, 3), noise(f"si{tick}", 0, 2)
    idle = 1000 - us - sy - wa - si
    cpu_line = (f"%Cpu(s): {us / 10:4.1f} us, {sy / 10:4.1f} sy,  0.0 ni, {idle / 10:4.1f} id, "
                f"{wa / 10:4.1f} wa,  0.0 hi, {si / 10:4.1f} si,  0.0 st")

    shown = []
    for r in rows:
        name = r.get("comm") or comm(r["cmd"])      # PID 1 is `systemd`, though started as /sbin/init
        if r["cmd"] == "top" or r["cmd"].startswith("top"):
            cpu = 0.3 + noise(f"t{tick}", 0, 5) / 10
        elif name in _BUSY_COMM and noise(f"b{r['pid']}x{tick}", 0, 99) > 88:
            cpu = noise(f"c{r['pid']}x{tick}", 3, 12) / 10
        else:
            cpu = 0.0
        stat = r["stat"]
        pr, ni = ("0", -20) if "<" in stat else ("39", 19) if "N" in stat else ("20", 0)
        if name.startswith(_RT):
            pr, ni = "rt", 0
        shr = int(r["rss"] * (0.25 + noise(f"s{r['pid']}", 0, 30) / 100))
        shown.append({**r, "cpu": cpu, "name": name, "pr": pr, "ni": ni, "shr": shr,
                      "state": "R" if cpu >= 0.3 and name == "top" else stat[0]})
    key = {"cpu": lambda r: (-r["cpu"], r["pid"]), "mem": lambda r: (-r["mem"], r["pid"]),
           "pid": lambda r: r["pid"], "time": lambda r: (-r["time"], r["pid"])}[sort]
    shown.sort(key=key)

    running = sum(1 for r in shown if r["state"] == "R")
    head = [
        f"top -{uptime_line}",
        f"Tasks: {len(shown):>3} total, {running:>3} running, {len(shown) - running:>3} sleeping,"
        f"   0 stopped,   0 zombie",
        cpu_line,
        f"MiB Mem : {mib(mem['total']):8.1f} total, {mib(mem['free']):8.1f} free, "
        f"{mib(used):8.1f} used, {mib(buff_cache):8.1f} buff/cache",
        f"MiB Swap: {mib(mem['swap_total']):8.1f} total, {mib(mem['swap_free']):8.1f} free, "
        f"{mib(swap_used):8.1f} used. {mib(mem['available']):8.1f} avail Mem ",
        "",
        "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
    ]
    fmt = user_fmt or (lambda u: u[:8])
    lines = head
    for r in shown[: max(1, height - len(head))] if height else shown:
        seconds = r["time"] + tick * delay * r["cpu"] / 100
        lines.append(f"{r['pid']:>7} {fmt(r['user']):<9} {r['pr']:>2} {r['ni']:>3} "
                     f"{_mem(r['vsz']):>7} {_mem(r['rss']):>6} {_mem(r['shr']):>6} {r['state']} "
                     f"{r['cpu']:>5.1f} {r['mem']:>5.1f} {_hundredths(seconds):>9} {r['name']}")
    return "\n".join(lines)


def render_watch(cmd: str, hostname: str, now_text: str, output: str, delay: float, width: int):
    """`watch`'s frame: its own header line, a blank, then the command's output."""
    left = f"Every {delay:.1f}s: {cmd}"
    right = f"{hostname}: {now_text}"
    gap = max(2, width - len(left) - len(right))
    return left + " " * gap + right + "\n\n" + output
