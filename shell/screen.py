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


def render_top(rows, hw, uptime_line, tick, noise, delay, height, sort="cpu", user_fmt=None,
               opts=None, width=80, mem_drift=0, color=False):
    """One frame of `top` as text.

    rows: the process table (rulecore._rows); hw: system_state.hardware;
    noise(name, lo, hi): a seeded integer, so a frame is repeatable for a session.
    opts: what `top`'s flags and keys set: cmdline (c), per_cpu (1), idle (False = -i),
    user (-u), pids (-p). width: batch mode is 80 unless the terminal says otherwise.
    color: interactive top draws its column header in reverse video and R tasks bold.
    """
    opts = opts or {}
    mem = hw["memory_kb"]
    mib = lambda kb: kb / 1024
    # free memory and the page cache trade a few MB with each other as the box works
    free = mem["free"] + mem_drift
    buff_cache = mem["buffers"] + mem["cached"] + mem["sreclaimable"] - mem_drift
    used = mem["total"] - free - buff_cache
    swap_used = mem["swap_total"] - mem["swap_free"]

    def cpu_split(label, salt):
        us, sy = noise(f"us{salt}{tick}", 2, 9), noise(f"sy{salt}{tick}", 1, 6)
        wa, si = noise(f"wa{salt}{tick}", 0, 3), noise(f"si{salt}{tick}", 0, 2)
        idle = 1000 - us - sy - wa - si
        return (f"{label} {us / 10:4.1f} us, {sy / 10:4.1f} sy,  0.0 ni, {idle / 10:4.1f} id, "
                f"{wa / 10:4.1f} wa,  0.0 hi, {si / 10:4.1f} si,  0.0 st")
    if opts.get("per_cpu"):
        cpu_lines = [cpu_split(f"%Cpu{i:<3d}:", i) for i in range(hw.get("cpus", 1))]
    else:
        cpu_lines = [cpu_split("%Cpu(s):", "")]

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
    if opts.get("user"):
        shown = [r for r in shown if r["user"] == opts["user"]]
    if opts.get("pids"):
        shown = [r for r in shown if r["pid"] in opts["pids"]]
    if opts.get("idle") is False:
        shown = [r for r in shown if r["cpu"] > 0 or r["state"] == "R"]
    key = {"cpu": lambda r: (-r["cpu"], r["pid"]), "mem": lambda r: (-r["mem"], r["pid"]),
           "pid": lambda r: r["pid"], "time": lambda r: (-r["time"], r["pid"])}[sort]
    shown.sort(key=key)

    running = sum(1 for r in shown if r["state"] == "R")
    # the task counts describe the whole machine, not the filtered view
    total = len(rows)
    head = [
        f"top -{uptime_line}",
        f"Tasks: {total:>3} total, {1:>3} running, {total - 1:>3} sleeping,"
        f"   0 stopped,   0 zombie",
        *cpu_lines,
        f"MiB Mem : {mib(mem['total']):8.1f} total, {mib(free):8.1f} free, "
        f"{mib(used):8.1f} used, {mib(buff_cache):8.1f} buff/cache",
        f"MiB Swap: {mib(mem['swap_total']):8.1f} total, {mib(mem['swap_free']):8.1f} free, "
        f"{mib(swap_used):8.1f} used. {mib(mem['available'] + mem_drift):8.1f} avail Mem ",
        "",
    ]
    column_names = "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"
    fmt = user_fmt or (lambda u: u[:8])
    body = []
    for r in shown[: max(1, height - len(head) - 1)] if height else shown:
        seconds = r["time"] + tick * delay * r["cpu"] / 100
        shown_cmd = r["cmd"] if opts.get("cmdline") else r["name"]
        line = (f"{r['pid']:>7} {fmt(r['user']):<9} {r['pr']:>2} {r['ni']:>3} "
                f"{_mem(r['vsz']):>7} {_mem(r['rss']):>6} {_mem(r['shr']):>6} {r['state']} "
                f"{r['cpu']:>5.1f} {r['mem']:>5.1f} {_hundredths(seconds):>9} ")
        room = width - len(line)
        text = shown_cmd if len(shown_cmd) <= room else shown_cmd[: max(room - 1, 0)] + "+"
        body.append((line + text, r["state"] == "R"))
    lines = head[:]
    if color:
        sort_col = {"cpu": "%CPU", "mem": "%MEM", "pid": "PID", "time": "TIME+"}[sort]
        marked = column_names.replace(sort_col, f"\x1b[1m{sort_col}\x1b[0m\x1b[7m", 1)
        lines.append("\x1b[7m" + marked.ljust(width + 0) + "\x1b[0m")
        lines += [("\x1b[1m" + t + "\x1b[0m") if bold else t for t, bold in body]
        return "\n".join(lines)
    lines.append(column_names)
    lines += [t for t, _ in body]
    return "\n".join(l[:width] for l in lines)


def render_watch(cmd: str, hostname: str, now_text: str, output: str, delay: float, width: int):
    """`watch`'s frame: its own header line, a blank, then the command's output."""
    left = f"Every {delay:.1f}s: {cmd}"
    right = f"{hostname}: {now_text}"
    gap = max(2, width - len(left) - len(right))
    return left + " " * gap + right + "\n\n" + output
