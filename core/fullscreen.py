"""
core/fullscreen.py -- programs that take over the terminal (top, watch).

The shell reads a line at a time, so a program that redraws and waits for keys cannot
run through it: `top` used to print once and return to the prompt. Here the channel
is switched to raw keys, the program is drawn on the alternate screen, and it ends on
`q` or Ctrl-C, leaving the terminal as it was, which is what ncurses programs do.
"""
import asyncio
import re
import shlex
import time
from datetime import datetime

import asyncssh

from shell import netsim
from shell import screen as screen_mod

_SORT_KEYS = {"P": "cpu", "M": "mem", "N": "pid", "T": "time"}
# keys that flip a display option, as in the real top: c = full command lines,
# 1 = one line per CPU, i = hide idle tasks
_TOGGLES = {"c": "cmdline", "1": "per_cpu", "i": "idle"}
_MAX_TICKS = 400                    # a `watch` nobody stops ends on its own after a while


def watch_spec(cmd: str, handler, hostname: str):
    """Spec for `watch [-n SEC] command...`, or None when it is not one we model."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return None
    if argv[:1] == ["sudo"]:
        argv = argv[1:]
    if argv[:1] != ["watch"]:
        return None
    delay, i = 2.0, 1
    while i < len(argv) and argv[i].startswith("-"):
        a = argv[i]
        if a in ("-n", "--interval") and i + 1 < len(argv):
            try:
                delay = max(float(argv[i + 1]), 0.1)
            except ValueError:
                return None
            i += 2
        elif re.fullmatch(r"-n\d+(\.\d+)?", a):
            delay, i = max(float(a[2:]), 0.1), i + 1
        elif a in ("-t", "--no-title", "-d", "--differences", "-b", "--beep"):
            i += 1
        else:
            return None
    inner = " ".join(argv[i:])
    if not inner:
        return None

    def frame(tick, height, width, sort):
        buf = []
        response, _ = handler(inner, buf.append, lambda: None)
        out = response if isinstance(response, str) and response and not response.startswith("__SWALLOW_") \
            else "".join(buf)
        out = out.replace("\r\n", "\n")
        body = "\n".join(l[:width] for l in out.split("\n")[: max(1, height - 2)])
        now = datetime.now().strftime("%a %b %e %H:%M:%S %Y")
        return screen_mod.render_watch(inner, hostname, now, body, delay, width)
    return {"kind": "watch", "delay": delay, "count": None, "frame": frame,
            "begin": lambda: None, "end": lambda: None}


def stream_spec(cmd: str, handler, ctx: dict):
    """Spec for programs that print as they go and end on Ctrl-C: `ping`, `tail -f`."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return None
    if argv[:1] == ["sudo"]:
        argv = argv[1:]
    if argv[:1] == ["ping"]:
        cfg, err = netsim.parse_ping(argv, ctx["hostname"])
        if cfg is None:
            return None                       # an error line: the normal path prints it
        ping = cfg["ping"]
        return {"kind": "stream", "start": ping.header(), "interval": cfg["interval"],
                "count": cfg["count"], "tick": ping.reply,
                "finish": lambda n, ms: ping.summary(ms)}
    if argv[:1] == ["tail"] and ("-f" in argv or "-F" in argv or "--follow" in argv):
        files = [a for a in argv[1:] if not a.startswith("-") and not a.isdigit()]
        n = 10
        for i, a in enumerate(argv):
            if a == "-n" and i + 1 < len(argv) and argv[i + 1].isdigit():
                n = int(argv[i + 1])
        if len(files) != 1:
            return None
        buf = []
        response, _ = handler(f"cat {shlex.quote(files[0])}", buf.append, lambda: None)
        text = (response if isinstance(response, str) and response else "".join(buf)).replace("\r\n", "\n")
        if text.startswith("cat: ") and "No such file" in text:
            return {"kind": "stream", "start": f"tail: cannot open '{files[0]}' for reading: No such file or directory",
                    "interval": 1.0, "count": 0, "tick": lambda n_: None, "finish": lambda n_, ms: "tail: no files remaining"}
        last = "\n".join(text.rstrip("\n").split("\n")[-n:])
        return {"kind": "stream", "start": last, "interval": 5.0, "count": None,
                "tick": lambda n_: None, "finish": lambda n_, ms: ""}
    return None


async def run_stream(process, spec) -> None:
    """Print lines as they come, until the count is reached or Ctrl-C."""
    chan = process.channel
    chan.set_line_mode(False)
    chan.set_echo(False)

    def out(text):
        if text and not process.stdout.is_closing():
            process.stdout.write(text.replace("\n", "\r\n"))
    out(spec["start"] + "\n")
    started, seq, reader, interrupted = time.monotonic(), 0, None, False
    try:
        while spec.get("count") != 0:
            seq += 1
            line = spec["tick"](seq)
            if line:
                out(line + "\n")
            if spec.get("count") is not None and seq >= spec["count"]:
                break
            if reader is None:
                reader = asyncio.ensure_future(process.stdin.read(1))
            done, _ = await asyncio.wait({reader}, timeout=spec["interval"])
            if done:
                try:
                    key = reader.result()
                except (asyncssh.TerminalSizeChanged,):
                    reader = None
                    continue
                reader = None
                if not key or key == "\x03":
                    interrupted = True
                    break
        if interrupted:
            out("^C\n")
        tail = spec["finish"](seq, int((time.monotonic() - started) * 1000))
        if tail:
            out(tail + "\n")
    finally:
        if reader is not None and not reader.done():
            reader.cancel()
        if not (process.stdout.is_closing() or chan.is_closing()):
            try:
                chan.set_echo(True)
                chan.set_line_mode(True)
            except Exception:
                pass


async def run(process, spec) -> None:
    """Draw `spec` until the attacker quits. The prompt is written by the caller."""
    if spec["kind"] == "stream":
        return await run_stream(process, spec)
    size = process.get_terminal_size() or (80, 24, 0, 0)
    width, height = size[0] or 80, size[1] or 24
    chan = process.channel
    chan.set_line_mode(False)
    chan.set_echo(False)
    process.stdout.write("\x1b[?1049h\x1b[?25l")
    sort, tick, reader = spec.get("sort", "cpu"), 0, None
    opts = dict(spec.get("opts") or {})
    spec["begin"]()
    try:
        while tick < _MAX_TICKS:
            if spec["kind"] == "top":
                text = await asyncio.to_thread(spec["frame"], tick, height, spec["delay"], sort,
                                               opts, width, True)
            else:
                text = await asyncio.to_thread(spec["frame"], tick, height, width, sort)
            lines = [l[:width] for l in text.split("\n")][:height]
            if process.stdout.is_closing() or chan.is_closing():
                break                              # the client is gone: draw nothing more
            try:
                process.stdout.write("\x1b[H" + "\x1b[K\r\n".join(lines) + "\x1b[K\x1b[J")
            except (BrokenPipeError, ConnectionError, asyncssh.Error):
                break
            tick += 1
            if spec.get("count") and tick >= spec["count"]:
                break
            if reader is None:
                reader = asyncio.ensure_future(process.stdin.read(1))
            done, _ = await asyncio.wait({reader}, timeout=spec["delay"])
            if not done:
                continue
            try:
                key = reader.result()
            except asyncssh.TerminalSizeChanged:
                size = process.get_terminal_size() or size
                width, height = size[0] or width, size[1] or height
                reader = None
                continue
            except asyncssh.BreakReceived:
                break
            reader = None
            if not key or key in ("q", "Q", "\x03", "\x04"):
                break
            if key in _SORT_KEYS and spec["kind"] == "top":
                sort = _SORT_KEYS[key]
            elif key in _TOGGLES and spec["kind"] == "top":
                opt = _TOGGLES[key]
                opts[opt] = not opts.get(opt, opt == "idle")
    finally:
        if reader is not None and not reader.done():
            reader.cancel()
        spec["end"]()
        if not (process.stdout.is_closing() or chan.is_closing()):
            try:
                process.stdout.write("\x1b[?25h\x1b[?1049l")
                chan.set_echo(True)
                chan.set_line_mode(True)
            except Exception:
                pass
