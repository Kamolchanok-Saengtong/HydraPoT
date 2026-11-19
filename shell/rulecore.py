"""
shell/rulecore.py — commands answered straight from the world-state.

Implements the rule core of Section IV-A in Gil et al., "OSCAR: Provably
Consistent LLM Honeypots via Ontology-Constrained Response Generation",
IEEE TDSC 2026 (DOI 10.1109/TDSC.2026.3749501): high-frequency commands whose
answer is a fact are rendered from the register, so sizes, modes, times,
inodes, links, variables and processes always agree with what the session
established. Output formats copy a real Ubuntu 20.04 host byte for byte.

Contract, as responders.py:
    -> (True,  output)  handled; this is the answer
    -> (False, None)    not determined by the world-state; route as before

A command is only answered when the register fully knows the answer; anything
touching paths it does not own falls through to Cowrie or a model. `patch`
then repairs those answers for listings and the process table.
"""
import math
import posixpath
import re
import shlex
from datetime import datetime, timezone

from shell.world import Fact

_SPECIAL = set("|;<>`")
_PS_NUMERIC = frozenset({"PID", "PPID", "%CPU", "%MEM", "VSZ", "RSS", "C"})
_LS_FLAGS = set("laA1h")


def _human(kib: int) -> str:
    size, unit = float(kib), "K"
    for nxt in ("M", "G", "T"):
        if size < 1024:
            break
        size, unit = size / 1024, nxt
    if unit == "K":
        return f"{int(size)}K" if kib else "0"
    return f"{size:.1f}{unit}" if size < 10 else f"{math.ceil(size)}{unit}"


def _apply_mode(spec: str, mode: int, is_dir: bool):
    """chmod's mode arithmetic: octal, or symbolic like u+x,go-w; None if unknown."""
    if re.fullmatch(r"[0-7]{3,4}", spec):
        return int(spec, 8)
    bits = {"r": 0o444, "w": 0o222, "x": 0o111}
    who_bits = {"u": 0o700, "g": 0o070, "o": 0o007, "a": 0o777}
    for clause in spec.split(","):
        m = re.fullmatch(r"([ugoa]*)([+=-])([rwxX]*)", clause)
        if not m:
            return None
        who, op, perms = m.groups()
        # No "who": everyone, minus what umask 022 would mask
        mask = sum(who_bits[w] for w in set(who)) if who else 0o777 & ~0o022
        change = 0
        for p in perms:
            if p == "X":
                if is_dir or mode & 0o111:
                    change |= 0o111
            else:
                change |= bits[p]
        change &= mask
        if op == "+":
            mode |= change
        elif op == "-":
            mode &= ~change
        else:
            mode = (mode & ~mask) | change
    return mode


def _hms(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


class RuleCore:
    """One session's fact-backed commands.

        rc = RuleCore(register, fs, hostname="psu", users=lambda: state["users"])
        rc.answer("stat key.pem")       -> (True, "  File: key.pem\\n  Size: ...")
    """

    def __init__(self, register, fs, hostname: str, users=None, variables=None,
                 username: str = "root", device: str = "801h/2049d",
                 processes=(), kernel: str = "5.15.0-generic", materializer=None):
        self.reg = register
        self.fs = fs
        self.hostname = hostname
        self.users = users or (lambda: {})
        self.variables = variables if variables is not None else {}
        self.username = username
        self.device = device
        self.changed = False          # the last answer changed the state
        self._jobs = 0
        self._next_pid = None
        self._started = {}            # pid -> spawn time (ns), for ps START
        # Base process table (Cowrie's data: VSZ/RSS bytes, TIME minutes)
        self.processes = sorted(processes, key=lambda p: p["PID"])
        self.kernel = kernel
        self.materializer = materializer

    @property
    def inst(self):
        return self.reg.inst

    # ── entry points ───────────────────────────────────────────────────────

    def answer(self, cmd: str):
        self.changed = False
        text = cmd.strip()
        # Same answer with or without sudo, as routing treats it (flags like -u differ)
        if text.startswith("sudo ") and not text[5:].lstrip().startswith("-"):
            text = text[5:].strip()
        if not text or _SPECIAL & set(text) or "$(" in text or "&&" in text:
            return False, None
        if text.endswith("&"):
            return self._spawn(text[:-1].strip())
        if "&" in text:
            return False, None
        m = re.fullmatch(r"echo\s+\$\{?(\w+)\}?", text)
        if m:
            return self._echo_var(m.group(1))
        if "$" in text:
            return False, None
        try:
            argv = shlex.split(text)
        except ValueError:
            return False, None
        handler = getattr(self, f"_cmd_{argv[0]}", None)
        return handler(argv) if handler else (False, None)

    def patch(self, cmd: str, output: str) -> str:
        """Repair an answer Cowrie or a model gave so it agrees with the register."""
        try:
            argv = shlex.split(cmd.strip())
        except ValueError:
            return output
        if argv[:1] == ["sudo"] and argv[1:2] and not argv[1].startswith("-"):
            argv = argv[1:]
        if not argv or _SPECIAL & set(cmd):
            return output
        if argv[0] == "ps":
            return self._patch_ps(output)
        if argv[0] == "ls":
            return self._patch_ls(argv, output)
        return output

    # ── what the register owns ─────────────────────────────────────────────

    def _resolve(self, arg: str) -> str:
        path = self.fs.resolve(arg)
        # Copy the path in from the filesystem design before judging it
        if self.materializer:
            self.materializer.ensure(path)
        return path

    def _kind(self, path):
        return self.inst.get("kind", path)

    def _closed(self, path) -> bool:
        """A directory whose full contents are known: attacker-made, or listed by
        the filesystem design."""
        while path:
            if self.inst.get("sealed", path) or self.inst.get("profiled", path):
                return True
            if path == "/":
                return False
            path = posixpath.dirname(path)
        return False

    def _owned(self, path) -> bool:
        kind = self._kind(path)
        if kind == "symlink":
            return True
        if kind == "file":
            return (self.inst.get("content", path) is not None
                    or self.inst.get("psize", path) is not None)
        if kind == "dir":
            return self._closed(path)
        return False

    def _missing(self, path) -> bool:
        """Known not to exist: denied before, or under a directory we fully know."""
        return (self.inst.get("absent", path) is not None
                or (self._kind(path) is None and self._closed(posixpath.dirname(path))))

    def _children(self, directory):
        if self.materializer:
            self.materializer.ensure_children(directory)
        prefix = directory.rstrip("/") + "/"
        return sorted({p[len(prefix):].split("/")[0] for p in self.inst.keys("kind")
                       if p.startswith(prefix) and p != directory},
                      key=lambda n: n.lower().lstrip("."))

    def _target(self, path, depth=0):
        """Follow symlinks to the real path, or None if dangling."""
        if depth > 8:
            return None
        if self._kind(path) != "symlink":
            return path if self._kind(path) else None
        link = self.inst.get("target", path)
        nxt = posixpath.normpath(posixpath.join(posixpath.dirname(path), link))
        if self.materializer:
            self.materializer.ensure(nxt)
        return self._target(nxt, depth + 1)

    # ── metadata ───────────────────────────────────────────────────────────

    def _size(self, path) -> int:
        kind = self._kind(path)
        if kind == "dir":
            return 4096
        if kind == "symlink":
            return len(self.inst.get("target", path) or "")
        if self.inst.get("content", path) is None and self.inst.get("psize", path) is not None:
            return self.inst.get("psize", path)
        return len(self.inst.get("content", path) or b"")

    def _blocks_1k(self, path) -> int:
        kind = self._kind(path)
        if kind == "dir":
            return 4
        if kind == "symlink":
            return 0
        return math.ceil(self._size(path) / 4096) * 4

    def _links(self, path) -> int:
        if self._kind(path) != "dir":
            return 1
        prefix = path.rstrip("/") + "/"
        subdirs = sum(1 for p in self.inst.keys("kind") if p.startswith(prefix)
                      and "/" not in p[len(prefix):] and self._kind(p) == "dir")
        return 2 + subdirs

    def _perms(self, path) -> str:
        from shell.register import mode_to_perms
        kind = self._kind(path)
        mode = 0o777 if kind == "symlink" else self.inst.get("mode", path)
        return mode_to_perms(kind, mode if mode is not None else 0o644)

    def _owner(self, path):
        owner = self.inst.get("owner", path) or "root"
        return owner, self.inst.get("group", path) or owner

    def _uid(self, name) -> int:
        if name in self.users():
            return int(self.users()[name].get("uid", 0))
        return self._design_id(name, "users")

    def _gid(self, name) -> int:
        if name in self.users():
            return int(self.users()[name].get("gid", 0))
        return self._design_id(name, "groups")

    def _design_id(self, name, table) -> int:
        """Accounts only the filesystem design's /etc/passwd or /etc/group names."""
        names = getattr(self.materializer, table, None) or {}
        return next((i for i, n in names.items() if n == name), 0)

    def _when(self, path, rel="mtime") -> datetime:
        self.reg.ensure_meta(path)
        ns = self.inst.get(rel, path)
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)

    def _stat_time(self, path, rel) -> str:
        self.reg.ensure_meta(path)
        ns = self.inst.get(rel, path)
        dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
        return f"{dt:%Y-%m-%d %H:%M:%S}.{ns % 1_000_000_000:09d} +0000"

    def _ls_date(self, path) -> str:
        dt = self._when(path)
        now = datetime.fromtimestamp(self.reg.now_ns() / 1e9, tz=timezone.utc)
        recent = abs((now - dt).days) < 182
        tail = f"{dt:%H:%M}" if recent else f" {dt:%Y}"
        return f"{dt:%b} {dt.day:>2} {tail}"

    # ── ls ─────────────────────────────────────────────────────────────────

    def _cmd_ls(self, argv):
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
        args = [a for a in argv[1:] if not a.startswith("-")]
        if set(flags) - _LS_FLAGS or len(args) > 1:
            return False, None
        arg = args[0] if args else "."
        path = self._resolve(arg if args else self.reg.cwd())
        if self._missing(path):
            return True, f"ls: cannot access '{arg}': No such file or directory"
        if not self._owned(path):
            return False, None
        long, show_all = "l" in flags, "a" in flags or "A" in flags
        if self._kind(path) != "dir":
            return True, self._long([(arg, path)]) if long else arg
        names = self._children(path)
        entries = [(n, posixpath.join(path, n)) for n in names
                   if show_all or not n.startswith(".")]
        if "a" in flags:
            entries = [(".", path), ("..", posixpath.dirname(path) or "/")] + entries
        if not long:
            return True, "  ".join(name for name, _ in entries)
        total = sum(self._blocks_1k(p) for _, p in entries)
        body = self._long(entries)
        return True, f"total {total}" + (f"\n{body}" if body else "")

    def _long(self, entries) -> str:
        rows = []
        for name, path in entries:
            owner, group = self._owner(path)
            label = name
            if self._kind(path) == "symlink":
                label += f" -> {self.inst.get('target', path)}"
            rows.append((self._perms(path), str(self._links(path)), owner, group,
                         str(self._size(path)), self._ls_date(path), label))
        if not rows:
            return ""
        widths = [max(len(r[i]) for r in rows) for i in range(5)]
        return "\n".join(
            f"{r[0]} {r[1]:>{widths[1]}} {r[2]:<{widths[2]}} {r[3]:<{widths[3]}} "
            f"{r[4]:>{widths[4]}} {r[5]} {r[6]}" for r in rows)

    # ── stat / wc / du / cat ───────────────────────────────────────────────

    def _cmd_stat(self, argv):
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) != 1 or len(argv) != 2:
            return False, None
        arg, path = args[0], self._resolve(args[0])
        if self._missing(path):
            return True, f"stat: cannot stat '{arg}': No such file or directory"
        if not self._owned(path):
            return False, None
        self.reg.ensure_meta(path)
        kind, size = self._kind(path), self._size(path)
        typ = {"dir": "directory", "symlink": "symbolic link"}.get(
            kind, "regular file" if size else "regular empty file")
        blocks = {"dir": 8, "symlink": 0}.get(kind, math.ceil(size / 4096) * 8)
        title = arg + (f" -> {self.inst.get('target', path)}" if kind == "symlink" else "")
        perms = self._perms(path)
        mode = 0o777 if kind == "symlink" else self.inst.get("mode", path) or 0o644
        owner, group = self._owner(path)
        return True, "\n".join([
            f"  File: {title}",
            f"  Size: {size:<10}\tBlocks: {blocks:<10} IO Block: 4096   {typ}",
            f"Device: {self.device}\tInode: {self.inst.get('inode', path):<10}  "
            f"Links: {self._links(path)}",
            f"Access: ({mode & 0o7777:04o}/{perms})  Uid: ({self._uid(owner):>5}/{owner:>8})"
            f"   Gid: ({self._gid(group):>5}/{group:>8})",
            f"Access: {self._stat_time(path, 'atime')}",
            f"Modify: {self._stat_time(path, 'mtime')}",
            f"Change: {self._stat_time(path, 'ctime')}",
            " Birth: -",
        ])

    def _cmd_wc(self, argv):
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
        args = [a for a in argv[1:] if not a.startswith("-")]
        if set(flags) - set("lwc") or len(args) != 1:
            return False, None
        arg, path = args[0], self._resolve(args[0])
        if self._missing(path):
            return True, f"wc: {arg}: No such file or directory"
        real = self._target(path)
        if real is None or self._kind(real) != "file" or not self._owned(real):
            return False, None
        data = self.inst.get("content", real)
        if data is None:          # size known, bytes not: let Cowrie answer
            return False, None
        counts = {"l": data.count(b"\n"), "w": len(data.split()), "c": len(data)}
        fields = [counts[f] for f in "lwc" if f in (flags or "lwc")]
        width = len(str(len(data))) if len(fields) > 1 else 1
        return True, " ".join(f"{n:>{width}}" for n in fields) + f" {arg}"

    def _cmd_du(self, argv):
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
        args = [a for a in argv[1:] if not a.startswith("-")]
        if set(flags) - set("bsh") or len(args) != 1:
            return False, None
        arg, path = args[0], self._resolve(args[0])
        if self._missing(path):
            return True, f"du: cannot access '{arg}': No such file or directory"
        if not self._owned(path):
            return False, None
        apparent = "b" in flags

        def usage(p):
            return self._size(p) if apparent else self._blocks_1k(p)

        def fmt(n):
            return _human(n) if "h" in flags and not apparent else str(n)

        if self._kind(path) != "dir":
            return True, f"{fmt(usage(path))}\t{arg}"
        lines, totals = [], {}
        for sub in sorted(self._subtree(path), key=lambda p: -p.count("/")):
            total = usage(sub) + sum(totals.get(posixpath.join(sub, c), 0) if
                                     self._kind(posixpath.join(sub, c)) == "dir"
                                     else usage(posixpath.join(sub, c))
                                     for c in self._children(sub))
            totals[sub] = total
            if "s" not in flags or sub == path:
                shown = arg if sub == path else posixpath.join(arg, posixpath.relpath(sub, path))
                lines.append(f"{fmt(total)}\t{shown}")
        return True, "\n".join(lines)

    def _subtree(self, path):
        prefix = path.rstrip("/") + "/"
        return [path] + [p for p in self.inst.keys("kind")
                         if p.startswith(prefix) and self._kind(p) == "dir"]

    def _cmd_cat(self, argv):
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) != 1 or len(argv) != 2:
            return False, None
        arg, path = args[0], self._resolve(args[0])
        if self._missing(path):
            return True, f"cat: {arg}: No such file or directory"
        if self._kind(path) == "dir" and self._closed(path):
            return True, f"cat: {arg}: Is a directory"
        real = self._target(path)
        if self._kind(path) == "symlink" and real is None:
            return True, f"cat: {arg}: No such file or directory"
        if real is None or self._kind(real) != "file" or not self._owned(real):
            return False, None
        data = self.inst.get("content", real)
        if data is None:          # size known, bytes not: let Cowrie answer
            return False, None
        if b"\x00" in data:
            return False, None
        return True, data.decode("utf-8", "replace").rstrip("\n")

    # ── cwd and modes ──────────────────────────────────────────────────────

    def _cmd_pwd(self, argv):
        if len(argv) != 1 or not self.reg.cwd():
            return False, None
        return True, self.reg.cwd()

    def _cmd_chmod(self, argv):
        if len(argv) != 3 or argv[1].startswith("-"):
            return False, None
        spec, arg = argv[1], argv[2]
        path = self._resolve(arg)
        if self._missing(path):
            return True, f"chmod: cannot access '{arg}': No such file or directory"
        real = self._target(path)
        if real is None or self._kind(real) is None or self.inst.get("mode", real) is None:
            return False, None
        old = self.inst.get("mode", real)
        new = _apply_mode(spec, old, self._kind(real) == "dir")
        if new is None:
            return False, None
        if new != old:
            now = self.reg.now_ns()
            remove = {Fact("mode", real, old)}
            if self.inst.get("ctime", real) is not None:
                remove.add(Fact("ctime", real, self.inst.get("ctime", real)))
            self.reg.commit({Fact("mode", real, new), Fact("ctime", real, now)},
                            remove, why=f"chmod {spec} {arg}")
            self.changed = True
        return True, ""

    # ── reading files: head / tail / grep ──────────────────────────────────

    def _text_of(self, arg, tool):
        """(handled, lines-or-error) for a file the register holds."""
        path = self._resolve(arg)
        if self._missing(path):
            return True, None, f"{tool}: cannot open '{arg}' for reading: No such file or directory"
        real = self._target(path)
        if real is None or self._kind(real) != "file" or not self._owned(real):
            return False, None, None
        data = self.inst.get("content", real)
        if data is None:          # size known, bytes not: let Cowrie answer
            return False, None, None
        if b"\x00" in data:
            return False, None, None
        text = data.decode("utf-8", "replace")
        body = text[:-1] if text.endswith("\n") else text
        return True, (body.split("\n") if body else []), None

    def _head_tail(self, argv, tail):
        n, files, args, i = 10, [], argv[1:], 0
        while i < len(args):
            a = args[i]
            if a == "-n" and i + 1 < len(args) and args[i + 1].isdigit():
                n, i = int(args[i + 1]), i + 2
                continue
            m = re.fullmatch(r"-n?(\d+)", a)
            if m:
                n, i = int(m.group(1)), i + 1
                continue
            if a.startswith("-"):
                return False, None
            files.append(a)
            i += 1
        if len(files) != 1:
            return False, None
        handled, lines, err = self._text_of(files[0], argv[0])
        if not handled:
            return False, None
        if err:
            return True, err
        return True, "\n".join(lines[-n:] if tail and n else lines[:n])

    def _cmd_head(self, argv):
        return self._head_tail(argv, tail=False)

    def _cmd_tail(self, argv):
        return self._head_tail(argv, tail=True)

    def _cmd_grep(self, argv):
        flags, args = set(), []
        for a in argv[1:]:
            if a.startswith("-") and len(a) > 1 and not args:
                flags |= set(a[1:])
            else:
                args.append(a)
        if flags - set("ivcnF") or len(args) != 2:
            return False, None
        pattern, arg = args
        path = self._resolve(arg)
        if self._missing(path):
            return True, f"grep: {arg}: No such file or directory"
        handled, lines, _ = self._text_of(arg, "grep")
        if not handled or lines is None:
            return False, None
        if "F" in flags:
            needle = pattern.lower() if "i" in flags else pattern
            hit = lambda line: needle in (line.lower() if "i" in flags else line)
        else:
            try:
                rx = re.compile(pattern, re.I if "i" in flags else 0)
            except re.error:
                return False, None
            hit = lambda line: rx.search(line) is not None
        matched = [(i + 1, line) for i, line in enumerate(lines)
                   if hit(line) != ("v" in flags)]
        if "c" in flags:
            return True, str(len(matched))
        return True, "\n".join(f"{i}:{line}" if "n" in flags else line for i, line in matched)

    # ── this login: who / w / last / uptime / auth.log ─────────────────────

    def _dt(self, ns):
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)

    def _syslog(self, ns):
        dt = self._dt(ns)
        return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} {self.hostname}"

    def _boot_ns(self) -> int:
        """Boot time agrees with ps: pid 1's START, at a seeded hour."""
        now = self._dt(self.reg.now_ns())
        first = next((p for p in self.processes if p["PID"] == 1), None)
        if first:
            try:
                day = datetime.strptime(f"{now.year} {first['START']}", "%Y %b%d").replace(
                    tzinfo=timezone.utc, hour=self.reg.prf("boot_h", "boot", 0, 23),
                    minute=self.reg.prf("boot_m", "boot", 0, 59))
                if day > now:
                    day = day.replace(year=now.year - 1)
                return int(day.timestamp() * 1e9)
            except ValueError:
                pass
        return self.reg.epoch_ns - self.reg.prf("uptime", "boot", 3, 200) * 86_400 * 10**9

    def _uptime_line(self) -> str:
        now = self._dt(self.reg.now_ns())
        delta = now - self._dt(self._boot_ns())
        h, m = divmod(delta.seconds // 60, 60)
        up = (f"{delta.days} day{'s' if delta.days != 1 else ''}, {h:2d}:{m:02d}"
              if delta.days else f"{h:2d}:{m:02d}")
        loads = [self.reg.prf(f"load{i}", "load", 0, 30) / 100 for i in range(3)]
        users = 1 if self.reg.session("ip") is not None else 0
        return (f" {now:%H:%M:%S} up {up},  {users} user{'s' if users != 1 else ''},  "
                f"load average: {loads[0]:.2f}, {loads[1]:.2f}, {loads[2]:.2f}")

    def _cmd_uptime(self, argv):
        return (True, self._uptime_line()) if len(argv) == 1 else (False, None)

    def _cmd_who(self, argv):
        if len(argv) != 1 or self.reg.session("ip") is None:
            return False, None
        dt = self._dt(self.reg.session("login_ns"))
        return True, (f"{self.reg.session('user'):<8} {self.reg.session('tty'):<12} "
                      f"{dt:%Y-%m-%d %H:%M} ({self.reg.session('ip')})")

    def _cmd_w(self, argv):
        if len(argv) != 1 or self.reg.session("ip") is None:
            return False, None
        dt = self._dt(self.reg.session("login_ns"))
        return True, "\n".join([
            self._uptime_line(),
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT",
            f"{self.reg.session('user'):<8} {self.reg.session('tty'):<8} "
            f"{self.reg.session('ip'):<16} {dt:%H:%M}   {'0.00s':>6} {'0.04s':>6} {'0.00s':>6} w"])

    def _cmd_last(self, argv):
        if len(argv) != 1 or self.reg.session("ip") is None:
            return False, None
        login, boot = self._dt(self.reg.session("login_ns")), self._dt(self._boot_ns())

        def when(dt):
            return f"{dt:%a %b} {dt.day:>2} {dt:%H:%M}"
        return True, "\n".join([
            f"{self.reg.session('user'):<8} {self.reg.session('tty'):<12} "
            f"{self.reg.session('ip'):<16} {when(login)}   still logged in",
            f"{'reboot':<8} {'system boot':<12} {self.kernel[:16]:<16} {when(boot)}   still running",
            "",
            f"wtmp begins {boot:%a %b} {boot.day:>2} {boot:%H:%M:%S %Y}"])

    def live_lines(self, path: str) -> bytes:
        """Lines this session added to a log: the login, then sudo events."""
        if path != "/var/log/auth.log" or self.reg.session("ip") is None:
            return b""
        stamp, pid = self._syslog(self.reg.session("login_ns")), self.reg.session("sshd_pid")
        user, ip = self.reg.session("user"), self.reg.session("ip")
        logind = next((p["PID"] for p in self.processes
                       if "systemd-logind" in p["COMMAND"]), None) or self.reg.prf(
                           "logind_pid", "boot", 500, 900)
        lines = [f"{stamp} sshd[{pid}]: Accepted password for {user} from {ip} "
                 f"port {self.reg.session('port')} ssh2",
                 f"{stamp} sshd[{pid}]: pam_unix(sshd:session): session opened for user "
                 f"{user} by (uid=0)",
                 f"{stamp} systemd-logind[{logind}]: New session "
                 f"{self.reg.session('logind_session')} of user {user}."]
        lines += [self.inst.get("event", k) for k in sorted(self.inst.keys("event"))]
        return ("\n".join(lines) + "\n").encode()

    def note_sudo(self, command: str) -> None:
        """A real sudo logs to auth.log; record it, and append if the log exists."""
        try:
            argv = shlex.split(command)
        except ValueError:
            return
        if not argv:
            return
        exe = argv[0] if "/" in argv[0] else f"/usr/bin/{argv[0]}"
        stamp, user = self._syslog(self.reg.now_ns()), self.reg.session("user", "root")
        lines = [f"{stamp} sudo: {user:>8} : TTY={self.reg.session('tty', 'pts/0')} ; "
                 f"PWD={self.reg.cwd()} ; USER=root ; COMMAND={' '.join([exe] + argv[1:])}",
                 f"{stamp} sudo: pam_unix(sudo:session): session opened for user root by "
                 f"{user}(uid=0)",
                 f"{stamp} sudo: pam_unix(sudo:session): session closed for user root"]
        base = (self.reg.seq + 1) * 10
        self.reg.commit({Fact("event", base + i, line) for i, line in enumerate(lines)},
                        why="sudo")
        log = "/var/log/auth.log"
        old = self.inst.get("content", log)
        if old is None:
            return
        new = old + ("\n".join(lines) + "\n").encode()
        remove = {Fact(r, log, self.inst.get(r, log)) for r in ("content", "size", "mtime")
                  if self.inst.get(r, log) is not None}
        self.reg.commit({Fact("content", log, new), Fact("size", log, len(new)),
                         Fact("mtime", log, self.reg.now_ns())}, remove, why="sudo log")

    # ── links ──────────────────────────────────────────────────────────────

    def _cmd_ln(self, argv):
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
        args = [a for a in argv[1:] if not a.startswith("-")]
        if flags not in ("s", "sf") or len(args) != 2:
            return False, None
        target, link = args
        path = self._resolve(link)
        if self._kind(path) == "dir":
            path = posixpath.join(path, posixpath.basename(target))
        if self._kind(path) is not None:
            if "f" not in flags:
                return True, f"ln: failed to create symbolic link '{link}': File exists"
            self.reg.delete_record(path)
        now = self.reg.now_ns()
        facts = {Fact("kind", path, "symlink"), Fact("target", path, target),
                 Fact("mode", path, 0o777), Fact("listed", path),
                 Fact("size", path, len(target)),
                 Fact("inode", path, self.reg.new_inode(path))}
        facts |= {Fact(rel, path, now) for rel in ("mtime", "atime", "ctime")}
        if not self.reg.commit(facts, why=f"ln -s {target} {link}"):
            return False, None
        self.changed = True
        return True, ""

    def _cmd_readlink(self, argv):
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
        args = [a for a in argv[1:] if not a.startswith("-")]
        if set(flags) - set("f") or len(args) != 1:
            return False, None
        path = self._resolve(args[0])
        kind = self._kind(path)
        if kind is None:
            return (True, "") if self._missing(path) else (False, None)
        if "f" in flags:
            real = self._target(path)
            return (True, real) if real else (False, None)
        if kind == "symlink":
            return True, self.inst.get("target", path)
        return True, ""

    # ── variables ──────────────────────────────────────────────────────────

    def _cmd_export(self, argv):
        pairs = [a for a in argv[1:] if not a.startswith("-")]
        if not pairs or not all(re.fullmatch(r"\w+=.*", a, re.S) for a in pairs):
            return False, None
        for pair in pairs:
            name, value = pair.split("=", 1)
            cur = self.inst.get("env", name)
            remove = {Fact("env", name, cur)} if cur is not None else set()
            self.reg.commit({Fact("env", name, value)}, remove, why=f"export {name}")
            self.variables[name] = value
        self.changed = True
        return True, ""

    def _value(self, name):
        if self.inst.get("env", name) is not None:
            return self.inst.get("env", name)
        if name in self.variables:
            return self.variables[name]
        home = (self.users().get(self.username) or {}).get("home", "/root")
        return {"HOME": home, "USER": self.username, "LOGNAME": self.username,
                "PWD": self.reg.cwd(), "SHELL": "/bin/bash",
                "HOSTNAME": self.hostname}.get(name)

    def _cmd_printenv(self, argv):
        if len(argv) != 2:
            return False, None
        value = self._value(argv[1])
        if value is None:
            # An unset variable prints nothing; only claim it when we set others
            return (True, "") if self.inst.keys("env") else (False, None)
        return True, value

    def _echo_var(self, name):
        value = self._value(name)
        if value is None:
            return (True, "") if self.inst.keys("env") else (False, None)
        return True, value

    # ── processes ──────────────────────────────────────────────────────────

    def _spawn(self, command: str):
        try:
            argv = shlex.split(command)
        except ValueError:
            return False, None
        if not argv or argv[0] not in ("sleep", "nohup"):
            return False, None
        self._jobs += 1
        pid = self._new_pid()
        self._started[pid] = self.reg.now_ns()
        self.reg.commit({Fact("proc", pid, command)}, why=f"spawn {command}")
        self.changed = True
        return True, f"[{self._jobs}] {pid}"

    def _new_pid(self) -> int:
        """PIDs only grow, starting above the base table, like a real kernel."""
        if self._next_pid is None:
            top = max([p["PID"] for p in self.processes] + [self._shell_pid()])
            self._next_pid = top + self.reg.prf("pid", "session", 100, 900)
        self._next_pid += self.reg.prf("pidstep", str(self._next_pid), 1, 3)
        return self._next_pid

    def _shell_pid(self) -> int:
        pid = self.reg.session("shell_pid")
        if pid is None:
            top = max([p["PID"] for p in self.processes] or [1000])
            pid = top + self.reg.prf("shellpid", "session", 1, 99)
        return pid

    def _rows(self, me: str):
        """The process table: base, the login shell, jobs, then this ps."""
        def hhmm(ns):
            return f"{datetime.fromtimestamp(ns / 1e9, tz=timezone.utc):%H:%M}"

        rows = []
        for p in self.processes:
            minutes = float(p.get("TIME") or 0)
            rows.append({"user": p["USER"], "pid": p["PID"], "ppid": 2 if
                         p["COMMAND"].startswith("[") else 1,
                         "cpu": float(p.get("CPU") or 0), "mem": float(p.get("MEM") or 0),
                         "vsz": int(p.get("VSZ") or 0) // 1024,
                         "rss": int(p.get("RSS") or 0) // 1024, "tty": p["TTY"],
                         "stat": p["STAT"], "start": p["START"],
                         "time": int(minutes * 60), "cmd": p["COMMAND"].rstrip()})
        shell = self._shell_pid()
        sshd = self.reg.session("sshd_pid")
        if sshd is not None:
            rows.append({"user": self.username, "pid": sshd, "ppid": 1, "cpu": 0.0,
                         "mem": 0.2, "vsz": 13788, "rss": 8964, "tty": "?",
                         "stat": "Ss", "start": hhmm(self.reg.epoch_ns), "time": 0,
                         "cmd": f"sshd: {self.username}@{self.reg.session('tty', 'pts/0')}"})
        rows.append({"user": self.username, "pid": shell, "ppid": sshd or 1, "cpu": 0.0,
                     "mem": 0.1, "vsz": 10036, "rss": 5136, "tty": "pts/0",
                     "stat": "Ss", "start": hhmm(self.reg.epoch_ns), "time": 0,
                     "cmd": "-bash"})
        for pid in sorted(self.inst.keys("proc")):
            cmd = self.inst.get("proc", pid)
            small = cmd.split()[0] == "sleep"
            rows.append({"user": self.username, "pid": pid, "ppid": shell, "cpu": 0.0,
                         "mem": 0.0, "vsz": 2516 if small else 7228,
                         "rss": 576 if small else 1820, "tty": "pts/0", "stat": "S",
                         "start": hhmm(self._started.get(pid, self.reg.now_ns())),
                         "time": 0, "cmd": cmd})
        rows.append({"user": self.username, "pid": self._new_pid(), "ppid": shell,
                     "cpu": 0.0, "mem": 0.0, "vsz": 5900, "rss": 2828, "tty": "pts/0",
                     "stat": "R+", "start": hhmm(self.reg.now_ns()), "time": 0,
                     "cmd": me})
        return rows

    def _cmd_ps(self, argv):
        style = " ".join(argv[1:])
        if style not in ("", "aux", "-aux", "-ef", "-e", "-A", "ax"):
            return False, None
        rows = self._rows(" ".join(argv))
        if style == "":
            mine = [r for r in rows if r["tty"] == "pts/0"]
            return True, "\n".join(["    PID TTY          TIME CMD"] + [
                f"{r['pid']:>7} {r['tty']:<8} {_hms(r['time'])} {posixpath.basename(r['cmd'].split()[0]).lstrip('-')}"
                for r in mine])
        if style in ("-ef", "-e", "-A"):
            return True, "\n".join(["UID          PID    PPID  C STIME TTY          TIME CMD"] + [
                f"{r['user']:<8} {r['pid']:>7} {r['ppid']:>7} {0:>2} {r['start']:>5} "
                f"{r['tty']:<8} {_hms(r['time'])} {r['cmd']}" for r in rows])
        return True, "\n".join(["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"] + [
            f"{r['user'][:8]:<8} {r['pid']:>7} {r['cpu']:>4.1f} {r['mem']:>4.1f} "
            f"{r['vsz']:>6} {r['rss']:>5} {r['tty']:<8} {r['stat']:<4} {r['start']:>5} "
            f"{r['time'] // 60:>3}:{r['time'] % 60:02d} {r['cmd']}" for r in rows])

    def _cmd_kill(self, argv):
        pids = [a for a in argv[1:] if a.isdigit()]
        if not pids or len(pids) != len(argv) - 1:
            return False, None
        out = []
        for pid in map(int, pids):
            cmd = self.inst.get("proc", pid)
            if cmd is None:
                return False, None
            self.reg.commit(remove={Fact("proc", pid, cmd)}, why=f"kill {pid}")
        self.changed = True
        return True, "\n".join(out)

    def _patch_ps(self, output: str) -> str:
        procs = sorted(self.inst.keys("proc"))
        lines = output.splitlines()
        if not procs or not lines or "PID" not in lines[0]:
            return output
        header = lines[0]
        cols = [(m.start(), m.group()) for m in re.finditer(r"\S+", header)]
        now = datetime.fromtimestamp(self.reg.now_ns() / 1e9, tz=timezone.utc)
        for pid in procs:
            if re.search(rf"(?<!\d){pid}(?!\d)", output):
                continue
            values = {"USER": "root", "UID": "root", "PID": str(pid), "PPID": "1",
                      "%CPU": "0.0", "%MEM": "0.0", "C": "0", "VSZ": "7228",
                      "RSS": "580", "TTY": "pts/0", "STAT": "S", "STIME": f"{now:%H:%M}",
                      "START": f"{now:%H:%M}", "TIME": "0:00",
                      "COMMAND": self.inst.get("proc", pid), "CMD": self.inst.get("proc", pid)}
            row = ""
            for start, title in cols:
                value = values.get(title, "-")
                if title in _PS_NUMERIC:
                    # Numbers end where their header ends, as in real ps
                    end = start + len(title)
                    row = row.ljust(max(len(row) + 1, end - len(value))) + value
                else:
                    row = row.ljust(max(len(row) + 1 if row else 0, start)) + value
            lines.append(row.rstrip())
        return "\n".join(lines)

    def _patch_ls(self, argv, output: str) -> str:
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
        args = [a for a in argv[1:] if not a.startswith("-")]
        if set(flags) - _LS_FLAGS or len(args) > 1:
            return output
        path = self._resolve(args[0] if args else self.reg.cwd())
        if self._kind(path) != "dir" or self._closed(path):
            return output
        ours = [n for n in self._children(path)
                if (self.inst.get("listed", posixpath.join(path, n))
                    or self._kind(posixpath.join(path, n)) == "symlink")
                and (not n.startswith(".") or set(flags) & {"a", "A"})]
        if "l" in flags:
            gone = {posixpath.basename(p) for p in self.inst.keys("absent")
                    if posixpath.dirname(p) == path}
            kept = [line for line in output.splitlines()
                    if line.split()[-1:] and line.split()[-1] not in gone]
            shown = {line.split()[-1] for line in kept if line.split()}
            extra = [(n, posixpath.join(path, n)) for n in ours if n not in shown]
            return "\n".join(kept + ([self._long(extra)] if extra else []))
        names = [n for n in output.split()
                 if not (n.startswith("-") and self._kind(posixpath.join(path, n)) is None)
                 and self.inst.get("absent", posixpath.join(path, n)) is None]
        for n in ours:
            if n not in names:
                names.append(n)
        names.sort(key=lambda n: n.lower().lstrip("."))
        return "  ".join(names)
