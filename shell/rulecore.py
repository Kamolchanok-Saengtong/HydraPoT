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
import fnmatch
import math
import posixpath
import re
import shlex
from datetime import datetime, timezone

from shell.compound import failed as _printed_an_error
from shell.world import Fact

_SPECIAL = set("|;<>`")
# Facts that describe the world rather than one path
_NON_PATH_RELS = frozenset({"session", "event", "env", "proc", "cwd", "user", "uid", "gid", "home", "shell"})
_PS_NUMERIC = frozenset({"PID", "PPID", "%CPU", "%MEM", "VSZ", "RSS", "C"})
_LS_FLAGS = set("laA1hd")
# Kernel-provided trees: a write there is not a file in a directory
_VIRTUAL = ("/proc", "/sys", "/dev", "/run")


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
        # Cowrie-safe commands that reproduce the last answer's change in Cowrie's own
        # filesystem: absolute quoted paths, no -p or ~ (Cowrie's mkdir lacks both)
        self.sync_cmds = []
        # Exit status of the last answer, for `&&` and `||`: None until a handler sets
        # it, then read back from the output; handled_last says the answer was ours
        self.status = None
        self.handled_last = False

    @property
    def inst(self):
        return self.reg.inst

    # ── entry points ───────────────────────────────────────────────────────

    def _replay(self, *cmds):
        self.sync_cmds.extend(cmds)

    def answer(self, cmd: str):
        self.changed = False
        self.sync_cmds = []
        self.status = None
        handled, out = self._answer(cmd)
        self.handled_last = handled
        if handled and self.status is None:
            self.status = 1 if _printed_an_error(out) else 0
        return handled, out

    def _answer(self, cmd: str):
        text = cmd.strip()
        # Same answer with or without sudo, as routing treats it (flags like -u differ)
        if text.startswith("sudo ") and not text[5:].lstrip().startswith("-"):
            text = text[5:].strip()
        quiet = False
        stderr = re.search(r"\s+2>\s*/dev/null\s*$", text)
        if stderr:                       # the shell discards stderr: errors never print
            text, quiet = text[:stderr.start()], True
        redirect = self._redirect(text)
        if redirect is not None:
            return redirect
        # operators only count outside quotes: `bash -c 'a && b'` is one command
        bare = re.sub(r"""'[^']*'|"(?:[^"\\]|\\.)*\"""", "", text)
        if not text or _SPECIAL & set(bare) or "$(" in text or "&&" in bare:
            return False, None
        if text.endswith("&"):
            return self._spawn(text[:-1].strip())
        if "&" in bare:
            return False, None
        m = re.fullmatch(r"echo\s+\$\{?(\w+)\}?", text)
        if m:
            return self._echo_var(m.group(1))
        if "$" in text:
            return False, None
        words = self._words(text)
        if not words:
            return False, None
        argv = self._expand(words)
        if argv is None or not argv:
            return False, None
        if "/" in argv[0]:
            return self._run_path(argv)
        handler = getattr(self, f"_cmd_{argv[0]}", None)
        if not handler:
            return False, None
        handled, out = handler(argv)
        if handled and quiet and out:
            out = "\n".join(l for l in out.split("\n") if not l.startswith(f"{argv[0]}: "))
        return handled, out

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

    _WORD = re.compile(r"""(?:'[^']*'|"(?:[^"\\]|\\.)*"|\\.|[^\s'"\\])+""")

    def _words(self, text):
        """[(value, quoted)]: shlex's words, plus whether the shell would expand them."""
        out = []
        for m in self._WORD.finditer(text):
            raw = m.group(0)
            try:
                value = shlex.split(raw)[0]
            except (ValueError, IndexError):
                return None
            out.append((value, any(c in raw for c in "'\"\\")))
        return out

    def _expand(self, words):
        """What the shell does before a command runs: ~ and one-level globs.

        Quoted words are left alone. None when a glob names a directory the
        register does not fully know.
        """
        out = [words[0][0] if words[0][1] else self._tilde(words[0][0])]
        for arg, quoted in words[1:]:
            if quoted:
                out.append(arg)
                continue
            arg = self._tilde(arg)
            if arg.startswith("-") or not any(c in arg for c in "*?["):
                out.append(arg)
                continue
            only_dirs = arg.endswith("/")
            head, pattern = posixpath.split(arg.rstrip("/"))
            if any(c in head for c in "*?["):
                return None
            directory = self._resolve(head) if head else self.reg.cwd()
            if self._kind(directory) != "dir" or not self._closed(directory):
                return None
            names = [n for n in self._children(directory)
                     if pattern.startswith(".") or not n.startswith(".")]
            hits = sorted(fnmatch.filter(names, pattern),
                          key=lambda n: n.lower().lstrip("."))
            if only_dirs:                     # `*/` matches directories only
                hits = [n for n in hits if self._kind(posixpath.join(directory, n)) == "dir"]
            suffix = "/" if only_dirs else ""
            # an unmatched pattern stays literal, as in bash
            out += [posixpath.join(head, n) + suffix if head else n + suffix for n in hits] or [arg]
        return out

    _BIN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin")

    def _run_path(self, argv):
        """`./x`, `/tmp/x`, `/bin/ls`: a command named by path."""
        path = self._resolve(argv[0])
        if self._virtual(path):
            return False, None
        handler = getattr(self, f"_cmd_{posixpath.basename(path)}", None)
        if posixpath.dirname(path) in self._BIN_DIRS and handler:
            return handler([posixpath.basename(path)] + argv[1:])
        if self._kind(path) is None and self._missing(path):
            self.status = 127
            return True, f"bash: {argv[0]}: No such file or directory"
        if self._kind(path) == "file":
            return self._script(path, " ".join(argv))
        return False, None

    # ── scripts: run only what every line of can be answered ───────────────

    _depth = 0

    def _script(self, path, shown):
        """Run a shell script held in the register, or None-answer if any line is beyond us."""
        data = self.inst.get("content", self._target(path) or path)
        if data is None or b"\x00" in data or self._depth >= 5:
            return False, None
        text = data.decode("utf-8", "replace")
        first = text.splitlines()[0] if text else ""
        if first.startswith("#!") and not re.match(r"#!\s*(/usr)?/bin/(env\s+)?(ba)?sh\b", first):
            return False, None                    # another interpreter
        return self._run_lines(text.splitlines())

    def _run_lines(self, lines):
        lines = [l.strip() for l in lines]
        lines = [l for l in lines if l and not l.startswith("#")]
        point = (self.reg.checkpoint(), self._jobs, self._next_pid, dict(self._started),
                 self.changed, list(self.sync_cmds))
        self._depth += 1
        outs, status = [], 0
        try:
            for line in lines:
                if line == "exit" or line.startswith("exit "):
                    break
                handled, out, status = self._run_line(line)
                if not handled:
                    self.reg.rollback(point[0])
                    self._jobs, self._next_pid, self._started = point[1], point[2], point[3]
                    self.changed, self.sync_cmds = point[4], point[5]
                    return False, None
                if out:
                    outs.append(out)
        finally:
            self._depth -= 1
        self.status = status
        return True, "\n".join(outs)

    def _run_line(self, line):
        """(handled, output, exit status) for one script line, `&&`/`||`/`;` included."""
        from shell import compound
        parts = compound.split(line) or [(line, None)]
        outs, ok, status = [], True, 0
        for seg, op in parts:
            if not compound.runs(op, ok):
                continue
            verdict = self.test_status(seg)
            if verdict is not None:
                ok, status = verdict, 0 if verdict else 1
                continue
            self.status = None
            handled, out = self._answer(seg)
            if not handled:
                return False, None, 0
            status = self.status if self.status is not None else (1 if _printed_an_error(out) else 0)
            ok = status == 0
            if out:
                outs.append(out)
        return True, "\n".join(outs), status

    def _cmd_bash(self, argv):
        """`bash file`, `bash -c 'cmds'` (and sh)."""
        args = argv[1:]
        if args[:1] == ["-c"] and len(args) >= 2:
            return self._run_lines([args[1]])
        if args and not args[0].startswith("-"):
            path = self._resolve(args[0])
            if self._kind(path) is None:
                if self._missing(path):
                    self.status = 127
                    return True, f"{argv[0]}: {args[0]}: No such file or directory"
                return False, None
            return self._script(path, args[0])
        return False, None

    _cmd_sh = _cmd_bash

    def _cmd_echo(self, argv):
        words = argv[1:]
        newline = not (words and words[0] == "-n")
        if not newline:
            words = words[1:]
        if any(w.startswith("-") and len(w) > 1 and set(w[1:]) <= set("neE") for w in words[:1]):
            return False, None                    # -e/-E change what is printed
        return True, " ".join(words)

    def _tilde(self, arg: str) -> str:
        if arg == "~" or arg.startswith("~/"):
            home = (self.users().get(self.username) or {}).get("home", "/root")
            return home + arg[1:]
        return arg

    def _resolve(self, arg: str) -> str:
        path = self.fs.resolve(self._tilde(arg))
        # Copy the path in from the filesystem design before judging it
        if self.materializer:
            self.materializer.ensure(path)
        return path

    def _kind(self, path):
        return self.inst.get("kind", path)

    def _closed(self, path) -> bool:
        """A directory whose full contents are known: attacker-made, or listed by
        the filesystem design. Never the kernel's trees: their contents are not ours."""
        if self._virtual(path):
            return False
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
        if self._virtual(path):
            return self.inst.get("absent", path) is not None
        parent = posixpath.dirname(path)
        while parent and parent != "/":
            if self._kind(parent) == "symlink":      # /bin/x lives under /usr/bin
                return False
            parent = posixpath.dirname(parent)
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
        if set(flags) - _LS_FLAGS:
            return False, None
        long, show_all = "l" in flags, "a" in flags or "A" in flags
        errors, files, dirs = [], [], []
        order = lambda item: item[0].lower().lstrip(".")
        for arg in args or ["."]:
            path = self._resolve(arg if args else self.reg.cwd())
            if self._missing(path):
                errors.append(f"ls: cannot access '{arg}': No such file or directory")
            elif not self._owned(path):
                return False, None
            elif self._kind(path) == "dir" and "d" not in flags:
                dirs.append((arg, path))
            else:
                files.append((arg, path))
        join = "\n" if "1" in flags else "  "
        blocks = []
        if files:
            files.sort(key=order)
            blocks.append(self._long(files) if long else join.join(a for a, _ in files))
        for arg, path in sorted(dirs, key=order):
            body = self._ls_dir(path, flags, long, show_all)
            blocks.append(body if len(args) <= 1 else f"{arg}:" + (f"\n{body}" if body else ""))
        text = "\n\n".join(blocks)
        return True, "\n".join(errors + ([text] if text else []))

    def _ls_dir(self, path, flags, long, show_all) -> str:
        entries = [(n, posixpath.join(path, n)) for n in self._children(path)
                   if show_all or not n.startswith(".")]
        if "a" in flags:
            entries = [(".", path), ("..", posixpath.dirname(path) or "/")] + entries
        if not long:
            return ("\n" if "1" in flags else "  ").join(name for name, _ in entries)
        total = sum(self._blocks_1k(p) for _, p in entries)
        body = self._long(entries)
        return f"total {total}" + (f"\n{body}" if body else "")

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
            self._replay(f"chmod {spec} {shlex.quote(real)}")
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
        if flags - set("ivcnFq") or len(args) != 2:
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
        self.status = 0 if matched else 1          # grep: 1 means "no match", silently
        if "q" in flags:
            return True, ""
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

    def test_status(self, text):
        """True/False for `test ...` and `[ ... ]` on state the register holds, else None."""
        if "$" in text or "&" in text or "|" in text or ";" in text:
            return None
        try:
            argv = shlex.split(text)
        except ValueError:
            return None
        if argv[:1] == ["["]:
            if argv[-1:] != ["]"]:
                return None
            argv = argv[1:-1]
        elif argv[:1] == ["test"]:
            argv = argv[1:]
        else:
            return None
        negate = argv[:1] == ["!"]
        result = self._test(argv[1:] if negate else argv)
        return None if result is None else result != negate

    def _test(self, a):
        unary = {"-e", "-f", "-d", "-s", "-r", "-w", "-x", "-L", "-h", "-z", "-n"}
        if len(a) == 2 and a[0] in ("-z", "-n"):
            return (a[1] == "") == (a[0] == "-z")
        if len(a) == 2 and a[0] in unary:
            path = self._resolve(a[1])
            kind = self._kind(path)
            if kind is None:
                return False if self._missing(path) else None
            real = self._target(path)
            if a[0] in ("-L", "-h"):
                return kind == "symlink"
            if real is None:
                return None
            if a[0] == "-e":
                return True
            if a[0] == "-f":
                return self._kind(real) == "file"
            if a[0] == "-d":
                return self._kind(real) == "dir"
            if a[0] == "-s":
                return self._size(real) > 0
            mode = self.inst.get("mode", real)
            if mode is None:
                return None
            if a[0] in ("-r", "-w"):
                return True                    # root reads and writes anything
            return self._kind(real) == "dir" or bool(mode & 0o111)
        if len(a) == 3 and a[1] in ("=", "==", "!="):
            return (a[0] == a[2]) == (a[1] != "!=")
        if len(a) == 3 and a[1] in ("-eq", "-ne", "-gt", "-lt", "-ge", "-le"):
            try:
                x, y = int(a[0]), int(a[2])
            except ValueError:
                return None
            return {"-eq": x == y, "-ne": x != y, "-gt": x > y,
                    "-lt": x < y, "-ge": x >= y, "-le": x <= y}[a[1]]
        return None

    # ── find ───────────────────────────────────────────────────────────────

    def _meta(self, path):
        """(kind, mode, owner) from the register, else from the filesystem design."""
        kind = self._kind(path)
        if kind is not None:
            return kind, self.inst.get("mode", path), self.inst.get("owner", path)
        node = self.materializer.profile.node(path) if self.materializer else None
        if node is None or self.inst.get("absent", path):
            return None
        who = self.materializer.users.get(node[2], str(node[2]))
        return {0: "symlink", 1: "dir", 2: "file"}.get(node[1], "file"), node[5] & 0o7777, who

    def _cmd_find(self, argv):
        args, i, roots = argv[1:], 0, []
        while i < len(args) and not args[i].startswith(("-", "(", "!")):
            roots.append(args[i])
            i += 1
        tests, maxd, mind = [], None, 0
        while i < len(args):
            t = args[i]
            if t == "-print":
                i += 1
                continue
            if t not in ("-name", "-iname", "-type", "-maxdepth", "-mindepth", "-perm",
                         "-user") or i + 1 >= len(args):
                return False, None
            v = args[i + 1]
            if t == "-maxdepth" or t == "-mindepth":
                if not v.isdigit():
                    return False, None
                maxd, mind = (int(v), mind) if t == "-maxdepth" else (maxd, int(v))
            elif t == "-type" and v not in ("f", "d", "l"):
                return False, None
            elif t == "-perm" and not re.fullmatch(r"[-/]?[0-7]{1,4}", v):
                return False, None
            else:
                tests.append((t, v))
            i += 2
        reg = {}
        for p in self.inst.keys("kind"):
            reg.setdefault(posixpath.dirname(p) or "/", set()).add(posixpath.basename(p))

        def names(directory):
            found = set(reg.get(directory, ()))
            if self.materializer:
                found |= set(self.materializer.profile.children(directory))
            return sorted((n for n in found if n and self._meta(posixpath.join(directory, n))),
                          key=lambda n: n.lower().lstrip("."))

        def matches(path, meta):
            kind, mode, owner = meta
            for t, v in tests:
                if t == "-name" and not fnmatch.fnmatchcase(posixpath.basename(path) or "/", v):
                    return False
                if t == "-iname" and not fnmatch.fnmatch(posixpath.basename(path).lower(), v.lower()):
                    return False
                if t == "-type" and {"f": "file", "d": "dir", "l": "symlink"}[v] != kind:
                    return False
                if t == "-user" and owner != v:
                    return False
                if t == "-perm":
                    want, bits = int(v.lstrip("-/"), 8), (mode or 0) & 0o7777
                    if v[0] == "-" and bits & want != want:
                        return False
                    if v[0] == "/" and not bits & want:
                        return False
                    if v[0] not in "-/" and bits != want:
                        return False
            return True

        lines = []
        for root in roots or ["."]:
            start = self._resolve(root)
            meta = self._meta(start)
            if meta is None:
                if not self._missing(start):
                    return False, None
                lines.append(f"find: '{root}': No such file or directory")
                continue
            stack = [(root, start, 0)]
            while stack:
                shown, path, depth = stack.pop()
                meta = self._meta(path)
                if depth >= mind and matches(path, meta):
                    lines.append(shown)
                if meta[0] == "dir" and (maxd is None or depth < maxd):
                    kids = names(path)
                    stack += [(posixpath.join(shown, n), posixpath.join(path, n), depth + 1)
                              for n in reversed(kids)]
        return True, "\n".join(lines)

    def _cmd_chattr(self, argv):
        """Attacker scripts run `chattr -i -a` before editing a file; it is silent when it works."""
        words = argv[1:]
        modes = [w for w in words if w[:1] in "+-=" and len(w) > 1 and not w.startswith("-v")]
        files = [w for w in words if w[:1] not in "+-="]
        letters = set("".join(m[1:] for m in modes))
        if not modes or not files or letters - set("RVfpacdeijstuADSTCF"):
            return False, None              # usage text and odd forms are left to others
        errors = []
        for arg in files:
            path = self._resolve(arg)
            if self._kind(path) is None:
                if not self._missing(path):
                    return False, None
                errors.append(f"chattr: No such file or directory while trying to stat {arg}")
        self.status = 1 if errors else 0
        return True, "\n".join(errors)

    def _cmd_true(self, argv):
        return True, ""

    def _cmd_false(self, argv):
        self.status = 1
        return True, ""

    def _cmd_sudo(self, argv):
        """`sudo -l` as Ubuntu 20.04 prints it for an account with full rights."""
        if argv[1:] != ["-l"]:
            return False, None
        host, user = self.hostname, self.username
        return True, (f"Matching Defaults entries for {user} on {host}:\n"
                      "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:"
                      "/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\n"
                      f"User {user} may run the following commands on {host}:\n"
                      "    (ALL : ALL) ALL")

    def note_sudo(self, command: str) -> None:
        """A real sudo logs to auth.log; record it, and append if the log exists."""
        try:
            argv = shlex.split(command)
        except ValueError:
            return
        if not argv:
            return
        exe = argv[0] if "/" in argv[0] else f"/usr/bin/{argv[0]}"
        if argv[0] == "-l":
            exe, argv = "list", ["list"]
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

    # ── creating, copying, moving, removing (OSCAR Sec. IV-A) ───────────────

    def _virtual(self, *paths) -> bool:
        return any(p == v or p.startswith(v + "/") for p in paths for v in _VIRTUAL)

    def _parent(self, path):
        """('dir'|'notdir'|'missing'|'unknown', real parent) for path's directory."""
        parent = posixpath.dirname(path) or "/"
        real = self._target(parent)
        if real is None:
            return ("missing" if self._missing(parent) else "unknown"), None
        return ("dir" if self._kind(real) == "dir" else "notdir"), real

    def _fresh(self, path, kind, mode, content=b"", target=None, inode=None,
               stamp=None, used=None):
        """Facts for a new path owned by the attacker's account."""
        now = stamp or self.reg.now_ns()
        ino = inode or self.reg.new_inode(path)
        while used is not None and ino in used:
            ino += 1
        if used is not None:
            used.add(ino)
        group = "root" if self.username == "root" else self.username
        facts = {Fact("kind", path, kind), Fact("mode", path, mode),
                 Fact("owner", path, self.username), Fact("group", path, group),
                 Fact("inode", path, ino), Fact("listed", path)}
        facts |= {Fact(rel, path, now) for rel in ("mtime", "atime", "ctime")}
        if kind == "dir":
            facts.add(Fact("sealed", path))
        elif kind == "symlink":
            facts |= {Fact("target", path, target), Fact("size", path, len(target))}
        else:
            facts |= {Fact("content", path, content), Fact("size", path, len(content))}
        return facts

    def _bump(self, directory, add, remove):
        """A directory's mtime/ctime move when an entry is added or removed."""
        self.reg.ensure_meta(directory)
        now = self.reg.now_ns()
        for rel in ("mtime", "ctime"):
            old = self.inst.get(rel, directory)
            if old is not None:
                remove.add(Fact(rel, directory, old))
            add.add(Fact(rel, directory, now))

    def _flags(self, argv, allowed):
        flags = "".join(a[1:] for a in argv[1:] if a.startswith("-") and a != "--")
        args = [a for a in argv[1:] if a == "--" or not a.startswith("-")]
        args = [a for a in args if a != "--"]
        if set(flags) - set(allowed) or any(c in a for a in args for c in "*?[{$"):
            return None, None
        return flags, args

    def _cmd_mkdir(self, argv):
        flags, args = self._flags(argv, "p")
        if flags is None or not args:
            return False, None
        paths = [self._resolve(a) for a in args]
        if self._virtual(*paths):
            return False, None
        plans = []
        for arg, path in zip(args, paths):
            if self._kind(path) is not None:
                plans.append(("exists", arg, path, []))
                continue
            chain, cur = [], path
            while True:
                state, real = self._parent(cur)
                chain.append(cur)
                if state == "dir":
                    break
                if state in ("missing", "unknown") and "p" in flags:
                    cur = posixpath.dirname(cur)
                    if self._kind(cur) is not None or cur == "/":
                        break
                    continue
                break
            state, real = self._parent(chain[-1])
            if state == "unknown" or (state == "missing" and len(args) > 1):
                return False, None
            plans.append((state, arg, path, chain[::-1]))
        errors = []
        for state, arg, path, chain in plans:
            if state == "exists":
                if "p" not in flags:
                    errors.append(f"mkdir: cannot create directory '{arg}': File exists")
                continue
            if state == "notdir":
                errors.append(f"mkdir: cannot create directory '{arg}': Not a directory")
                continue
            if state == "missing" and "p" not in flags:
                errors.append(f"mkdir: cannot create directory '{arg}': No such file or directory")
                continue
            add, remove, used = set(), set(), set()
            top = posixpath.dirname(chain[0]) or "/"
            for d in chain:
                add |= self._fresh(d, "dir", 0o755, used=used)
            self._bump(self._target(top) or top, add, remove)
            if not self.reg.commit(add, remove, why=f"mkdir {arg}"):
                return False, None
            self._replay(*[f"mkdir {shlex.quote(d)}" for d in chain])
            self.changed = True
        return True, "\n".join(errors)

    def _cmd_touch(self, argv):
        flags, args = self._flags(argv, "c")
        if flags is None or not args:
            return False, None
        if self._virtual(*[self._resolve(a) for a in args]):
            return False, None
        errors = []
        for arg in args:
            path = self._resolve(arg)
            real = self._target(path) if self._kind(path) else None
            if real is not None:
                self.reg.ensure_meta(real)
                now, add, remove = self.reg.now_ns(), set(), set()
                for rel in ("mtime", "atime", "ctime"):
                    old = self.inst.get(rel, real)
                    if old is not None:
                        remove.add(Fact(rel, real, old))
                    add.add(Fact(rel, real, now))
                self.reg.commit(add, remove, why=f"touch {arg}")
                self._replay(f"touch {shlex.quote(real)}")
                self.changed = True
                continue
            if self._kind(path) is not None:
                return False, None            # dangling link: Cowrie decides
            state, parent = self._parent(path)
            if state == "unknown":
                return False, None
            if state != "dir":
                if "c" not in flags:
                    errors.append(f"touch: cannot touch '{arg}': "
                                  + ("Not a directory" if state == "notdir"
                                     else "No such file or directory"))
                continue
            if "c" in flags:
                continue
            add, remove = self._fresh(path, "file", 0o644), set()
            self._bump(parent, add, remove)
            if not self.reg.commit(add, remove, why=f"touch {arg}"):
                return False, None
            self._replay(f"touch {shlex.quote(path)}")
            self.changed = True
        return True, "\n".join(errors)

    def _tree(self, path):
        """Every path at or under `path`, parents first."""
        out, stack = [], [path]
        while stack:
            cur = stack.pop(0)
            out.append(cur)
            if self._kind(cur) == "dir":
                stack = [posixpath.join(cur, n) for n in self._children(cur)] + stack
        return out

    def _cmd_rm(self, argv):
        flags, args = self._flags(argv, "rRf")
        if flags is None or not args:
            return False, None
        recursive, force = bool(set(flags) & set("rR")), "f" in flags
        paths = [self._resolve(a) for a in args]
        if self._virtual(*paths):
            return False, None
        dots = [a for a in args if a.rstrip("/").rsplit("/", 1)[-1] in (".", "..")]
        if dots:
            return True, "\n".join(
                (f"rm: refusing to remove '.' or '..' directory: skipping '{a}'" if recursive
                 else f"rm: cannot remove '{a}': Is a directory") for a in dots)
        for path in paths:
            if path == "/" or (self._kind(path) is None and not self._missing(path)):
                return False, None
        errors = []
        for arg, path in zip(args, paths):
            if self._kind(path) is None:
                if not force:
                    errors.append(f"rm: cannot remove '{arg}': No such file or directory")
                continue
            if self._kind(path) == "dir" and not recursive:
                errors.append(f"rm: cannot remove '{arg}': Is a directory")
                continue
            state, parent = self._parent(path)
            if state != "dir":
                return False, None
            # removing the attacker's own cwd or an ancestor is left to Cowrie
            cwd = self.reg.cwd() or "/"
            if cwd == path or cwd.startswith(path.rstrip("/") + "/"):
                return False, None
            add, remove = {Fact("absent", path)}, set()
            self._bump(parent, add, remove)
            gone = {f for f in self.inst.facts() if isinstance(f.key, str)
                    and f.rel not in _NON_PATH_RELS
                    and (f.key == path or f.key.startswith(path.rstrip("/") + "/"))}
            if not self.reg.commit(add, remove | gone, why=f"rm {arg}"):
                return False, None
            self._replay(f"rm -rf {shlex.quote(path)}")
            self.changed = True
        return True, "\n".join(errors)

    def _clone_facts(self, src, dst, keep_inode, stamp):
        """Facts for dst as a copy (or rename) of the subtree at src."""
        add, used = set(), set()
        for old in self._tree(src):
            new = dst + old[len(src):]
            kind = self._kind(old)
            mode = self.inst.get("mode", old)
            if kind == "symlink":
                f = self._fresh(new, "symlink", mode, target=self.inst.get("target", old),
                                inode=self.inst.get("inode", old) if keep_inode else None,
                                stamp=stamp, used=used)
            elif kind == "dir":
                f = self._fresh(new, "dir", mode, inode=self.inst.get("inode", old)
                                if keep_inode else None, stamp=stamp, used=used)
            else:
                data = self.inst.get("content", old)
                if data is None:
                    return None
                f = self._fresh(new, "file", mode, content=data,
                                inode=self.inst.get("inode", old) if keep_inode else None,
                                stamp=stamp, used=used)
            if keep_inode:          # a rename keeps owner and times
                for rel in ("owner", "group", "mtime", "atime"):
                    v = self.inst.get(rel, old)
                    if v is not None:
                        f = {x for x in f if x.rel != rel} | {Fact(rel, new, v)}
            add |= f
        return add

    def _cmd_cp(self, argv):
        return self._transfer(argv, "cp")

    def _cmd_mv(self, argv):
        return self._transfer(argv, "mv")

    def _transfer(self, argv, tool):
        """cp and mv: same operand rules and messages as GNU coreutils."""
        flags, args = self._flags(argv, "rRf" if tool == "cp" else "f")
        if flags is None:
            return False, None
        hint = f"Try '{tool} --help' for more information."
        if not args:
            return True, f"{tool}: missing file operand\n{hint}"
        if len(args) == 1:
            return True, f"{tool}: missing destination file operand after '{args[0]}'\n{hint}"
        *sources, dst_arg = args
        dst = self._resolve(dst_arg)
        dreal = self._target(dst) if self._kind(dst) else None
        dst_is_dir = dreal is not None and self._kind(dreal) == "dir"
        if len(sources) > 1 and not dst_is_dir:
            return True, f"{tool}: target '{dst_arg}' is not a directory"
        recursive = bool(set(flags) & set("rR"))

        plans, errors = [], []
        for src_arg in sources:
            src = self._resolve(src_arg)
            if self._kind(src) is None:
                if not self._missing(src):
                    return False, None
                errors.append(f"{tool}: cannot stat '{src_arg}': No such file or directory")
                continue
            real = self._target(src) if tool == "cp" else src       # mv moves the link itself
            if real is None:
                return False, None
            skind = self._kind(real)
            base = posixpath.basename(src_arg.rstrip("/"))
            final = posixpath.join(dreal if dst_is_dir else dst, base) if dst_is_dir else dst
            shown = posixpath.join(dst_arg, base) if dst_is_dir else dst_arg
            if self._virtual(real, final):
                return False, None
            if tool == "cp" and skind == "dir" and not recursive:
                errors.append(f"cp: -r not specified; omitting directory '{src_arg}'")
                continue
            if final == real:
                errors.append(f"{tool}: '{src_arg}' and '{shown}' are the same file")
                continue
            if skind == "dir" and final.startswith(real.rstrip("/") + "/"):
                state, par = self._parent(final)
                if tool == "cp" and state == "dir" and self._kind(final) is None:
                    # cp makes the empty destination before it notices the loop
                    made, gone = self._fresh(final, "dir", 0o755), set()
                    self._bump(par, made, gone)
                    if self.reg.commit(made, gone, why=f"cp {src_arg} {dst_arg}"):
                        self._replay(f"mkdir {shlex.quote(final)}")
                        self.changed = True
                errors.append(f"cp: cannot copy a directory, '{src_arg}', into itself, '{shown}'"
                              if tool == "cp" else
                              f"mv: cannot move '{src_arg}' to a subdirectory of itself, '{shown}'")
                continue
            fstate, fparent = self._parent(final)
            if fstate == "unknown":
                return False, None
            if fstate != "dir":
                what = "directory" if skind == "dir" else "regular file"
                reason = "Not a directory" if fstate == "notdir" else "No such file or directory"
                errors.append(f"cp: cannot create {what} '{shown}': {reason}" if tool == "cp"
                              else f"mv: cannot move '{src_arg}' to '{shown}': {reason}")
                continue
            fkind = self._kind(final)
            if fkind == "dir" and skind != "dir":
                errors.append(f"{tool}: cannot overwrite directory '{shown}' with non-directory")
                continue
            if fkind is not None and fkind != "dir" and skind == "dir":
                errors.append(f"{tool}: cannot overwrite non-directory '{shown}' with "
                              f"directory '{src_arg}'")
                continue
            if tool == "mv" and fkind == "dir" and self._children(final):
                errors.append(f"mv: cannot move '{src_arg}' to '{shown}': Directory not empty")
                continue
            plans.append((src_arg, src, real, final, fparent))

        for src_arg, src, real, final, fparent in plans:
            stamp = self.reg.now_ns()
            add = self._clone_facts(real, final, tool == "mv", stamp)
            if add is None:
                return False, None
            remove = {f for f in self.inst.facts() if isinstance(f.key, str)
                      and f.rel not in _NON_PATH_RELS
                      and (f.key == final or f.key.startswith(final.rstrip("/") + "/"))}
            parents = {fparent}
            if tool == "mv":
                add.add(Fact("absent", src))
                remove |= {f for f in self.inst.facts() if isinstance(f.key, str)
                           and f.rel not in _NON_PATH_RELS
                           and (f.key == src or f.key.startswith(src.rstrip("/") + "/"))}
                parents.add(self._parent(src)[1] or posixpath.dirname(src))
            for d in parents:
                self._bump(d, add, remove)
            if not self.reg.commit(add, remove, why=f"{tool} {src_arg} {dst_arg}"):
                return False, None
            self._replay(f"{tool} {'-r ' if tool == 'cp' else ''}{shlex.quote(src if tool == 'mv' else real)} "
                         f"{shlex.quote(dst)}")
            self.changed = True
        return True, "\n".join(errors)

    def _redirect(self, text):
        """`echo words > file` and `>>`: the usual way an attacker makes a file."""
        bare = re.sub(r"""'[^']*'|"(?:[^"\\]|\\.)*\"""", "", text)     # operators in quotes are text
        if (">" not in bare or any(c in bare for c in "|;&<(") or "$" in text
                or "`" in text or "\n" in text):
            return None
        try:
            tokens = shlex.split(text)
        except ValueError:
            return None
        if len(tokens) < 3 or tokens[0] != "echo" or tokens[-2] not in (">", ">>"):
            return None
        op, arg, words = tokens[-2], tokens[-1], tokens[1:-2]
        if ">" in "".join(words) or any(w.startswith("-") and w != "-n" for w in words[:1]):
            return None
        newline = not (words and words[0] == "-n")
        data = (" ".join(words[1:] if not newline else words) + ("\n" if newline else "")).encode()
        piece = data                         # what this command writes, before any append
        path = self._resolve(arg)
        if path == "/dev/null":
            return True, ""                  # the kernel throws the bytes away
        if self._virtual(path):
            return None
        real = self._target(path) if self._kind(path) else None
        if real is not None and self._kind(real) == "dir":
            return True, f"bash: {arg}: Is a directory"
        if real is not None:
            old = self.inst.get("content", real)
            if old is None:
                return None
            data = old + data if op == ">>" else data
            self.reg.ensure_meta(real)
            now = self.reg.now_ns()
            add = {Fact("content", real, data), Fact("size", real, len(data))}
            remove = {Fact("content", real, old), Fact("size", real, len(old))}
            for rel in ("mtime", "ctime"):
                if self.inst.get(rel, real) is not None:
                    remove.add(Fact(rel, real, self.inst.get(rel, real)))
                add.add(Fact(rel, real, now))
            if not self.reg.commit(add, remove, why=f"write {arg}"):
                return None
            self._replay(self._echo_cmd(piece, newline, op, real))
            self.changed = True
            return True, ""
        if self._kind(path) is not None:
            return None                      # dangling link: Cowrie decides
        state, parent = self._parent(path)
        if state == "unknown":
            return None
        if state != "dir":
            return True, f"bash: {arg}: " + ("Not a directory" if state == "notdir"
                                              else "No such file or directory")
        add, remove = self._fresh(path, "file", 0o644, content=data), set()
        self._bump(parent, add, remove)
        if not self.reg.commit(add, remove, why=f"write {arg}"):
            return None
        self._replay(self._echo_cmd(piece, newline, op, path))
        self.changed = True
        return True, ""

    @staticmethod
    def _echo_cmd(piece: bytes, newline: bool, op: str, path: str) -> str:
        text = piece.decode("utf-8", "replace")
        text = text[:-1] if newline and text.endswith("\n") else text
        return f"echo {'' if newline else '-n '}{shlex.quote(text)} {op} {shlex.quote(path)}"

    def _cmd_cd(self, argv):
        if len(argv) > 2 or (len(argv) == 2 and argv[1].startswith("-")):
            return False, None
        if len(argv) == 1 or argv[1] == "~":
            target = (self.users().get(self.username) or {}).get("home", "/root")
            arg = target
        else:
            arg, target = argv[1], argv[1]
        path = self._resolve(target)
        real = self._target(path) if self._kind(path) else None
        if real is None:
            if self._kind(path) is None and self._missing(path):
                return True, f"bash: cd: {arg}: No such file or directory"
            return False, None
        if self._kind(real) != "dir":
            return True, f"bash: cd: {arg}: Not a directory"
        if not self.reg.set_cwd(real):
            return False, None
        self._replay(f"cd {shlex.quote(real)}")
        self.changed = True
        return True, ""

    # ── hashing and the environment ────────────────────────────────────────

    def _hash(self, argv, algo):
        import hashlib
        flags, args = self._flags(argv, "")
        if flags is None or not args:
            return False, None
        lines = []
        for arg in args:
            path = self._resolve(arg)
            real = self._target(path) if self._kind(path) else None
            if real is None:
                if self._missing(path):
                    lines.append(f"{argv[0]}: {arg}: No such file or directory")
                    continue
                return False, None
            if self._kind(real) == "dir":
                lines.append(f"{argv[0]}: {arg}: Is a directory")
                continue
            data = self.inst.get("content", real)
            if data is None:
                return False, None
            lines.append(f"{hashlib.new(algo, data).hexdigest()}  {arg}")
        return True, "\n".join(lines)

    def _cmd_md5sum(self, argv):
        return self._hash(argv, "md5")

    def _cmd_sha1sum(self, argv):
        return self._hash(argv, "sha1")

    def _cmd_sha256sum(self, argv):
        return self._hash(argv, "sha256")

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
