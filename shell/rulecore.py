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
import base64
import fnmatch
import gzip
import io
import math
import posixpath
import re
import shlex
import tarfile
from datetime import datetime, timezone

from core import snapshot as image_snapshot
from shell import hardware, network, packages, pipeline, screen
from shell.compound import failed as _printed_an_error
from shell.world import Fact

# The port the fake sshd listens on, as `ss -tlnp` shows it; SSH_CONNECTION names it
_SSH_PORT = 22
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


def _ps_user(name: str) -> str:
    """procps shows a user name wider than 8 as its first 7 characters and `+`."""
    return name if len(name) <= 8 else name[:7] + "+"


def _hms(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


class RuleCore:
    """One session's fact-backed commands.

        rc = RuleCore(register, fs, hostname="psu", users=lambda: state["users"])
        rc.answer("stat key.pem")       -> (True, "  File: key.pem\\n  Size: ...")
    """

    def __init__(self, register, fs, hostname: str, users=None, variables=None,
                 username: str = "root", device: str = "801h/2049d",
                 processes=(), kernel: str = "5.15.0-generic", materializer=None, tools=None,
                 hardware_spec=None, network_spec=None, os_name: str = "", groups=None,
                 image=None, machine_id: str = "", boot_id: str = "", extra_packages=()):
        self.reg = register
        self.fs = fs
        self.hostname = hostname
        self.users = users or (lambda: {})
        self.variables = variables if variables is not None else {}
        self.username = username
        self.device = device
        self.changed = False          # the last answer changed the state
        self._peers = []              # later stages of the pipe being answered
        self._screen_pid = None       # pid of the full-screen program being drawn
        self.typed = []               # lines the attacker entered this session, for `history`
        self._hist_from = 0
        self._jobs = 0
        self._job_table = {}          # job number -> (pid, command), for `jobs` and `kill %N`
        self._ended = []              # jobs killed since `jobs` last ran, reported once
        self._next_pid = None
        self._started = {}            # pid -> spawn time (ns), for ps START
        # Base process table (Cowrie's data: VSZ/RSS bytes, TIME minutes)
        self.processes = sorted(processes, key=lambda p: p["PID"])
        self.kernel = kernel
        self.materializer = materializer
        self.tools = tools            # what is installed: path_of(name), kind(name)
        self.hw = hardware_spec       # system_state.hardware: free, df, nproc, /proc
        self.net = network_spec       # system_state.network: ifconfig, ip, netstat, ss
        self.os_name = os_name
        self.image = image            # core.snapshot.Snapshot: the image's lsb-release
        self.machine_id, self.boot_id = machine_id, boot_id
        self.extra_packages = list(extra_packages or [])
        self._quiet = False
        self.groups = groups or (lambda: {})
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
        self._quiet = quiet
        redirect = self._redirect(text)
        if redirect is not None:
            return redirect
        stages = pipeline.split_pipes(text)
        if stages:
            return self._pipeline(stages)
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
        if self.username != "root":
            denied = self._permission_denied(argv)
            if denied:
                return True, denied
        handler = getattr(self, f"_cmd_{argv[0]}", None)
        if not handler:
            return False, None
        handled, out = handler(argv)
        if handled and quiet and out:
            out = "\n".join(l for l in out.split("\n") if not l.startswith(f"{argv[0]}: "))
        return handled, out

    # First commands whose answer is read from the register and changes nothing,
    # so running one as the head of a pipe leaves no side effect to undo.
    _PIPE_SOURCES = frozenset({"ps", "cat", "ls", "who", "w", "last", "uptime", "find",
                               "grep", "head", "tail", "wc", "stat", "du", "echo", "pwd",
                               "printenv", "env", "md5sum", "sha1sum", "sha256sum", "id",
                               "netstat", "ss", "ifconfig", "ip", "free", "df", "hostname",
                               "lsb_release", "hostnamectl", "nproc", "groups", "top", "history", "dpkg", "apt", "whoami", "mount"})

    def _pipeline(self, stages):
        """`source | filter | ...`: the register answers the source, the filters run exactly.

        Declines (None) unless every stage is modelled, so anything else keeps its old path.
        """
        try:
            head = shlex.split(stages[0])
        except ValueError:
            return False, None
        if head[:1] == ["sudo"]:
            head = head[1:]
        if not head or head[0] not in self._PIPE_SOURCES:
            return False, None
        first = stages[0]
        if head[0] == "ls" and not any(a.startswith("-") and set(a[1:]) & set("l1C") for a in head[1:]):
            # into a pipe, ls prints one name per line, as `ls -1`
            first = re.sub(r"\bls\b", "ls -1", first, count=1)
        self._peers = stages[1:]          # `ps` lists the filters running beside it
        try:
            handled, data = self._answer(first)
        finally:
            self._peers = []
        if not handled or data is None or _printed_an_error(data):
            return False, None            # stderr is not piped: let the old path show it
        status = 0
        for stage in stages[1:]:
            done = pipeline.run_filter(stage, data)
            if done is None:
                return False, None
            data, status = done
        self.status = status
        return True, data

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
                hits = self._glob_path(arg.rstrip("/"))
                if hits is None:
                    return None
                if only_dirs:
                    hits = [h for h in hits if self._kind(self._resolve(h)) == "dir"]
                out += [h + ("/" if only_dirs else "") for h in hits] or [arg]
                continue
            directory = self._resolve(head if head else self.reg.cwd())
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

    def _glob_path(self, arg):
        """Expand a pattern whose directory part holds a glob too, one path
        component at a time. None when a directory on the way is not fully known."""
        absolute = arg.startswith("/")
        cur = [("/" if absolute else self.reg.cwd(), "/" if absolute else "")]
        comps = [c for c in arg.split("/") if c]
        for i, comp in enumerate(comps):
            last = i == len(comps) - 1
            nxt = []
            for directory, shown in cur:
                if not any(c in comp for c in "*?["):
                    path = posixpath.join(directory, comp)
                    if self._kind(path) is not None and (last or self._kind(path) == "dir"):
                        nxt.append((path, shown + comp + ("" if last else "/")))
                    continue
                directory = self._resolve(directory)      # load it from the design first
                if self._kind(directory) != "dir" or not self._closed(directory):
                    return None
                names = [n for n in self._children(directory)
                         if comp.startswith(".") or not n.startswith(".")]
                for n in sorted(fnmatch.filter(names, comp), key=lambda n: n.lower().lstrip(".")):
                    path = posixpath.join(directory, n)
                    if last or self._kind(path) == "dir":
                        nxt.append((path, shown + n + ("" if last else "/")))
            cur = nxt
        return [shown for _, shown in cur]

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
                 self.changed, list(self.sync_cmds), dict(self._job_table), list(self._ended))
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
                    self._job_table, self._ended = point[6], point[7]
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

    # ── the machine: free, df, nproc, and the /proc files that change ──────

    def _cmd_free(self, argv):
        if not self._has("free"):
            return False, None
        if not self.hw:
            return False, None
        out = hardware.free(self.hw, argv, self._mem_drift())
        return (True, out) if out else (False, None)

    def _cmd_nproc(self, argv):
        if not self._has("nproc"):
            return False, None
        return (True, str(self.hw["cpus"])) if self.hw and len(argv) == 1 else (False, None)

    def _cmd_df(self, argv):
        if not self._has("df"):
            return False, None
        disks = (self.hw or {}).get("disks")
        if not disks:
            return False, None

        def mounted_on(arg):
            path, best = self._resolve(arg), None
            for d in disks:
                m = d["mount"]
                if path == m or path.startswith(m.rstrip("/") + "/") or m == "/":
                    if best is None or len(m) > len(best):
                        best = m
            return best if self._kind(path) is not None or path == "/" else None
        out = hardware.df(disks, argv, mounted_on, self.hw["memory_kb"]["total"])
        return (True, out) if out else (False, None)

    # ── packages ───────────────────────────────────────────────────────────

    def _package_rows(self):
        image_rows = self.image.packages() if self.image else []
        if not image_rows:
            return None
        facts = {n: self.inst.get("pkg", n) for n in self.inst.keys("pkg")}
        return packages.table(image_rows, self.extra_packages, facts)

    def _cmd_dpkg(self, argv):
        rows = self._package_rows()
        if rows is None or not self._has("dpkg"):
            return False, None
        cols = 80 if self._peers else int(self.reg.session("cols", 80))
        out = packages.dpkg_list(rows, argv, cols)
        return (True, out) if out is not None else (False, None)

    def _cmd_apt(self, argv):
        rows = self._package_rows()
        if rows is None or not self._has("apt"):
            return False, None
        out = packages.apt_list(rows, argv, piped=bool(self._peers), quiet=self._quiet)
        return (True, out) if out is not None else (False, None)

    # ── who may do what: a user other than root ─────────────────────────────

    _ROOT_ONLY_FILES = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/shadow-")
    _READERS = frozenset({"cat", "grep", "wc", "sort", "uniq", "md5sum", "sha1sum", "sha256sum",
                          "stat", "strings", "file", "less", "more", "cut", "awk", "sed"})

    def _protected_dir(self, path):
        """The 0700 directory (root's home, another user's home) this path is inside, or None."""
        if path == "/root" or path.startswith("/root/"):
            return "/root"
        for name, u in self.users().items():
            home = u.get("home", "")
            if (u.get("uid", 0) >= 1000 and name != self.username and home.startswith("/home/")
                    and (path == home or path.startswith(home + "/"))):
                return home
        return None

    def _denied_read(self, path) -> bool:
        return (self.username != "root"
                and (path in self._ROOT_ONLY_FILES or path.startswith("/etc/ssh/ssh_host_")
                     and not path.endswith(".pub") or self._protected_dir(path) is not None))

    def _may_write(self, path) -> bool:
        if self.username == "root":
            return True
        home = (self.users().get(self.username) or {}).get("home", "/nonexistent")
        return (path == "/dev/null" or any(path == d or path.startswith(d + "/")
                                           for d in (home, "/tmp", "/var/tmp", "/dev/shm")))

    def _permission_denied(self, argv):
        """What Linux says when this user may not touch a path, or None."""
        cmd = argv[0]
        args = [a for a in argv[1:] if not a.startswith("-")]
        if cmd == "grep":
            args = args[1:]
        for a in args:
            path = self._resolve(a)
            if cmd in ("head", "tail") and self._denied_read(path):
                return f"{cmd}: cannot open '{a}' for reading: Permission denied"
            if cmd in self._READERS and self._denied_read(path):
                return f"{cmd}: {a}: Permission denied"
            if cmd == "ls" and self._denied_read(path):
                inside = self._protected_dir(path)
                return (f"ls: cannot open directory '{a}': Permission denied" if inside == path
                        else f"ls: cannot access '{a}': Permission denied")
            if cmd == "cd" and self._protected_dir(path) is not None:
                return f"bash: cd: {a}: Permission denied"
            if cmd in ("touch", "mkdir", "rm", "rmdir", "cp", "mv", "ln", "chmod", "chown", "tee") \
                    and not self._may_write(path):
                verb = {"touch": "cannot touch", "mkdir": "cannot create directory", "rm": "cannot remove",
                        "rmdir": "failed to remove", "chmod": "changing permissions of",
                        "chown": "changing ownership of"}.get(cmd, "cannot create regular file")
                tail = "Operation not permitted" if cmd in ("chmod", "chown") else "Permission denied"
                return f"{cmd}: {verb} '{a}': {tail}"
        return None

    def _cmd_whoami(self, argv):
        return (True, self.username) if len(argv) == 1 else (False, None)

    def _cmd_mount(self, argv):
        if len(argv) != 1 or not self.hw or not self._has("mount"):
            return False, None
        uid = (self.users().get(self.username) or {}).get("uid", 0)
        return True, hardware.mount_lines(self.hw["disks"], self.hw["memory_kb"]["total"], uid)

    # ── history ────────────────────────────────────────────────────────────

    def note(self, line: str) -> None:
        """Record a line as typed. Cowrie's own `history` also lists this honeypot's
        internal sync commands, so `history` is answered here instead."""
        if line and line.strip():
            self.typed.append(line.strip())

    def _cmd_history(self, argv):
        lines = self.typed[self._hist_from:]
        if len(argv) == 2 and argv[1] == "-c":
            self._hist_from = len(self.typed)
            return True, ""
        if len(argv) == 2 and argv[1].isdigit():
            count = int(argv[1])
            start = max(len(self.typed) - count, self._hist_from)
        elif len(argv) == 1:
            start = self._hist_from
        else:
            return False, None
        base = self._hist_from
        return True, "\n".join(f"{i - base + 1:>5}  {l}"
                               for i, l in enumerate(self.typed[start:], start))

    # ── who is who: id and groups ──────────────────────────────────────────

    def _account(self, name):
        """(uid, gid, [(gid, group)...]) for a user, primary group first; None if unknown."""
        user = self.users().get(name)
        if user is None:
            return None
        groups = self.groups()
        by_gid = {g.get("gid"): n for n, g in groups.items()}
        gid = user.get("gid", user.get("uid", 0))
        listed = [(gid, by_gid.get(gid, name))]
        listed += [(g["gid"], n) for n, g in groups.items()
                   if name in (g.get("members") or []) and g["gid"] != gid]
        return user.get("uid", 0), gid, listed

    def _cmd_id(self, argv):
        flags, names = set(), []
        for a in argv[1:]:
            if re.fullmatch(r"-[ugGn]+", a):
                flags |= set(a[1:])
            elif a.startswith("-"):
                return False, None
            else:
                names.append(a)
        if len(names) > 1 or len(flags & set("ugG")) > 1 or (flags and not flags & set("ugG")):
            return False, None
        who = names[0] if names else self.username
        acct = self._account(who)
        if acct is None:
            return True, f"id: \u2018{who}\u2019: no such user"
        uid, gid, listed = acct
        if "u" in flags:
            return True, who if "n" in flags else str(uid)
        if "g" in flags:
            return True, listed[0][1] if "n" in flags else str(gid)
        if "G" in flags:
            return True, " ".join(n if "n" in flags else str(g) for g, n in listed)
        groups = ",".join(f"{g}({n})" for g, n in listed)
        return True, f"uid={uid}({who}) gid={gid}({listed[0][1]}) groups={groups}"

    def _cmd_groups(self, argv):
        names = argv[1:]
        if any(n.startswith("-") for n in names):
            return False, None
        lines = []
        for who in names or [self.username]:
            acct = self._account(who)
            if acct is None:
                lines.append(f"groups: \u2018{who}\u2019: no such user")
                continue
            text = " ".join(n for _, n in acct[2])
            lines.append(f"{who} : {text}" if names else text)
        return True, "\n".join(lines)

    # ── the network ────────────────────────────────────────────────────────

    def _local_ip(self):
        return self.reg.session("local_ip") if self.net else None

    def _counters(self):
        pk = lambda k, lo, hi: self.reg.prf(k, "net", lo, hi)
        rx, tx = pk("rx", 6_000_000, 60_000_000), pk("tx", 4_000_000, 40_000_000)
        return {"rx_packets": rx, "rx_bytes": rx * pk("rxs", 780, 1150),
                "tx_packets": tx, "tx_bytes": tx * pk("txs", 520, 900),
                "lo": pk("lo", 150_000, 900_000)}

    def _cmd_ifconfig(self, argv):
        if not self._has("ifconfig"):
            return False, None
        ip = self._local_ip()
        out = network.ifconfig(self.net, ip, self._counters(), argv) if ip else None
        return (True, out) if out else (False, None)

    def _cmd_ip(self, argv):
        if not self._has("ip"):
            return False, None
        ip = self._local_ip()
        out = network.ip_command(self.net, ip, argv) if ip else None
        return (True, out) if out is not None else (False, None)

    def _cmd_hostname(self, argv):
        if not self._has("hostname"):
            return False, None
        ip = self._local_ip() or ""
        out = network.hostname_command(self.hostname, ip, argv)
        if out is None or (argv[1:] == ["-I"] and not ip):
            return False, None
        return True, out

    def _sockets(self):
        pids = {}
        for l in self.net["listeners"]:
            hit = next((p["PID"] for p in self.processes if l["process"] in p["COMMAND"]), None)
            if hit is not None:
                pids[l["process"]] = hit
        sshd = self.reg.session("sshd_pid")
        conn = ({"pid": sshd, "peer": f"{self.reg.session('ip')}:{self.reg.session('port')}"}
                if sshd is not None else None)
        return pids, conn

    def _cmd_netstat(self, argv):
        if not self._has("netstat"):
            return False, None
        ip = self._local_ip()
        if not ip:
            return False, None
        pids, conn = self._sockets()
        out = network.netstat(self.net, ip, pids, conn, argv)
        return (True, out) if out else (False, None)

    def _cmd_ss(self, argv):
        if not self._has("ss"):
            return False, None
        ip = self._local_ip()
        if not ip:
            return False, None
        pids, conn = self._sockets()
        out = network.ss(self.net, ip, pids, conn, argv)
        return (True, out) if out else (False, None)

    def _has(self, name: str) -> bool:
        """Is this command on the host? The image decides (plus what the operator adds)."""
        return self.tools is None or self.tools.available(name)

    def _lsb(self):
        text = (self.image.text("/etc/lsb-release") or "") if self.image else ""
        f = dict(l.split("=", 1) for l in text.splitlines() if "=" in l)
        f = {k: v.strip('"') for k, v in f.items()}
        if not f:
            return None
        return {"i": ("Distributor ID", f.get("DISTRIB_ID", "")),
                "d": ("Description", f.get("DISTRIB_DESCRIPTION", "")),
                "r": ("Release", f.get("DISTRIB_RELEASE", "")),
                "c": ("Codename", f.get("DISTRIB_CODENAME", ""))}

    def _cmd_lsb_release(self, argv):
        fields = self._lsb()
        if not fields or not self._has("lsb_release"):
            return False, None
        short, picks = False, []
        for a in argv[1:]:
            if not re.fullmatch(r"-[aidrcs]+", a):
                return False, None
            for ch in a[1:]:
                if ch == "s":
                    short = True
                elif ch == "a":
                    picks += ["i", "d", "r", "c"]
                else:
                    picks.append(ch)
        if not picks:
            return True, "No LSB modules are available."
        lines = [v if short else f"{k}:\t{v}" for k, v in (fields[p] for p in picks)]
        if any(a.startswith("-") and "a" in a for a in argv[1:]):
            lines.insert(0, "No LSB modules are available.")
        return True, "\n".join(lines)

    def _cmd_hostnamectl(self, argv):
        pretty = (self.image.os_release().get("PRETTY_NAME") if self.image else None) or self.os_name
        if (len(argv) > 2 or (len(argv) == 2 and argv[1] != "status") or not pretty
                or not self.machine_id or not self._has("hostnamectl")):
            return False, None
        rows = [("Static hostname", self.hostname), ("Icon name", "computer-vm"),
                ("Chassis", "vm"), ("Machine ID", self.machine_id), ("Boot ID", self.boot_id),
                ("Virtualization", "kvm"), ("Operating System", pretty),
                ("Kernel", f"Linux {self.kernel}"), ("Architecture", "x86-64")]
        return True, "\n".join(f"{k:>18}: {v}" for k, v in rows)

    def _image_proc(self, path):
        """/proc files that follow the declared hardware, then the ones that move with time."""
        if self.hw and path == "/proc/meminfo":
            return hardware.meminfo(self.hw)
        return self._proc_text(path)

    # ── top ────────────────────────────────────────────────────────────────

    def top_options(self, argv):
        """What a `top` command line asks for, or None for a flag top would refuse.

        batch (-b), count (-n), delay (-d), cmdline (-c), user (-u/-U), pids (-p),
        idle (-i turns it off), sort (-o). Flags that only change how top draws on a
        terminal (-H -S -s -E -e -w) are accepted and have no effect here.
        """
        opts = {"batch": False, "count": None, "delay": 3.0, "cmdline": False,
                "user": None, "pids": None, "idle": True, "sort": "cpu", "per_cpu": False}
        takes_value = set("ndpuUoeEw")
        args, i = argv[1:], 0
        while i < len(args):
            a = args[i]
            if not re.fullmatch(r"-[A-Za-z0-9,.%+]+", a):
                return None
            letters, j = a[1:], 0
            while j < len(letters):
                ch = letters[j]
                if ch not in takes_value:
                    if ch == "b": opts["batch"] = True
                    elif ch == "c": opts["cmdline"] = True
                    elif ch == "i": opts["idle"] = False
                    elif ch == "1": opts["per_cpu"] = True
                    elif ch not in "HSsE":
                        return None
                    j += 1
                    continue
                rest = letters[j + 1:]
                if not rest:
                    i += 1
                    rest = args[i] if i < len(args) else ""
                if ch == "n":
                    try: opts["count"] = int(float(rest))
                    except ValueError: return None
                elif ch == "d":
                    try: opts["delay"] = max(float(rest), 0.1)
                    except ValueError: return None
                elif ch in "uU":
                    opts["user"] = rest
                elif ch == "p":
                    try: opts["pids"] = {int(x) for x in rest.split(",") if x}
                    except ValueError: return None
                elif ch == "o":
                    field = rest.lstrip("+-").upper()
                    opts["sort"] = {"%CPU": "cpu", "%MEM": "mem", "PID": "pid", "TIME+": "time",
                                    "TIME": "time"}.get(field, "cpu")
                break
            i += 1
        return opts

    def _loads(self):
        """The three load averages: fixed per session at heart, drifting slowly with the clock,
        so `uptime` ten minutes apart does not print the same numbers."""
        import math
        t = self.reg.now_ns() / 1e9
        out = []
        for i, period in enumerate((90, 420, 1500)):
            base = self.reg.prf(f"load{i}", "load", 0, 30) / 100
            wave = 0.06 * math.sin(t / period + i) + 0.03 * math.sin(t / (period * 0.37))
            out.append(max(round(base + wave * (1 if i == 0 else 0.6), 2), 0.0))
        return out

    def _mem_drift(self):
        """kB that move between free memory and the page cache, changing every ten seconds."""
        bucket = int(self.reg.now_ns() / 1e9 // 10)
        return (self.reg.prf(f"memdrift{bucket}", "mem", 0, 6000) - 3000)

    def top_frame(self, tick, height, delay, sort="cpu", opts=None, width=80, color=False):
        """One frame of `top`, from the same rows and memory `ps` and `free` use."""
        if not self.hw:
            return None
        return screen.render_top(
            self._rows("top"), self.hw, self._uptime_line(), tick,
            lambda name, lo, hi: self.reg.prf(name, "top", lo, hi), delay, height, sort,
            user_fmt=_ps_user, opts=opts, width=width, mem_drift=self._mem_drift(), color=color)

    def _uptime_text(self) -> str:
        """`124 days, 03:31:11`, the way htop prints the uptime."""
        delta = self._dt(self.reg.now_ns()) - self._dt(self._boot_ns())
        h, rem = divmod(delta.seconds, 3600)
        m, sec = divmod(rem, 60)
        days = f"{delta.days} day{'s' if delta.days != 1 else ''}, " if delta.days else ""
        return f"{days}{h:02d}:{m:02d}:{sec:02d}"

    def htop_frame(self, tick, height, width=80, selected=0, sort="cpu"):
        if not self.hw:
            return None
        return screen.render_htop(
            self._rows("htop"), self.hw, self._uptime_text(), self._loads(), tick,
            lambda name, lo, hi: self.reg.prf(name, "htop", lo, hi), height, width, selected,
            sort, user_fmt=_ps_user, mem_drift=self._mem_drift())

    def begin_screen(self):
        """A full-screen program starts: it keeps one PID for all its frames."""
        self._screen_pid = self._new_pid()

    def end_screen(self):
        self._screen_pid = None

    def _cmd_top(self, argv):
        opts = self.top_options(argv)
        if not opts or not self.hw or not self._has("top"):
            return False, None
        # no terminal to draw on (batch mode, a pipe, ssh without -t): frames are printed
        self.begin_screen()
        try:
            frames = [self.top_frame(t, 0, opts["delay"], opts["sort"], opts, width=80)
                      for t in range(opts["count"] or 1)]
        finally:
            self.end_screen()
        return True, "\n".join(frames)

    def _proc_text(self, path):
        """/proc files whose value moves with time or load, else None."""
        if path == "/proc/uptime" and self.hw:
            up = (self.reg.now_ns() - self._boot_ns()) / 1e9
            idle = self.reg.prf("idle", "boot", 90, 99) / 100
            return hardware.uptime_file(up, self.hw["cpus"], idle).rstrip("\n")
        if path == "/proc/loadavg":
            loads = self._loads()
            top = max([p["PID"] for p in self.processes] + [self._shell_pid()])
            return hardware.loadavg(loads, len(self.processes) + 5,
                                    self._next_pid or top + 1).rstrip("\n")
        return None

    def _cmd_cat(self, argv):
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) != 1 or len(argv) != 2:
            return False, None
        arg, path = args[0], self._resolve(args[0])
        live = self._image_proc(path)
        if live is not None:
            return True, live.rstrip("\n")
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
        if data is None and self.inst.get("psize", real) == 0:
            data = b""            # an empty file is empty, whoever else has written to the real one
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
        proc = self._image_proc(path)
        if proc is not None:
            body = proc[:-1] if proc.endswith("\n") else proc
            return True, (body.split("\n") if body else []), None
        if self._missing(path):
            return True, None, f"{tool}: cannot open '{arg}' for reading: No such file or directory"
        real = self._target(path)
        if real is None or self._kind(real) != "file" or not self._owned(real):
            return False, None, None
        data = self.inst.get("content", real)
        if data is None and self.inst.get("psize", real) == 0:
            data = b""
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
        """Boot time agrees with ps: pid 1's START, at an hour fixed by the host's boot id."""
        now = self._dt(self.reg.now_ns())
        first = next((p for p in self.processes if p["PID"] == 1), None)
        if first and self.boot_id:
            try:
                return int(image_snapshot.boot_datetime(first["START"], self.boot_id, now)
                           .timestamp() * 1e9)
            except ValueError:
                pass
        return self.reg.epoch_ns - self.reg.prf("uptime", "boot", 3, 200) * 86_400 * 10**9

    def _uptime_line(self) -> str:
        now = self._dt(self.reg.now_ns())
        delta = now - self._dt(self._boot_ns())
        h, m = divmod(delta.seconds // 60, 60)
        up = (f"{delta.days} day{'s' if delta.days != 1 else ''}, {h:2d}:{m:02d}"
              if delta.days else f"{h:2d}:{m:02d}")
        loads = self._loads()
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

    def _cmd_which(self, argv):
        names = [a for a in argv[1:] if a != "--"]
        if not self.tools or any(a.startswith("-") for a in names):
            return False, None                    # -a and friends: not modelled
        found = [self.tools.path_of(n) for n in names]
        self.status = 0 if names and all(found) else 1
        return True, "\n".join(p for p in found if p)

    def _cmd_command(self, argv):
        if not self.tools or len(argv) < 3 or argv[1] != "-v":
            return False, None
        out, ok = [], True
        for name in argv[2:]:
            kind = self.tools.kind(name)
            if kind in ("keyword", "builtin"):
                out.append(name)
            elif kind == "file":
                out.append(self.tools.path_of(name))
            else:
                ok = False
        self.status = 0 if ok else 1
        return True, "\n".join(out)

    def _cmd_type(self, argv):
        if not self.tools or len(argv) < 2 or any(a.startswith("-") for a in argv[1:]):
            return False, None
        lines, ok = [], True
        for name in argv[1:]:
            kind = self.tools.kind(name)
            if kind == "file":
                lines.append(f"{name} is {self.tools.path_of(name)}")
            elif kind:
                lines.append(f"{name} is a shell {kind}")
            else:
                lines.append(f"bash: type: {name}: not found")
                ok = False
        self.status = 0 if ok else 1
        return True, "\n".join(lines)

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
        if len(tokens) < 3 or tokens[0] not in ("echo", "cat") or tokens[-2] not in (">", ">>"):
            return None
        op, arg, words = tokens[-2], tokens[-1], tokens[1:-2]
        newline = True
        if tokens[0] == "cat":               # `cat src > dst` is a copy of what the register holds
            if len(words) != 1 or words[0].startswith("-"):
                return None
            ok, text = self._cmd_cat(["cat", words[0]])
            if not ok or text.startswith("cat: "):
                return None
            data = text.encode() + (b"\n" if text else b"")
        else:
            if ">" in "".join(words) or any(w.startswith("-") and w != "-n" for w in words[:1]):
                return None
            newline = not (words and words[0] == "-n")
            data = (" ".join(words[1:] if not newline else words) + ("\n" if newline else "")).encode()
        piece = data                         # what this command writes, before any append
        path = self._resolve(arg)
        if self.username != "root" and not self._may_write(path):
            return True, f"bash: {arg}: Permission denied"
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

    def _login_env(self, tool: str = "env"):
        """The environment sshd and pam_systemd hand a login shell on Ubuntu 20.04, or
        None when the SSH layer did not tell us the connection (then Cowrie answers)."""
        reg = self.reg
        ip, port, local = reg.session("ip"), reg.session("port"), reg.session("local_ip")
        if ip is None or local is None:
            return None
        user = self.users().get(self.username) or {}
        uid, term = user.get("uid", 0), reg.session("term")
        runtime = f"/run/user/{uid}"
        env = [("SHELL", user.get("shell", "/bin/bash")), ("PWD", reg.cwd()),
               ("LOGNAME", self.username)]
        if term:
            env += [("XDG_SESSION_TYPE", "tty"), ("MOTD_SHOWN", "pam")]
        env += [("HOME", user.get("home", "/root")), ("LANG", "en_US.UTF-8"),
                ("SSH_CONNECTION", f"{ip} {port} {local} {_SSH_PORT}"),
                ("XDG_SESSION_CLASS", "user")]
        if term:
            env.append(("TERM", term))
        env += [("USER", self.username), ("SHLVL", "1"),
                ("XDG_SESSION_ID", str(reg.session("logind_session"))),
                ("XDG_RUNTIME_DIR", runtime), ("SSH_CLIENT", f"{ip} {port} {_SSH_PORT}"),
                ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"),
                ("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime}/bus")]
        if term:
            env.append(("SSH_TTY", f"/dev/{reg.session('tty', 'pts/0')}"))
        exported = {k: self.inst.get("env", k) for k in self.inst.keys("env")}
        env = [(k, exported.pop(k, v)) for k, v in env] + sorted(exported.items())
        return env + [("_", f"/usr/bin/{tool}")]

    def _cmd_env(self, argv):
        return self._print_environ(argv, "env")

    def _print_environ(self, argv, tool):
        if len(argv) != 1:
            return False, None
        env = self._login_env(tool)
        if env is None:
            return False, None
        return True, "\n".join(f"{k}={v}" for k, v in env)

    def _value(self, name):
        if self.inst.get("env", name) is not None:
            return self.inst.get("env", name)
        if name in self.variables:
            return self.variables[name]
        login = self._login_env()
        if login is not None and name != "_":
            found = dict(login).get(name)
            if found is not None:
                return found
        home = (self.users().get(self.username) or {}).get("home", "/root")
        return {"HOME": home, "USER": self.username, "LOGNAME": self.username,
                "PWD": self.reg.cwd(), "SHELL": "/bin/bash",
                "HOSTNAME": self.hostname}.get(name)

    def _cmd_printenv(self, argv):
        if len(argv) == 1:
            return self._print_environ(argv, "printenv")
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
        self._job_table[self._jobs] = (pid, command)
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

    def _mem_pct(self, p) -> float:
        """%MEM: the process's RSS against the host's memory, as ps computes it."""
        total = ((self.hw or {}).get("memory_kb") or {}).get("total")
        return round(int(p.get("RSS") or 0) / 1024 / total * 100, 1) if total else float(p.get("MEM") or 0)

    def _rows(self, me: str):
        """The process table: base, the login shell, jobs, then this ps."""
        def hhmm(ns):
            return f"{datetime.fromtimestamp(ns / 1e9, tz=timezone.utc):%H:%M}"

        rows = []
        for p in self.processes:
            minutes = float(p.get("TIME") or 0)
            # init and kthreadd have no parent; kernel threads hang off kthreadd
            ppid = 0 if p["PID"] in (1, 2) else 2 if p["COMMAND"].startswith("[") else 1
            rows.append({"user": p["USER"], "pid": p["PID"], "ppid": ppid,
                         "cpu": float(p.get("CPU") or 0), "mem": self._mem_pct(p),
                         "vsz": int(p.get("VSZ") or 0) // 1024,
                         "rss": int(p.get("RSS") or 0) // 1024, "tty": p["TTY"],
                         "stat": p["STAT"], "start": p["START"], "comm": p.get("COMM"),
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
        rows.append({"user": self.username, "pid": self._screen_pid or self._new_pid(), "ppid": shell,
                     "cpu": 0.0, "mem": 0.0, "vsz": 5900, "rss": 2828, "tty": "pts/0",
                     "stat": "R+", "start": hhmm(self.reg.now_ns()), "time": 0,
                     "cmd": me})
        # the other stages of `ps aux | grep x` are running too, as the shell forks them
        for stage in self._peers:
            try:
                shown = " ".join(shlex.split(stage))
            except ValueError:
                shown = stage
            rows.append({"user": self.username, "pid": self._new_pid(), "ppid": shell,
                         "cpu": 0.0, "mem": 0.0, "vsz": 6432, "rss": 892, "tty": "pts/0",
                         "stat": "S+", "start": hhmm(self.reg.now_ns()), "time": 0,
                         "cmd": shown})
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
                f"{_ps_user(r['user']):<8} {r['pid']:>7} {r['ppid']:>7} {0:>2} {r['start']:>5} "
                f"{r['tty']:<8} {_hms(r['time'])} {r['cmd']}" for r in rows])
        return True, "\n".join(["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"] + [
            f"{_ps_user(r['user']):<8} {r['pid']:>7} {r['cpu']:>4.1f} {r['mem']:>4.1f} "
            f"{r['vsz']:>6} {r['rss']:>5} {r['tty']:<8} {r['stat']:<4} {r['start']:>5} "
            f"{r['time'] // 60:>3}:{r['time'] % 60:02d} {r['cmd']}" for r in rows])

    def _live_jobs(self):
        return [(n, pid, cmd) for n, (pid, cmd) in sorted(self._job_table.items())
                if self.inst.get("proc", pid) is not None]

    def _mark(self, n, live):
        """bash marks the newest job `+`, the one before it `-`."""
        numbers = [j for j, _, _ in live]
        return "+" if n == max(numbers) else "-" if len(numbers) > 1 and n == sorted(numbers)[-2] else " "

    def _cmd_kill(self, argv):
        args = argv[1:]
        # a signal name or number is allowed; `-1` (every process) is not ours to answer
        args = [a for a in args if not re.fullmatch(r"-(?:[2-9]|\d\d+|[A-Z]+)", a)]
        if not args or any(not (a.isdigit() or re.fullmatch(r"%\d+", a)) for a in args):
            return False, None
        out = []
        for a in args:
            if a.startswith("%"):
                n = int(a[1:])
                live = self._live_jobs()
                job = next(((j, p, c) for j, p, c in live if j == n), None)
                if job is None:
                    out.append(f"bash: kill: {a}: no such job")
                    continue
                pid, cmd = job[1], job[2]
                self._ended.append(f"[{n}]{self._mark(n, live)}  Terminated              {cmd}")
            else:
                pid = int(a)
                cmd = self.inst.get("proc", pid)
                if cmd is None:
                    return False, None
            self.reg.commit(remove={Fact("proc", pid, self.inst.get("proc", pid))},
                            why=f"kill {pid}")
            self.changed = True
        self.status = 1 if out else 0
        return True, "\n".join(out)

    def _cmd_jobs(self, argv):
        if len(argv) > 1:
            return False, None
        live = self._live_jobs()
        lines = self._ended + [f"[{n}]{self._mark(n, live)}  Running                 {cmd} &"
                               for n, _, cmd in live]
        self._ended = []
        return True, "\n".join(lines)

    # ── tar ────────────────────────────────────────────────────────────────

    _TAR_MAX = 300

    def _put_file(self, path, data, mode=0o644, mtime_ns=None, owner=None, group=None):
        """Create or overwrite a file with these bytes. False when its folder is unknown."""
        state, parent = self._parent(path)
        if state != "dir":
            return False
        add, remove = set(), set()
        old = self._kind(path)
        stamp = self.reg.now_ns()
        if old == "file":
            self.reg.ensure_meta(path)
            remove = {Fact(r, path, self.inst.get(r, path))
                      for r in ("content", "size", "mtime", "ctime", "mode")
                      if self.inst.get(r, path) is not None}
            add = {Fact("content", path, data), Fact("size", path, len(data)),
                   Fact("mode", path, mode), Fact("mtime", path, mtime_ns or stamp),
                   Fact("ctime", path, stamp)}
        elif old is None:
            add = self._fresh(path, "file", mode, content=data, stamp=mtime_ns or stamp)
            add = {f for f in add if f.rel != "ctime"} | {Fact("ctime", path, stamp)}
            if owner:
                add = {f for f in add if f.rel not in ("owner", "group")} | {
                    Fact("owner", path, owner), Fact("group", path, group or owner)}
            self._bump(parent, add, remove)
        else:
            return False
        return self.reg.commit(add, remove, why=f"write {path}")

    def _sync_bytes(self, path, data):
        b64 = base64.b64encode(data).decode()
        if len(b64) < 4000:
            self._replay(f"echo '{b64}' | base64 -d > {shlex.quote(path)}")
        else:
            self._replay(f"touch {shlex.quote(path)}")

    def _cmd_tar(self, argv):
        args = argv[1:]
        letters = args[0].lstrip("-") if args and not args[0].startswith("--") else ""
        if not re.fullmatch(r"[cxtzvf]+", letters) or "f" not in letters:
            return False, None
        modes = [m for m in "cxt" if m in letters]
        if len(modes) != 1 or ("t" in letters and "v" in letters):
            return False, None
        mode, gz, verbose = modes[0], "z" in letters, "v" in letters
        rest, dest, opts, i = args[1:], None, [], 0
        while i < len(rest):
            if rest[i] == "-C" and i + 1 < len(rest):
                dest, i = rest[i + 1], i + 2
            elif rest[i].startswith("-"):
                return False, None
            else:
                opts.append(rest[i])
                i += 1
        if not opts:
            return False, None
        archive_arg, operands = opts[0], opts[1:]
        archive = self._resolve(archive_arg)
        if self._virtual(archive):
            return False, None
        if mode == "c":
            return self._tar_create(archive_arg, archive, operands, gz, verbose)
        return self._tar_read(mode, archive_arg, archive, dest, verbose)

    def _tar_create(self, archive_arg, archive, operands, gz, verbose):
        if not operands:
            self.status = 2
            return True, ("tar: Cowardly refusing to create an empty archive\n"
                          "Try 'tar --help' or 'tar --usage' for more information.")
        members, errors, warned, names = [], [], False, []
        for op in operands:
            root = self._resolve(op)
            if self._kind(root) is None:
                if not self._missing(root):
                    return False, None
                errors.append(f"tar: {op}: Cannot stat: No such file or directory")
                continue
            warned = warned or op.startswith("/")
            base = op.lstrip("/").rstrip("/") or "."
            for q in self._tree(root):
                if q == archive:
                    errors.append(f"tar: {archive_arg}: file is the archive; not dumped")
                    continue
                self.reg.ensure_meta(q)
                kind = self._kind(q)
                data = self.inst.get("content", q) if kind == "file" else b""
                if data is None or len(members) >= self._TAR_MAX:
                    return False, None             # bytes we do not hold: not ours to archive
                members.append((base + q[len(root):], q, kind, data))
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
            for name, q, kind, data in members:
                info = tarfile.TarInfo(name + ("/" if kind == "dir" else ""))
                info.mode = (self.inst.get("mode", q) or 0o644) & 0o7777
                info.mtime = int((self.inst.get("mtime", q) or 0) / 1e9)
                owner, group = self.inst.get("owner", q) or "root", self.inst.get("group", q) or "root"
                info.uname, info.gname = owner, group
                info.uid, info.gid = self._uid(owner), self._gid(group)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    info.type, info.linkname = tarfile.SYMTYPE, self.inst.get("target", q) or ""
                else:
                    info.size = len(data)
                tf.addfile(info, io.BytesIO(data) if kind == "file" else None)
                names.append(info.name)
        data = buf.getvalue()
        if gz:
            data = bytearray(gzip.compress(data, compresslevel=6, mtime=self.reg.now_ns() // 10**9))
            data[9] = 3                                      # gzip's OS byte: Unix
            data = bytes(data)
        if not self._put_file(archive, data):
            state, _ = self._parent(archive)
            if state == "unknown" or self._kind(archive) not in (None, "file"):
                return False, None
            self.status = 2
            return True, (f"tar: {archive_arg}: Cannot open: "
                          + ("Not a directory" if state == "notdir" else "No such file or directory")
                          + "\ntar: Error is not recoverable: exiting now")
        self._sync_bytes(archive, data)
        self.changed = True
        lines = (["tar: Removing leading `/' from member names"] if warned else [])
        lines += names if verbose else []
        lines += errors + (["tar: Exiting with failure status due to previous errors"] if errors else [])
        self.status = 2 if errors else 0
        return True, "\n".join(lines)

    def _tar_read(self, mode, archive_arg, archive, dest, verbose):
        if self._kind(archive) is None:
            if not self._missing(archive):
                return False, None
            self.status = 2
            return True, (f"tar: {archive_arg}: Cannot open: No such file or directory\n"
                          "tar: Error is not recoverable: exiting now")
        data = self.inst.get("content", self._target(archive) or archive)
        if data is None:
            return False, None
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
            members = tf.getmembers()
        except (tarfile.TarError, OSError, EOFError):
            return False, None
        if len(members) > self._TAR_MAX:
            return False, None
        listing = [m.name + ("/" if m.isdir() and not m.name.endswith("/") else "") for m in members]
        if mode == "t":
            return True, "\n".join(listing)
        root = self._resolve(dest) if dest else self.reg.cwd()
        if self._virtual(root) or self._kind(root) != "dir":
            return False, None
        for m in members:
            path = posixpath.normpath(posixpath.join(root, m.name.lstrip("/")))
            if m.isdir():
                if self._kind(path) is None:
                    handled, _ = self._cmd_mkdir(["mkdir", "-p", path])
                    if not handled:
                        return False, None
            elif m.isfile():
                folder = posixpath.dirname(path)
                if self._kind(folder) is None:
                    self._cmd_mkdir(["mkdir", "-p", folder])
                body = tf.extractfile(m).read()
                if not self._put_file(path, body, m.mode & 0o7777, int(m.mtime) * 10**9,
                                      m.uname or "root", m.gname or m.uname or "root"):
                    return False, None
                self._sync_bytes(path, body)
        self.changed = True
        return True, "\n".join(listing) if verbose else ""

    def _cmd_crontab(self, argv):
        """`crontab -l`, `-r`, and installing a file, kept as the account's crontab file."""
        user = self.username
        path = f"/var/spool/cron/crontabs/{user}"
        args = argv[1:]
        if args == ["-l"] or args == ["-r"]:
            data = self.inst.get("content", path)
            if self._kind(path) != "file" or data is None:
                self.status = 1
                return True, f"no crontab for {user}"
            if args == ["-r"]:
                self.reg.delete_record(path)
                self.changed = True
                self._replay(f"rm -f {shlex.quote(path)}")
                return True, ""
            return True, data.decode("utf-8", "replace").rstrip("\n")
        if len(args) == 1 and not args[0].startswith("-"):
            src = self._resolve(args[0])
            real = self._target(src) if self._kind(src) else None
            data = self.inst.get("content", real) if real else None
            if real is None:
                if self._missing(src):
                    self.status = 1
                    return True, f"{args[0]}: No such file or directory"
                return False, None
            if data is None:
                return False, None
            folder = posixpath.dirname(path)
            if self._kind(folder) != "dir":
                self._cmd_mkdir(["mkdir", "-p", folder])
            add, remove = self._fresh(path, "file", 0o600, content=data), set()
            old = self._kind(path)
            if old is not None:
                remove |= {f for f in self.inst.facts() if f.key == path and f.rel != "listed"}
            if not self.reg.commit(add, remove, why="crontab install"):
                return False, None
            self.changed = True
            self._replay(f"cp {shlex.quote(real)} {shlex.quote(path)}")
            return True, ""
        return False, None

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
