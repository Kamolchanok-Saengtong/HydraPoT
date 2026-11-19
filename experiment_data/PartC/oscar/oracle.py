"""
experiment_data/PartC/oscar/oracle.py — transcript-only contradiction oracle.

Counts contradictions in a (command, output) transcript the way Gil et al.,
"OSCAR", IEEE TDSC 2026, Sec. VI-A evaluates: it reconstructs what the
attacker's own commands established and flags outputs that disagree.

IMPORT-ISOLATED ON PURPOSE: this file must not import HydraPoT (no shell/,
no world-state, no gate). It reads only the transcript, so the honeypot is
never graded by its own consistency machinery.

The twelve signatures of the paper (Sec. VI-A, Table II):

  filesystem tree
    deny_created   a path the session created is reported missing
    content        a re-read returns different content than written/read
    reappear       a removed path reads back
    cwd            pwd disagrees with the cd history
    ls_omit        a listing leaves out an entry the session created
  semantic couplings
    size           ls -l / stat / wc -c size disagrees with the bytes written
    disk           du ignores a written file
    time_inode     a timestamp or inode shifts with no write in between
    mode           a mode a chmod did not produce
    symlink        a link resolves against something other than its target
    proc           a process the session started is absent from ps
    env            an exported variable a later read drops
"""
import posixpath
import re
import shlex

SIGNATURES = ("deny_created", "content", "reappear", "cwd", "ls_omit",
              "size", "disk", "time_inode", "mode", "symlink", "proc", "env")

_DENIAL = re.compile(r"no such file|not found|does not exist|"
                     r"cannot (?:access|stat|open|remove)", re.I)
_LS_LINE = re.compile(r"^([-dlcbps][-rwxsStT]{9})[.+@]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+"
                      r"(\S+\s+\d+\s+[\d:]+)\s+(.+?)(?: -> (.+))?$")
_STAT = {
    "size": re.compile(r"Size:\s*(\d+)"),
    "inode": re.compile(r"Inode:\s*(\d+)"),
    "perms": re.compile(r"Access:\s*\(\d+/([-dlrwxsStT]{10})\)"),
    "mtime": re.compile(r"Modify:\s*(.+)"),
}


def _octal_to_perms(mode: str, kind: str = "-") -> str:
    bits = int(mode, 8)
    out = kind
    for i, ch in enumerate("rwxrwxrwx"):
        out += ch if bits & (1 << (8 - i)) else "-"
    return out


class Oracle:
    def __init__(self, home: str = "/root"):
        self.home = home
        self.cwd = home
        self.files = {}          # path -> known content (None = exists, unknown)
        self.sizes = {}          # path -> bytes the session wrote
        self.dirs = set()        # directories the session created
        self.removed = set()
        self.links = {}          # link path -> target as written
        self.modes = {}          # path -> perms a chmod produced
        self.seen = {}           # (path, attr) -> first value observed since the last write
        self.env = {}
        self.seen_reads = {}     # path -> first content read (files not created here)
        self.procs = set()
        self.contradictions = []

    # ── helpers ────────────────────────────────────────────────────────────

    def _abs(self, path: str, base: str = None) -> str:
        if path == "~" or path.startswith("~/"):
            path = self.home + path[1:]
        if not path.startswith("/"):
            path = posixpath.join(base or self.cwd, path)
        return posixpath.normpath(path)

    def _flag(self, seq, kind, cmd, detail):
        self.contradictions.append({"seq": seq, "signature": kind,
                                    "cmd": cmd, "detail": detail})

    def _exists(self, path):
        return path in self.files or path in self.dirs or path in self.links

    def _written(self, path):
        """A write: earlier timestamps/sizes no longer bind."""
        for attr in ("size", "mtime", "inode"):
            self.seen.pop((path, attr), None)

    def _stable(self, seq, cmd, path, attr, value, signature):
        """First observation is the baseline; later ones must match it."""
        key = (path, attr)
        if key in self.seen and self.seen[key] != value:
            self._flag(seq, signature, cmd,
                       f"{path} {attr} was {self.seen[key]!r}, now {value!r}")
        self.seen.setdefault(key, value)

    def _check_size(self, seq, cmd, path, size, signature="size"):
        if path in self.links:
            return
        if self.sizes.get(path) is not None and size != self.sizes[path]:
            self._flag(seq, signature, cmd,
                       f"{path} has {self.sizes[path]} bytes, shown {size}")
        else:
            self._stable(seq, cmd, path, "size", size, signature)

    def _check_perms(self, seq, cmd, path, perms):
        if path in self.modes and perms[1:] != self.modes[path][1:]:
            self._flag(seq, "mode", cmd, f"{path} chmod gave {self.modes[path]}, shown {perms}")
        elif path not in self.modes:
            self._stable(seq, cmd, path, "perms", perms[1:], "mode")

    def _children(self, directory):
        return {posixpath.basename(p) for p in
                list(self.files) + list(self.dirs) + list(self.links)
                if posixpath.dirname(p) == directory}

    # ── one turn ───────────────────────────────────────────────────────────

    def observe(self, seq: int, cmd: str, output: str) -> None:
        """Check one turn against what earlier turns established, then learn."""
        output = (output or "").replace("\r\n", "\n")
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return
        if not argv or any(t in cmd for t in ("|", ";", "&&", "`", "$(")):
            return
        base = argv[0]
        flags = [a for a in argv[1:] if a.startswith("-")]
        args = [a for a in argv[1:] if not a.startswith("-") and a != "&"]
        denied = bool(_DENIAL.search(output))
        self._check(seq, cmd, base, flags, args, output, denied)
        if not denied:
            self._learn(cmd, base, flags, args, output)

    def _check(self, seq, cmd, base, flags, args, output, denied):
        for arg in args:
            path = self._abs(arg)
            if denied and self._exists(path) and _names(output, arg):
                self._flag(seq, "deny_created", cmd, f"{path} was created")
        if denied:
            return

        if base == "cat" and len(args) == 1 and ">" not in cmd:
            path = self._abs(args[0])
            got = output.rstrip("\n")
            if path in self.links:
                target = self._abs(self.links[path], posixpath.dirname(path))
                known = self.files.get(target)
                if known is not None and got != known:
                    self._flag(seq, "symlink", cmd, f"{path} -> {target}, read {got!r}")
            elif path in self.removed:
                self._flag(seq, "reappear", cmd, f"{path} was removed")
            elif path in self.files:
                known = self.files[path]
                # Logs grow by appending; rewriting earlier lines is still a lie
                grew = (known is not None and path.startswith("/var/log/")
                        and got.startswith(known))
                if known is not None and got != known and not grew:
                    self._flag(seq, "content", cmd, f"expected {known!r}, got {got!r}")
                if known is None or grew:
                    self.files[path] = got
            else:
                # Any file read once is a baseline for its next read
                self.seen_reads[path] = self.seen_reads.get(path, got)
                known = self.seen_reads[path]
                grew = path.startswith("/var/log/") and got.startswith(known)
                if got != known and not grew:
                    self._flag(seq, "content", cmd, f"{path} read {known!r}, now {got!r}")
                elif grew:
                    self.seen_reads[path] = got

        if base == "pwd" and output.strip() and output.strip() != self.cwd:
            self._flag(seq, "cwd", cmd, f"expected {self.cwd}, got {output.strip()}")

        if base == "ls":
            self._check_ls(seq, cmd, flags, args, output)
        if base == "stat" and len(args) == 1:
            path = self._abs(args[0])
            for attr, rx in _STAT.items():
                m = rx.search(output)
                if not m:
                    continue
                if attr == "size":
                    self._check_size(seq, cmd, path, int(m.group(1)))
                elif attr == "perms":
                    self._check_perms(seq, cmd, path, m.group(1))
                else:
                    self._stable(seq, cmd, path, attr, m.group(1).strip(), "time_inode")
        if base == "wc" and "-c" in flags and len(args) == 1:
            m = re.match(r"^\s*(\d+)", output)
            if m:
                self._check_size(seq, cmd, self._abs(args[0]), int(m.group(1)))
        if base == "du" and len(args) == 1:
            m = re.match(r"^(\d+)", output)
            if m and any("b" in f for f in flags):
                path, used = self._abs(args[0]), int(m.group(1))
                if path in self.files:
                    self._check_size(seq, cmd, path, used, "disk")
                else:
                    floor = sum(s or 0 for p, s in self.sizes.items()
                                if p.startswith(path.rstrip("/") + "/"))
                    if used < floor:
                        self._flag(seq, "disk", cmd, f"{path} holds >= {floor} bytes, du says {used}")
        if base == "readlink" and len(args) == 1:
            path = self._abs(args[0])
            if path in self.links and output.strip() != self.links[path]:
                self._flag(seq, "symlink", cmd, f"{path} -> {self.links[path]}, shown {output.strip()}")
        if base == "printenv" and len(args) == 1 and args[0] in self.env:
            if output.strip() != self.env[args[0]]:
                self._flag(seq, "env", cmd, f"{args[0]}={self.env[args[0]]}, read {output.strip()!r}")
        m = re.match(r"^echo\s+\$\{?(\w+)\}?$", cmd.strip())
        if m and m.group(1) in self.env and output.strip() != self.env[m.group(1)]:
            self._flag(seq, "env", cmd, f"{m.group(1)}={self.env[m.group(1)]}, read {output.strip()!r}")
        if base == "ps":
            for proc in self.procs:
                if proc not in output:
                    self._flag(seq, "proc", cmd, f"{proc!r} missing from ps")

    def _check_ls(self, seq, cmd, flags, args, output):
        target = self._abs(args[0]) if args else self.cwd
        long = any("l" in f for f in flags)
        if not long:
            if not flags and target in self.dirs:
                shown = set(output.split())
                for child in self._children(target):
                    if child not in shown:
                        self._flag(seq, "ls_omit", cmd, f"{child} missing from {target}")
            return
        listing_dir = target if (target in self.dirs or not args
                                 or output.startswith("total")) else None
        shown = set()
        for line in output.splitlines():
            m = _LS_LINE.match(line.strip())
            if not m:
                continue
            perms, size, mtime, name, link_to = m.groups()
            path = self._abs(name, listing_dir) if listing_dir else self._abs(name)
            shown.add(posixpath.basename(path))
            if perms[0] == "-":
                self._check_size(seq, cmd, path, int(size))
                self._stable(seq, cmd, path, "ls_mtime", mtime, "time_inode")
            if perms[0] in "-d":
                self._check_perms(seq, cmd, path, perms)
            if path in self.links and link_to is not None and link_to != self.links[path]:
                self._flag(seq, "symlink", cmd, f"{path} -> {self.links[path]}, shown {link_to}")
        if listing_dir and listing_dir in self.dirs:
            for child in self._children(listing_dir):
                if child not in shown:
                    self._flag(seq, "ls_omit", cmd, f"{child} missing from {listing_dir}")

    def _learn(self, cmd, base, flags, args, output):
        m = re.match(r"^echo\s+(-n\s+)?(.*?)\s*(>>|>)\s*(\S+)$", cmd)
        if m:
            text, path = _unquote(m.group(2)), self._abs(m.group(4))
            nbytes = len(text.encode()) + (0 if m.group(1) else 1)
            if m.group(3) == ">>" and path in self.files:
                old = self.files[path]
                self.files[path] = None if old is None else old + "\n" + text
                prev = self.sizes.get(path)
                self.sizes[path] = None if prev is None else prev + nbytes
            else:
                self.files[path], self.sizes[path] = text, nbytes
            self.removed.discard(path)
            self._written(path)
            return
        if base == "touch":
            for arg in args:
                path = self._abs(arg)
                if path not in self.files:
                    self.files[path], self.sizes[path] = "", 0
                self.removed.discard(path)
                self._written(path)
        elif base == "mkdir":
            for arg in args:
                path = self._abs(arg)
                self.dirs.add(path)
                self.removed.discard(path)
        elif base == "rm":
            for arg in args:
                path = self._abs(arg)
                for table in (self.files, self.sizes, self.links, self.modes):
                    for p in [p for p in table if p == path or p.startswith(path + "/")]:
                        del table[p]
                        self.removed.add(p)
                self.dirs = {d for d in self.dirs if d != path and not d.startswith(path + "/")}
                self.removed.add(path)
        elif base == "cd":
            if not output.strip():
                self.cwd = self._abs(args[0]) if args else self.home
        elif base == "chmod" and len(args) == 2:
            path = self._abs(args[1])
            if re.fullmatch(r"[0-7]{3}", args[0]):
                self.modes[path] = _octal_to_perms(args[0])
            else:
                self.modes.pop(path, None)
                self.seen.pop((path, "perms"), None)
        elif base == "ln" and "-s" in flags and len(args) == 2:
            self.links[self._abs(args[1])] = args[0]
            self.removed.discard(self._abs(args[1]))
        elif base == "export" and args and "=" in args[0]:
            name, value = args[0].split("=", 1)
            self.env[name] = _unquote(value)
        elif cmd.rstrip().endswith("&") and not cmd.rstrip().endswith("&&"):
            self.procs.add(cmd.rstrip()[:-1].strip())
        elif base == "kill":
            self.procs.clear()


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _names(block: str, arg: str) -> bool:
    return re.search(rf"(?<![\w./-]){re.escape(arg)}(?![\w./-])", block) is not None


def count(transcript) -> list:
    """Contradictions in a [(cmd, output), ...] transcript."""
    oracle = Oracle()
    for seq, (cmd, out) in enumerate(transcript):
        oracle.observe(seq, cmd, out)
    return oracle.contradictions
