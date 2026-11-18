"""
experiment_data/PartC/oscar/oracle.py — transcript-only contradiction oracle.

Counts contradictions in a (command, output) transcript the way Gil et al.,
"OSCAR", IEEE TDSC 2026, Sec. VI-A evaluates: it reconstructs what the
attacker's own commands established and flags outputs that disagree.

IMPORT-ISOLATED ON PURPOSE: this file must not import HydraPoT (no shell/,
no world-state, no gate). It reads only the transcript, so the honeypot is
never graded by its own consistency machinery.

Signatures checked (the paper's five filesystem-tree ones):
    deny_created   a path the session created is reported missing
    content        a re-read returns different content than written/read
    reappear       a removed path reads back
    cwd            pwd disagrees with the cd history
    ls_omit        ls of a directory leaves out an entry the session created
"""
import posixpath
import re
import shlex

_DENIAL = re.compile(r"no such file|not found|does not exist|"
                     r"cannot (?:access|stat|open|remove)", re.I)


class Oracle:
    def __init__(self, home: str = "/root"):
        self.home = home
        self.cwd = home
        self.files = {}          # path -> known content (None = exists, unknown)
        self.dirs = set()        # directories the session created
        self.removed = set()
        self.contradictions = []

    def _abs(self, path: str) -> str:
        if path == "~" or path.startswith("~/"):
            path = self.home + path[1:]
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        return posixpath.normpath(path)

    def _flag(self, seq, kind, cmd, detail):
        self.contradictions.append({"seq": seq, "signature": kind,
                                    "cmd": cmd, "detail": detail})

    def _exists(self, path):
        return path in self.files or path in self.dirs

    def observe(self, seq: int, cmd: str, output: str) -> None:
        """Check one turn against what earlier turns established, then learn from it."""
        output = (output or "").replace("\r\n", "\n")
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return
        if not argv or any(t in cmd for t in ("|", ";", "&&", "`", "$(")):
            return
        base, args = argv[0], [a for a in argv[1:] if not a.startswith("-")]
        denied = bool(_DENIAL.search(output))

        # ── checks ──
        for arg in args:
            path = self._abs(arg)
            if denied and self._exists(path) and _names(output, arg):
                self._flag(seq, "deny_created", cmd, f"{path} was created")
        if base == "cat" and len(args) == 1 and ">" not in cmd:
            path = self._abs(args[0])
            if path in self.removed and not denied:
                self._flag(seq, "reappear", cmd, f"{path} was removed")
            elif path in self.files and not denied:
                known = self.files[path]
                got = output.rstrip("\n")
                if known is not None and got != known:
                    self._flag(seq, "content", cmd, f"expected {known!r}, got {got!r}")
                if known is None:
                    self.files[path] = got
        if base == "pwd" and output.strip() and output.strip() != self.cwd:
            self._flag(seq, "cwd", cmd, f"expected {self.cwd}, got {output.strip()}")
        if base == "ls" and not denied and not any(a.startswith("-") for a in argv[1:]):
            target = self._abs(args[0]) if args else self.cwd
            if target in self.dirs:
                shown = set(output.split())
                for child in self._children(target):
                    if child not in shown:
                        self._flag(seq, "ls_omit", cmd, f"{child} missing from {target}")

        # ── learn ──
        if denied:
            return
        m = re.match(r"^echo\s+(-n\s+)?(.*?)\s*(>>|>)\s*(\S+)$", cmd)
        if m:
            text = _unquote(m.group(2))
            path = self._abs(m.group(4))
            old = self.files.get(path) if m.group(3) == ">>" else None
            self.files[path] = text if old is None else old + "\n" + text
            self.removed.discard(path)
        elif base == "touch":
            for arg in args:
                path = self._abs(arg)
                if path not in self.files:
                    self.files[path] = ""
                self.removed.discard(path)
        elif base == "mkdir":
            for arg in args:
                path = self._abs(arg)
                self.dirs.add(path)
                self.removed.discard(path)
        elif base == "rm":
            for arg in args:
                path = self._abs(arg)
                for p in [p for p in self.files if p == path or p.startswith(path + "/")]:
                    del self.files[p]
                    self.removed.add(p)
                self.dirs = {d for d in self.dirs if d != path and not d.startswith(path + "/")}
                self.removed.add(path)
        elif base == "cd":
            if not output.strip():
                self.cwd = self._abs(args[0]) if args else self.home

    def _children(self, directory):
        out = set()
        for p in list(self.files) + list(self.dirs):
            if posixpath.dirname(p) == directory:
                out.add(posixpath.basename(p))
        return out


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _names(line_block: str, arg: str) -> bool:
    return re.search(rf"(?<![\w./-]){re.escape(arg)}(?![\w./-])", line_block) is not None


def count(transcript) -> list:
    """Contradictions in a [(cmd, output), ...] transcript."""
    oracle = Oracle()
    for seq, (cmd, out) in enumerate(transcript):
        oracle.observe(seq, cmd, out)
    return oracle.contradictions
