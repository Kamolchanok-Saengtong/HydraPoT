"""
shell/register.py — the System State Register for one session.

Holds the world-state of shell/world.py and is the only way it changes:
every change is checked against Sigma (Def. 1), committed as a transition
(Def. 2) and logged as +/- fact rows. A refused change is logged with the
constraint it broke. Replaying the rows rebuilds the state at any command, so
a session is reproducible from its seed and its log, as in Gil et al.,
"OSCAR", IEEE TDSC 2026 (DOI 10.1109/TDSC.2026.3749501).

The old SYSTEM_STATE dict API (files, cwd) is kept as a view over the facts
so existing modules keep working while they move over one at a time.
"""
import base64
import hashlib
import hmac
import posixpath
import re
import time
from collections.abc import MutableMapping

from prompt.prompt_manager import _decode_echo_payload
from shell.world import Fact, Instance, Proposal, chase, feasible

_TYPE = {"-": "file", "d": "dir", "l": "symlink"}
_TYPE_CHAR = {v: k for k, v in _TYPE.items()}
# File attributes an old-style record replaces as a whole
_RECORD_RELS = ("content", "size", "raw", "size_text", "backend", "source")
# echo ends its output with a newline unless -n is given
_ECHO_NO_NEWLINE = re.compile(r"^-[a-zA-Z]*n[a-zA-Z]*\s")
_TIMES = ("mtime", "atime", "ctime")
# Relations not keyed by a path
_NON_PATH = frozenset({"user", "uid", "gid", "home", "shell", "env", "proc", "cwd"})


def perms_to_mode(perms: str):
    """'-rwxr-xr-x' -> ('file', 0o755)."""
    kind = _TYPE.get(perms[:1], "file")
    mode = 0
    for i, ch in enumerate(perms[1:10]):
        if ch in "rwxst":
            mode |= 1 << (8 - i)
        if ch in "sS" and i == 2:
            mode |= 0o4000
        if ch in "sS" and i == 5:
            mode |= 0o2000
        if ch in "tT" and i == 8:
            mode |= 0o1000
    if perms[3:4] == "S":
        mode &= ~0o100
    if perms[6:7] == "S":
        mode &= ~0o010
    if perms[9:10] == "T":
        mode &= ~0o001
    return kind, mode


def mode_to_perms(kind: str, mode: int) -> str:
    """('file', 0o755) -> '-rwxr-xr-x'."""
    out = [_TYPE_CHAR.get(kind, "-")]
    for i, ch in enumerate("rwxrwxrwx"):
        out.append(ch if mode & (1 << (8 - i)) else "-")
    for pos, bit, on, off in ((3, 0o4000, "s", "S"), (6, 0o2000, "s", "S"),
                              (9, 0o1000, "t", "T")):
        if mode & bit:
            out[pos] = on if out[pos] == "x" else off
    return "".join(out)


def file_bytes(raw: str) -> bytes:
    """The bytes an `echo` record really wrote, including its newline."""
    data = _decode_echo_payload(raw)
    if raw.strip() and not _ECHO_NO_NEWLINE.match(raw.strip()):
        data += b"\n"
    return data


def _encode(value):
    if isinstance(value, bytes):
        return {"b64": base64.b64encode(value).decode()}
    return value


def _decode(value):
    if isinstance(value, dict) and "b64" in value:
        return base64.b64decode(value["b64"])
    return value


def _order(fact: Fact):
    return fact.rel, str(fact.key)


class Register:
    """One session's world-state and its change log.

        reg = Register(seed, writer=telemetry.record_state)
        reg.begin(seq, cmd)
        reg.commit(add={Fact("kind", "/tmp/x", "file")})
        reg.flush()                     # writes the +/- rows
    """

    def __init__(self, seed: bytes = b"", writer=None):
        self.inst = chase(Instance())
        self.before = self.inst
        self.seed = seed
        # -1 = before the first command, matching storage.sessions' seq from 0
        self.seq = -1
        self.cmd = ""
        self.loaded = False          # after the profile, new dirs are attacker-made
        self.violations = []
        self._rows = [{"seq": -1, "op": "seed", "rel": "", "key": "",
                       "value": seed.hex()}]
        self.writer = writer
        self.clock = time.time_ns
        self.epoch_ns = self.clock()

    # ── deterministic metadata ─────────────────────────────────────────────

    def prf(self, label: str, path: str, lo: int, hi: int) -> int:
        """Same seed, same path, same number: metadata stays stable."""
        digest = hmac.new(self.seed, f"{label}\0{path}".encode(), hashlib.sha256).digest()
        return lo + int.from_bytes(digest[:8], "big") % (hi - lo + 1)

    def new_inode(self, path: str) -> int:
        used = {self.inst.get("inode", p) for p in self.inst.keys("inode")}
        inode = self.prf("inode", path, 100_000, 9_999_999)
        while inode in used:
            inode += 1
        return inode

    def now_ns(self) -> int:
        return self.clock()

    def past_ns(self, path: str) -> int:
        """A creation time before the session, for files the box shipped with."""
        age = self.prf("age", path, 86_400, 300 * 86_400)
        return self.epoch_ns - age * 1_000_000_000 - self.prf("ns", path, 0, 999_999_999)

    def ensure_meta(self, path: str) -> None:
        """Give an existing path the inode and times it lacks, once (eps3)."""
        if self.inst.get("kind", path) is None:
            return
        add = set()
        if self.inst.get("inode", path) is None:
            add.add(Fact("inode", path, self.new_inode(path)))
        when = self.past_ns(path)
        for rel in _TIMES:
            if self.inst.get(rel, path) is None:
                add.add(Fact(rel, path, when))
        if add:
            self.commit(add, why=f"meta {path}")

    def begin(self, seq: int, cmd: str) -> None:
        self.seq, self.cmd = seq, cmd
        # I_t for Def. 1: claims are checked against the state BEFORE this
        # command's effects (instances are replaced, never mutated)
        self.before = self.inst

    # ── transitions ────────────────────────────────────────────────────────

    def commit(self, add=(), remove=(), why: str = "") -> bool:
        """Apply a change if Sigma allows it; refuse and log it otherwise."""
        verdict = feasible(self.inst, Proposal("", frozenset(add), frozenset(remove)))
        if not verdict.ok:
            self.refuse(verdict.reason, why)
            return False
        self.adopt(verdict.successor)
        return True

    def adopt(self, successor: Instance) -> None:
        """Make an already-checked successor current and log the difference."""
        old, new = set(self.inst.facts()), set(successor.facts())
        # Removals first, so replaying the rows in order never conflicts
        for fact in sorted(old - new, key=_order):
            self._rows.append(self._row("-", fact))
        for fact in sorted(new - old, key=_order):
            self._rows.append(self._row("+", fact))
        self.inst = successor

    def checkpoint(self):
        """A point to return to: a script that cannot be finished leaves no trace."""
        return (self.inst, len(self._rows), len(self.violations))

    def rollback(self, point) -> None:
        self.inst = point[0]
        del self._rows[point[1]:]
        del self.violations[point[2]:]

    def refuse(self, reason: str, why: str = "") -> None:
        entry = {"seq": self.seq, "cmd": self.cmd, "reason": reason, "why": why}
        self.violations.append(entry)
        self._rows.append({"seq": self.seq, "op": "!", "rel": "violation",
                           "key": why, "value": reason})

    def note(self, op: str, record: dict) -> None:
        """Log a non-state event for this command, e.g. a gate decision."""
        self._rows.append({"seq": self.seq, "op": op,
                           "rel": record.get("status", ""),
                           "key": record.get("source", ""), "value": record})

    def _row(self, op, fact):
        return {"seq": self.seq, "op": op, "rel": fact.rel,
                "key": _encode(fact.key), "value": _encode(fact.value)}

    def flush(self):
        """Hand the rows logged since the last flush to the writer."""
        rows, self._rows = self._rows, []
        if rows and self.writer:
            self.writer(rows)
        return rows

    @staticmethod
    def replay(rows, upto_seq=None) -> Instance:
        """Rebuild the world-state from logged rows, up to a command if given."""
        inst = Instance()
        for row in rows:
            if upto_seq is not None and row["seq"] > upto_seq:
                break
            if row["op"] not in "+-" or not row["op"]:
                continue
            fact = Fact(row["rel"], _decode(row["key"]), _decode(row["value"]))
            if row["op"] == "+":
                inst.add(fact)
            else:
                inst.remove(fact)
        return inst

    # ── old-style records ──────────────────────────────────────────────────

    def write_record(self, path: str, rec: dict) -> bool:
        """Store an old SYSTEM_STATE["files"] record as facts."""
        inst = self.inst
        add, remove = set(), set()
        is_new = inst.get("kind", path) is None
        old_content, old_mode = inst.get("content", path), inst.get("mode", path)
        new_data, new_mode = None, None
        for rel in _RECORD_RELS:
            cur = inst.get(rel, path)
            if cur is not None:
                remove.add(Fact(rel, path, cur))

        perms = rec.get("perms")
        kind = inst.get("kind", path) or "file"
        if perms:
            kind, mode = perms_to_mode(perms)
            new_mode = mode
            if inst.get("mode", path) is not None:
                remove.add(Fact("mode", path, inst.get("mode", path)))
            add.add(Fact("mode", path, mode))
        if inst.get("kind", path) not in (None, kind):
            remove.add(Fact("kind", path, inst.get("kind", path)))
        add.add(Fact("kind", path, kind))

        raw = rec.get("content")
        if raw is not None:
            add.add(Fact("raw", path, raw))
            # Cowrie holds the real bytes of its downloads; ours is a placeholder
            if (kind == "file" and rec.get("backend") != "cowrie"
                    and not str(raw).startswith("[downloaded from")):
                new_data = file_bytes(raw)
                add |= {Fact("content", path, new_data), Fact("size", path, len(new_data))}
        for rel, field in (("size_text", "size"), ("backend", "backend"),
                           ("source", "source")):
            if rec.get(field) is not None:
                add.add(Fact(rel, path, rec[field]))
        if not inst.get("listed", path):
            add.add(Fact("listed", path))
            if kind == "dir" and self.loaded:
                add.add(Fact("sealed", path))

        # A write moves mtime and ctime; a chmod moves only ctime
        when = self.now_ns() if self.loaded else self.past_ns(path)
        if is_new:
            add.add(Fact("inode", path, self.new_inode(path)))
            add |= {Fact(rel, path, when) for rel in _TIMES}
        else:
            moved = (("mtime", "ctime") if new_data is not None and new_data != old_content
                     else ("ctime",) if new_mode is not None and new_mode != old_mode else ())
            for rel in moved:
                if inst.get(rel, path) is not None:
                    remove.add(Fact(rel, path, inst.get(rel, path)))
                add.add(Fact(rel, path, when))
        return self.commit(add, remove, why=f"write {path}")

    def delete_record(self, path: str) -> bool:
        """The path and everything under it are gone."""
        prefix = path.rstrip("/") + "/"
        remove = {f for f in self.inst.facts()
                  if f.rel not in _NON_PATH and isinstance(f.key, str)
                  and (f.key == path or f.key.startswith(prefix))}
        return self.commit({Fact("absent", path)}, remove, why=f"delete {path}")

    def cwd(self) -> str:
        return self.inst.get("cwd", "session")

    def set_cwd(self, path: str) -> bool:
        path = posixpath.normpath(path)
        cur = self.cwd()
        remove = {Fact("cwd", "session", cur)} if cur is not None else set()
        return self.commit({Fact("cwd", "session", path)}, remove, why=f"cd {path}")

    def start_session(self, ip: str, user: str, tty: str = "pts/0",
                      pid_floor: int = 1000) -> None:
        """Record this login once; logs, ps, who and last all read it."""
        sshd = pid_floor + self.prf("sshd_pid", "session", 20, 400)
        facts = {
            "ip": ip, "user": user, "tty": tty, "login_ns": self.epoch_ns,
            "port": self.prf("port", "session", 32768, 60999),
            "sshd_pid": sshd, "shell_pid": sshd + self.prf("shell_pid", "session", 2, 9),
            "logind_session": self.prf("logind", "session", 2, 60),
        }
        self.commit({Fact("session", k, v) for k, v in facts.items()}, why="login")

    def session(self, key, default=None):
        value = self.inst.get("session", key)
        return default if value is None else value

    def load_profile(self, starting_files: dict, known_dirs=()) -> None:
        """The box as it ships: known directories and pre-seeded files."""
        for path in known_dirs:
            if self.inst.get("kind", path) is None:
                self.commit({Fact("kind", path, "dir")}, why=f"profile {path}")
        for path, rec in starting_files.items():
            self.write_record(path, dict(rec))
        self.loaded = True


class RecordView(MutableMapping):
    """One old-style file record, read from and written to the facts."""

    _FIELDS = ("content", "perms", "size", "backend", "source")

    def __init__(self, reg: Register, path: str):
        self._reg, self._path = reg, path

    def __getitem__(self, field):
        inst, path = self._reg.inst, self._path
        if field == "perms":
            kind, mode = inst.get("kind", path), inst.get("mode", path)
            if kind is None or mode is None:
                raise KeyError(field)
            return mode_to_perms(kind, mode)
        if field == "size":
            text = inst.get("size_text", path)
            if text is None and inst.get("size", path) is not None:
                text = f"{inst.get('size', path)}B"
            value = text
        elif field == "content":
            value = inst.get("raw", path)
        elif field in ("backend", "source"):
            value = inst.get(field, path)
        else:
            value = None
        if value is None:
            raise KeyError(field)
        return value

    def __setitem__(self, field, value):
        rec = dict(self)
        rec[field] = value
        self._reg.write_record(self._path, rec)

    def __delitem__(self, field):
        rec = dict(self)
        del rec[field]
        self._reg.write_record(self._path, rec)

    def __iter__(self):
        return (f for f in self._FIELDS if f in self)

    def __contains__(self, field):
        try:
            self[field]
            return True
        except KeyError:
            return False

    def __len__(self):
        return sum(1 for _ in self)

    def __repr__(self):
        return repr(dict(self))


class FilesView(MutableMapping):
    """The old SYSTEM_STATE["files"] dict, backed by the register."""

    def __init__(self, reg: Register):
        self._reg = reg

    def __getitem__(self, path):
        if not self._reg.inst.get("listed", path):
            raise KeyError(path)
        return RecordView(self._reg, path)

    def __setitem__(self, path, rec):
        self._reg.write_record(path, dict(rec))

    def __delitem__(self, path):
        if not self._reg.inst.get("listed", path):
            raise KeyError(path)
        self._reg.delete_record(path)

    def __contains__(self, path):
        return bool(self._reg.inst.get("listed", path))

    def __iter__(self):
        return iter(self._reg.inst.keys("listed"))

    def __len__(self):
        return len(self._reg.inst.keys("listed"))

    def get(self, path, default=None):
        return self[path] if path in self else default

    def pop(self, path, *default):
        # A copy: the facts behind a live view disappear with the delete
        if path not in self:
            if default:
                return default[0]
            raise KeyError(path)
        rec = dict(self[path])
        del self[path]
        return rec

    def copy(self):
        return {path: dict(rec) for path, rec in self.items()}

    def __repr__(self):
        return repr(self.copy())


class SystemState(dict):
    """SYSTEM_STATE: `files` and `cwd` live in the register, the rest is plain."""

    def __init__(self, register: Register, **rest):
        super().__init__(**rest)
        self.register = register
        dict.__setitem__(self, "files", FilesView(register))

    def __getitem__(self, key):
        if key == "cwd":
            return self.register.cwd()
        return super().__getitem__(key)

    def get(self, key, default=None):
        if key == "cwd":
            return self.register.cwd()
        return super().get(key, default)

    def __setitem__(self, key, value):
        if key == "cwd":
            self.register.set_cwd(value)
        elif key == "files":
            raise TypeError("files are held by the register; write records instead")
        else:
            super().__setitem__(key, value)

    def __contains__(self, key):
        return key == "cwd" or super().__contains__(key)

    def __deepcopy__(self, memo):
        # A plain-dict snapshot: StateTracker diffs before/after with it
        import copy
        snap = {k: copy.deepcopy(v, memo) for k, v in dict.items(self)
                if k != "files"}
        snap["files"] = self["files"].copy()
        snap["cwd"] = self.register.cwd()
        return snap
