"""
shell/profile.py — the user's filesystem design, read lazily into the register.

The profile is the same fs.pickle Cowrie serves: Cowrie's stock tree plus the
additions and removals config.yaml declares (built by plugins/cowrie_fs.py),
with honeyfs files as content overrides. It is the base world-state of OSCAR
(Gil et al., TDSC 2026, Sec. IV-D):

    - only paths a command touches are copied into the register
    - every directory the design defines is closed: what it does not list
      does not exist
    - the seeded generator only completes realistic TYPED files (logs, ssh
      configs) the design leaves empty or missing, never arbitrary paths
"""
import os
import pickle
import posixpath

from shell.procfs import EXPECTED, path_type
from shell.world import Fact

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET = range(9)
_KIND = {0: "symlink", 1: "dir", 2: "file"}
_TYPED = frozenset({"sshd_config", "ssh_config", "auth_log", "log"})
# Virtual or identity files are answered elsewhere, never copied from the pickle
_SKIP = ("/proc", "/sys", "/dev", "/run")
_IDENTITY = frozenset({"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"})
_INDEX_CACHE = {}


def _skipped(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _SKIP)


class Profile:
    """The filesystem design: path -> pickle node, plus honeyfs content."""

    def __init__(self, pickle_path: str = None, honeyfs: str = None):
        self.index = {}
        self.honeyfs = honeyfs
        if pickle_path and os.path.isfile(pickle_path):
            key = (pickle_path, os.path.getmtime(pickle_path))
            if key not in _INDEX_CACHE:
                with open(pickle_path, "rb") as fh:
                    _INDEX_CACHE[key] = _flatten(pickle.load(fh))
            self.index = _INDEX_CACHE[key]
        self._overrides = self._honeyfs_overrides()

    def node(self, path):
        return self.index.get(path)

    def children(self, path):
        node = self.index.get(path)
        if node is None or node[A_TYPE] != 1 or not isinstance(node[A_CONTENTS], list):
            return []
        return [c[A_NAME] for c in node[A_CONTENTS]]

    def content(self, path):
        """Bytes the design gives a file: honeyfs first, then the pickle."""
        if path in self._overrides:
            return self._overrides[path]
        node = self.index.get(path)
        if node is None or path in _IDENTITY:
            return None
        data = node[A_CONTENTS]
        return data if isinstance(data, bytes) else None

    def users(self) -> dict:
        """uid -> name from the design's own /etc/passwd."""
        return self._names("/etc/passwd")

    def groups(self) -> dict:
        """gid -> name from the design's own /etc/group."""
        return self._names("/etc/group")

    def _names(self, path) -> dict:
        data = self.index.get(path)
        out = {0: "root"}
        if data and isinstance(data[A_CONTENTS], bytes):
            for line in data[A_CONTENTS].decode("utf-8", "replace").splitlines():
                parts = line.split(":")
                if len(parts) > 2 and parts[2].isdigit():
                    out[int(parts[2])] = parts[0]
        return out

    def _honeyfs_overrides(self) -> dict:
        """honeyfs/<path> content, moved to the link's target when <path> is a link."""
        out = {}
        if not self.honeyfs or not os.path.isdir(self.honeyfs):
            return out
        for root, _, names in os.walk(self.honeyfs):
            for name in names:
                full = os.path.join(root, name)
                path = "/" + os.path.relpath(full, self.honeyfs).replace(os.sep, "/")
                with open(full, "rb") as fh:
                    data = fh.read()
                # Keep `ls -l` showing the link; `cat` reaches the content
                out[self._resolve_links(path)] = data
        return out

    def _resolve_links(self, path, depth=0):
        node = self.index.get(path)
        if depth > 8 or node is None or node[A_TYPE] != 0:
            return path
        return self._resolve_links(link_target(path, node[A_TARGET]), depth + 1)


def link_target(path: str, stored: str) -> str:
    """Cowrie's pickle stores link targets relative to "/", not the link's dir."""
    return stored if stored.startswith("/") else posixpath.normpath("/" + stored)


def _flatten(root) -> dict:
    index, stack = {}, [("/", root)]
    while stack:
        path, node = stack.pop()
        index[path] = node
        if node[A_TYPE] == 1 and isinstance(node[A_CONTENTS], list):
            for child in node[A_CONTENTS]:
                stack.append((posixpath.join(path, child[A_NAME]), child))
    return index


class Materializer:
    """Copies touched paths into the register: design first, then typed generator.

        mat = Materializer(register, profile, generator)
        mat.ensure("/etc/ssh/sshd_config")
    """

    def __init__(self, register, profile: Profile, generator, users=None, live=None,
                 virtual=None):
        self.reg = register
        self.profile = profile
        self.gen = generator
        self.users = users or profile.users()
        self.groups = {**self.users, **profile.groups()}
        self.live = live or (lambda path: b"")
        # path -> text for files built from the account list (/etc/passwd, /etc/shadow)
        self.virtual = virtual or (lambda path: None)
        self._issued = set()          # inodes handed out within one batch

    def ensure(self, path: str) -> None:
        add, remove = self._plan(path)
        if add:
            self.reg.commit(add, remove, why=f"profile {path}")

    def ensure_children(self, path: str) -> None:
        """A listing reads every child the design defines, in one commit."""
        self.ensure(path)
        add, remove = set(), set()
        names = list(self.profile.children(path))
        names += [n for n in EXPECTED.get(path, ()) if n not in names]
        for name in names:
            a, r = self._plan(posixpath.join(path, name), parents=False)
            add, remove = add | a, remove | r
        if add:
            self.reg.commit(add, remove, why=f"profile list {path}")

    def _plan(self, path: str, parents: bool = True):
        """(facts to add, facts they replace) to bring `path` in from the design."""
        inst = self.reg.inst
        if not path or _skipped(path) or inst.get("absent", path):
            return set(), set()
        # Whatever the attacker touched, or the design already gave, is final
        if any(inst.get(rel, path) for rel in ("profiled", "listed", "sealed")):
            node = self.profile.node(path)
            if node is None or inst.get("sealed", path) or inst.get("profiled", path):
                return set(), set()
            # ...except config-declared entries still take what only the tree knows
            kind = inst.get("kind", path)
            if node[A_TYPE] == 1 and kind == "dir":
                return {Fact("profiled", path)}, set()
            if (node[A_TYPE] == 2 and kind == "file" and inst.get("content", path) is None
                    and inst.get("psize", path) is None):
                return {Fact("psize", path, int(node[A_SIZE]))}, set()
            return set(), set()
        parent = posixpath.dirname(path)
        if parents and parent != path:
            self.ensure(parent)
            inst = self.reg.inst
        if parent != path and inst.get("kind", parent) not in (None, "dir"):
            return set(), set()
        node = self.profile.node(path)
        if node is not None:
            add = self._from_design(path, node)
            # Replace what config or the chase guessed for this path
            remove = {f for f in inst.facts() if f.key == path and f.rel in
                      ("kind", "mode", "owner", "group", "mtime", "atime", "ctime", "inode")}
            return add, remove
        # Missing from the design: only a realistic typed file may appear
        if inst.get("kind", path) is None and path_type(path) in _TYPED:
            return self._touched(path, self._accounts(set(self.gen.materialize(
                inst, path, extra=self.live(path))))), set()
        return set(), set()

    def _accounts(self, facts) -> set:
        """Generated files may only name accounts /etc/passwd and /etc/group have."""
        known = {"owner": set(self.users.values()), "group": set(self.groups.values())}
        return {Fact(f.rel, f.key, "root") if f.rel in known and f.value not in known[f.rel]
                else f for f in facts}

    def _touched(self, path, facts) -> set:
        """A file holding this session's live lines was written just now."""
        if not self.live(path):
            return facts
        now = self.reg.now_ns()
        return ({f for f in facts if f.rel not in ("mtime", "ctime")}
                | {Fact("mtime", path, now), Fact("ctime", path, now)})

    def _inode(self, path) -> int:
        inode = self.reg.new_inode(path)
        while inode in self._issued:
            inode += 1
        self._issued.add(inode)
        return inode

    def _from_design(self, path, node) -> set:
        kind = _KIND.get(node[A_TYPE], "file")
        when = int(node[A_CTIME]) * 1_000_000_000
        facts = {
            Fact("kind", path, kind),
            Fact("mode", path, node[A_MODE] & 0o7777),
            Fact("owner", path, self.users.get(node[A_UID], str(node[A_UID]))),
            Fact("group", path, self.groups.get(node[A_GID], str(node[A_GID]))),
            Fact("inode", path, self._inode(path)),
        }
        facts |= {Fact(rel, path, when) for rel in ("mtime", "atime", "ctime")}
        facts.add(Fact("profiled", path))
        if kind == "symlink":
            # Links right under / keep their relative form (/bin -> usr/bin)
            stored = node[A_TARGET]
            shown = stored if posixpath.dirname(path) == "/" else link_target(path, stored)
            facts |= {Fact("target", path, shown), Fact("size", path, len(shown))}
        elif kind == "file":
            data = self.profile.content(path)
            if data is None and path in _IDENTITY:
                text = self.virtual(path)
                data = text.encode() if text else None
            if data is None and path_type(path) in _TYPED:
                data = (self.gen.content(path) or b"") + self.live(path)
            if data is not None:
                facts |= {Fact("content", path, data), Fact("size", path, len(data))}
                facts = self._touched(path, facts)
            else:
                facts.add(Fact("psize", path, int(node[A_SIZE])))
        return facts
