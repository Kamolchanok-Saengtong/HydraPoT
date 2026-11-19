"""
shell/world.py — the System State Register: world-state K = (I, Sigma).

Replaces the ad-hoc SYSTEM_STATE dict. Implements the world-state, chase,
feasible set (Def. 1) and transition (Def. 2) of Section IV-A to IV-C in:

    H. Gil, J. Kim, S. Ahn, S. Kang. "OSCAR: Provably Consistent LLM Honeypots
    via Ontology-Constrained Response Generation." IEEE Transactions on
    Dependable and Secure Computing, 2026. DOI 10.1109/TDSC.2026.3749501

I is a set of typed facts; Sigma is what those facts must satisfy:

    Sigma_T (tuple-generating), completed by the chase:
        sigma1   every object has a parent directory     (ancestor completion)
        witness  every object has an owner and a mode
        sigma2   every owner is a user
    Sigma_E (equality-generating): each FUNCTIONAL relation has one value per
        key -- one content, owner, mode, size, inode, mtime... per path
    Sigma_D (denial):
        delta1   a directory holds no content
        delta3   size equals the length of the content
        delta4   a path is not both absent and an object
        eps3     two paths never share an inode

delta2 (no cycle in the parent relation) holds by construction: a parent is
always the path's dirname.
"""
import posixpath
from dataclasses import dataclass, field

FUNCTIONAL = frozenset({
    "kind", "content", "size", "mode", "owner", "group", "mtime", "atime",
    "ctime", "inode",
    "target", "uid", "gid", "home", "shell", "env", "proc", "cwd",
    "backend", "source",
    # The login this session is: session(ip|user|tty|port|login_ns|sshd_pid|shell_pid)
    "session",
    # Session events a log would record, keyed by command seq
    "event",
    # How older modules wrote a file (raw echo text, display size). Kept
    # beside the real facts so Sigma always checks bytes, not display text.
    "raw", "size_text",
})
# sealed(dir): closed-world; the procedural generator invents no children
# listed(path): shown in the old SYSTEM_STATE["files"] view
PRESENCE = frozenset({"absent", "user", "sealed", "listed"})
RELATIONS = FUNCTIONAL | PRESENCE
KINDS = frozenset({"file", "dir", "symlink"})

_MISSING = object()


@dataclass(frozen=True)
class Fact:
    rel: str
    key: object
    value: object = True

    def __post_init__(self):
        if self.rel not in RELATIONS:
            raise ValueError(f"unknown relation {self.rel!r}")


class Violation(Exception):
    """A constraint in Sigma failed."""

    def __init__(self, constraint: str, detail: str):
        super().__init__(f"{constraint}: {detail}")
        self.constraint = constraint
        self.detail = detail


def norm(path: str) -> str:
    return posixpath.normpath(path) if path else path


class Instance:
    """The fact set I. Functional relations map key -> value."""

    def __init__(self):
        self._rel = {r: {} for r in RELATIONS}

    def copy(self) -> "Instance":
        out = Instance()
        out._rel = {r: dict(v) for r, v in self._rel.items()}
        return out

    def get(self, rel: str, key, default=None):
        return self._rel[rel].get(key, default)

    def holds(self, fact: Fact) -> bool:
        cur = self._rel[fact.rel].get(fact.key, _MISSING)
        return cur is not _MISSING and (fact.rel in PRESENCE or cur == fact.value)

    def add(self, fact: Fact) -> None:
        cur = self._rel[fact.rel].get(fact.key, _MISSING)
        # Sigma_E: a second value for the same key is a contradiction
        if fact.rel in FUNCTIONAL and cur is not _MISSING and cur != fact.value:
            raise Violation(f"egd:{fact.rel}",
                            f"{fact.key!r} is {cur!r}, not {fact.value!r}")
        self._rel[fact.rel][fact.key] = fact.value

    def remove(self, fact: Fact) -> None:
        if self.holds(fact):
            del self._rel[fact.rel][fact.key]

    def keys(self, rel: str):
        return list(self._rel[rel])

    def facts(self):
        for rel, table in self._rel.items():
            for key, value in table.items():
                yield Fact(rel, key, value)

    def __len__(self):
        return sum(len(t) for t in self._rel.values())

    def __eq__(self, other):
        return isinstance(other, Instance) and self._rel == other._rel


def default_witness(path: str, attr: str, kind: str, inst: "Instance"):
    """Values for Sigma_T existentials when no generator is plugged in."""
    if attr == "owner":
        return "root"
    if attr == "mode":
        return 0o755 if kind == "dir" else 0o644
    raise KeyError(attr)


def chase(inst: Instance, witness=default_witness) -> Instance:
    """Complete I under Sigma_T, then check Sigma_D. Raises Violation."""
    out = inst.copy()
    for p in out.keys("kind"):
        if out.get("kind", p) not in KINDS:
            raise Violation("kind", f"{p!r} has kind {out.get('kind', p)!r}")

    # The working directory is a directory
    for key in out.keys("cwd"):
        cwd = out.get("cwd", key)
        kind = out.get("kind", cwd)
        if kind is None:
            out.add(Fact("kind", cwd, "dir"))
        elif kind != "dir":
            raise Violation("cwd", f"{cwd!r} is a {kind}, not a directory")

    # sigma1: ancestor-directory completion
    work = out.keys("kind")
    while work:
        path = work.pop()
        if path == "/":
            continue
        parent = posixpath.dirname(path)
        kind = out.get("kind", parent)
        if kind is None:
            out.add(Fact("kind", parent, "dir"))
            work.append(parent)
        elif kind != "dir":
            raise Violation("sigma1", f"{parent!r} is a {kind}, cannot hold {path!r}")

    # Witnesses: every object has an owner and a mode
    for path in out.keys("kind"):
        kind = out.get("kind", path)
        for attr in ("owner", "mode"):
            if out.get(attr, path) is None:
                out.add(Fact(attr, path, witness(path, attr, kind, out)))

    # sigma2: every owner is a user
    for path in out.keys("owner"):
        user = out.get("owner", path)
        if out.get("user", user) is None:
            out.add(Fact("user", user))

    check_denials(out)
    return out


def check_denials(inst: Instance) -> None:
    for path in inst.keys("absent"):
        if inst.get("kind", path) is not None:
            raise Violation("delta4", f"{path!r} is both absent and present")
    for path in inst.keys("content"):
        kind = inst.get("kind", path)
        if kind not in (None, "file"):
            raise Violation("delta1", f"{path!r} is a {kind} with content")
        size = inst.get("size", path)
        if size is not None and size != len(inst.get("content", path)):
            raise Violation("delta3", f"{path!r} size {size} != content length")
    seen = {}
    for path in inst.keys("inode"):
        ino = inst.get("inode", path)
        if ino in seen:
            raise Violation("eps3", f"{path!r} and {seen[ino]!r} share inode {ino}")
        seen[ino] = path


@dataclass(frozen=True)
class Proposal:
    """A candidate response a: output text, effect (add, remove), claims (pos, neg).

    `denies` holds the paths the output asserts do not exist (Cl-).
    """
    output: str
    add: frozenset = field(default_factory=frozenset)
    remove: frozenset = field(default_factory=frozenset)
    claims: frozenset = field(default_factory=frozenset)
    denies: frozenset = field(default_factory=frozenset)


@dataclass
class Verdict:
    ok: bool
    reason: str = ""
    successor: Instance = None


def successor(inst: Instance, prop: Proposal, witness=default_witness) -> Instance:
    """Def. 2: I_{t+1} = (I minus remove) + add + claims, chased."""
    nxt = inst.copy()
    for fact in prop.remove:
        nxt.remove(fact)
    for fact in prop.add:
        # Creating a path withdraws an earlier denial of it
        if fact.rel == "kind":
            nxt.remove(Fact("absent", fact.key))
        nxt.add(fact)
    for fact in prop.claims:
        nxt.add(fact)
    # A denial the gate admits is committed as an absent fact
    for path in prop.denies:
        nxt.add(Fact("absent", path))
    return chase(nxt, witness)


def feasible(inst: Instance, prop: Proposal, witness=default_witness) -> Verdict:
    """Def. 1: claims agree with I, and the committed post-state satisfies Sigma."""
    try:
        base = chase(inst, witness)
        # (i) positive claims are consistent with the current state
        with_claims = base.copy()
        for fact in prop.claims:
            with_claims.add(fact)
        chase(with_claims, witness)
        # (i) no negative claim is entailed false by the current state
        for path in prop.denies:
            if base.get("kind", path) is not None:
                return Verdict(False, f"denies {path!r}, which exists")
        # (ii) the committed post-state is valid
        return Verdict(True, "", successor(base, prop, witness))
    except Violation as e:
        return Verdict(False, str(e))
