"""
shell/procfs.py — procedural filesystem for paths nobody created.

Implements the procedural filesystem of Section IV-D in Gil et al., "OSCAR:
Provably Consistent LLM Honeypots via Ontology-Constrained Response
Generation", IEEE TDSC 2026 (DOI 10.1109/TDSC.2026.3749501):

    content = realize(H(path, kind, seed), path_type)

H is a keyed PRF (HMAC-SHA256 keyed by the session seed), so a path's content
is a pure function of (seed, path): re-reads return the same bytes whether or
not the file was cached (Theorem 6). A path oracle picks the type; realizers
keep the structure valid and vary only details.
"""
import hashlib
import hmac
import posixpath
from datetime import datetime, timedelta, timezone

from shell.world import Fact, Instance

# Owned by the profile or rule core; the generator must never invent these
_RESERVED = frozenset({
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/hostname", "/etc/hosts", "/etc/os-release", "/etc/issue",
})
_RESERVED_PREFIXES = ("/proc/", "/sys/", "/dev/", "/run/")
_BINARY_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib", "/usr/lib")


class PRF:
    """Deterministic number stream for one (seed, path, kind)."""

    def __init__(self, seed: bytes, path: str, kind: str):
        self._key = seed
        self._msg = f"{kind}\0{path}".encode()
        self._block = 0
        self._pool = b""

    def bytes(self, n: int) -> bytes:
        while len(self._pool) < n:
            msg = self._msg + self._block.to_bytes(8, "big")
            self._pool += hmac.new(self._key, msg, hashlib.sha256).digest()
            self._block += 1
        out, self._pool = self._pool[:n], self._pool[n:]
        return out

    def int(self, lo: int, hi: int) -> int:
        """Uniform-enough integer in [lo, hi]."""
        span = hi - lo + 1
        return lo + int.from_bytes(self.bytes(8), "big") % span

    def choice(self, items):
        return items[self.int(0, len(items) - 1)]


def path_type(path: str):
    """Path oracle: the content type of a path, or None if not ours to invent."""
    if path in _RESERVED or path.startswith(_RESERVED_PREFIXES):
        return None
    if path.startswith(_BINARY_PREFIXES):
        return None
    name = posixpath.basename(path)
    if path in ("/etc/ssh/sshd_config",):
        return "sshd_config"
    if path == "/etc/ssh/ssh_config" or path.endswith("/.ssh/config"):
        return "ssh_config"
    if path in ("/var/log/auth.log", "/var/log/secure"):
        return "auth_log"
    if path.startswith("/var/log/") and (name.endswith(".log") or "." not in name):
        return "log"
    return "generic"


# File metadata per type: (owner, group, mode)
_META = {
    "sshd_config": ("root", "root", 0o644),
    "ssh_config": ("root", "root", 0o644),
    "auth_log": ("syslog", "adm", 0o640),
    "log": ("syslog", "adm", 0o640),
    "generic": ("root", "root", 0o644),
}


class Generator:
    """One session's procedural filesystem: same seed, same files.

        gen = Generator(seed, hostname="psu", epoch=session_start)
        facts = gen.materialize(inst, "/var/log/auth.log")
    """

    def __init__(self, seed: bytes, hostname: str, epoch: datetime):
        self.seed = seed
        self.hostname = hostname
        self.epoch = epoch.astimezone(timezone.utc)

    def content(self, path: str):
        """Bytes for a path in the open tail, or None if not generated."""
        kind = path_type(path)
        if kind is None:
            return None
        rng = PRF(self.seed, path, kind)
        return _REALIZERS[kind](self, rng, path).encode()

    def materialize(self, inst: Instance, path: str, extra: bytes = b""):
        """Facts that complete `path` from the generator, or [] if it must not.

        `extra` is appended after the generated part: live events of this
        session, such as the attacker's own login in auth.log.

        Respects the closed-world region: nothing is invented for an absent
        path, a path already known, or inside a sealed directory.
        """
        if inst.get("kind", path) is not None or inst.get("absent", path):
            return []
        parent = posixpath.dirname(path)
        while True:
            if inst.get("absent", parent) or inst.get("sealed", parent):
                return []
            if inst.get("kind", parent) not in (None, "dir"):
                return []
            if parent == "/":
                break
            parent = posixpath.dirname(parent)
        data = self.content(path)
        if data is None:
            return []
        data += extra
        owner, group, mode = _META[path_type(path)]
        rng = PRF(self.seed, path, "meta")
        mtime = self.epoch - timedelta(seconds=rng.int(3600, 90 * 86400))
        # Probe past taken inodes so eps3 (unique inode) holds
        used = {inst.get("inode", p) for p in inst.keys("inode")}
        inode = rng.int(100_000, 9_999_999)
        while inode in used:
            inode += 1
        return [
            Fact("kind", path, "file"), Fact("content", path, data),
            Fact("size", path, len(data)), Fact("owner", path, owner),
            Fact("group", path, group), Fact("mode", path, mode),
            # Register times are nanoseconds, like st_mtim
            *(Fact(rel, path, int(mtime.timestamp()) * 1_000_000_000)
              for rel in ("mtime", "atime", "ctime")),
            Fact("inode", path, inode),
        ]


# ── realizers: valid structure, seed-varied details ─────────────────────────

def _sshd_config(gen, rng, path):
    # Root password login stays enabled: the attacker just logged in that way
    return "\n".join([
        "#\t$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $",
        "",
        "# This is the sshd server system-wide configuration file.  See",
        "# sshd_config(5) for more information.",
        "",
        "Include /etc/ssh/sshd_config.d/*.conf",
        "",
        "#Port 22",
        "#AddressFamily any",
        "#ListenAddress 0.0.0.0",
        "",
        f"LoginGraceTime {rng.choice(['2m', '1m', '120', '60'])}",
        "PermitRootLogin yes",
        f"MaxAuthTries {rng.int(3, 6)}",
        f"MaxSessions {rng.choice([10, 10, 5, 20])}",
        "",
        "PasswordAuthentication yes",
        "ChallengeResponseAuthentication no",
        "UsePAM yes",
        "",
        f"X11Forwarding {rng.choice(['yes', 'no'])}",
        "PrintMotd no",
        f"ClientAliveInterval {rng.choice([0, 60, 120, 300])}",
        "",
        "AcceptEnv LANG LC_*",
        "Subsystem\tsftp\t/usr/lib/openssh/sftp-server",
        "",
    ])


def _ssh_config(gen, rng, path):
    if path.endswith("/.ssh/config"):
        lines = []
        for i in range(rng.int(1, 3)):
            name = rng.choice(["backup", "db", "web", "git", "jump", "staging"])
            lines += [f"Host {name}{i + 1}",
                      f"    HostName 10.{rng.int(0, 31)}.{rng.int(0, 255)}.{rng.int(2, 254)}",
                      f"    User {rng.choice(['root', 'deploy', 'ubuntu', 'admin'])}",
                      f"    Port {rng.choice([22, 22, 22, 2222])}", ""]
        return "\n".join(lines)
    return "\n".join([
        "# This is the ssh client system-wide configuration file.  See",
        "# ssh_config(5) for more information.",
        "",
        "Include /etc/ssh/ssh_config.d/*.conf",
        "",
        "Host *",
        "#   ForwardAgent no",
        "#   PasswordAuthentication yes",
        f"#   ConnectTimeout {rng.choice([0, 10, 30])}",
        "    SendEnv LANG LC_*",
        "    HashKnownHosts yes",
        "    GSSAPIAuthentication yes",
        "",
    ])


def _auth_log(gen, rng, path):
    t = gen.epoch - timedelta(hours=rng.int(6, 72))
    lines = []
    for _ in range(rng.int(20, 60)):
        t += timedelta(seconds=rng.int(1, 900))
        ip = f"{rng.int(1, 223)}.{rng.int(0, 255)}.{rng.int(0, 255)}.{rng.int(1, 254)}"
        pid = rng.int(1000, 65000)
        port = rng.int(1024, 65535)
        user = rng.choice(["root", "root", "admin", "ubuntu", "test", "oracle", "pi"])
        stamp = f"{t:%b} {t.day:>2} {t:%H:%M:%S} {gen.hostname}"
        if user == "root":
            lines.append(f"{stamp} sshd[{pid}]: Failed password for root from {ip} "
                         f"port {port} ssh2")
        else:
            lines.append(f"{stamp} sshd[{pid}]: Invalid user {user} from {ip} port {port}")
        lines.append(f"{stamp} sshd[{pid}]: Connection closed by {ip} port {port} [preauth]")
    return "\n".join(lines) + "\n"


def _log(gen, rng, path):
    t = gen.epoch - timedelta(hours=rng.int(1, 48))
    unit = posixpath.basename(path).split(".")[0] or "kernel"
    lines = []
    for _ in range(rng.int(5, 25)):
        t += timedelta(seconds=rng.int(5, 3600))
        msg = rng.choice(["Started Daily apt download activities.",
                          "Finished Daily apt upgrade and clean activities.",
                          "Starting Message of the Day...",
                          "Started Session of user root.",
                          "Reloading.", "Started Rotate log files."])
        lines.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} {gen.hostname} "
                     f"{unit}[{rng.int(1, 9999)}]: {msg}")
    return "\n".join(lines) + "\n"


def _generic(gen, rng, path):
    name = posixpath.basename(path)
    if name.endswith((".conf", ".cfg", ".ini", ".cnf")):
        keys = ["enabled", "timeout", "max_connections", "log_level", "listen", "user"]
        values = {"enabled": rng.choice(["true", "false"]),
                  "timeout": str(rng.int(5, 300)),
                  "max_connections": str(rng.int(16, 1024)),
                  "log_level": rng.choice(["info", "warn", "error"]),
                  "listen": f"127.0.0.1:{rng.int(1024, 9999)}",
                  "user": rng.choice(["www-data", "nobody", "root"])}
        picked = [k for k in keys if rng.int(0, 2)]
        return "\n".join([f"# {name}"] + [f"{k} = {values[k]}" for k in picked]) + "\n"
    words = ["backup", "deploy", "notes", "todo", "server", "config", "update",
             "restart", "check", "logs", "cron", "disk"]
    return "\n".join(" ".join(rng.choice(words) for _ in range(rng.int(3, 8)))
                     for _ in range(rng.int(1, 6))) + "\n"


_REALIZERS = {
    "sshd_config": _sshd_config,
    "ssh_config": _ssh_config,
    "auth_log": _auth_log,
    "log": _log,
    "generic": _generic,
}
