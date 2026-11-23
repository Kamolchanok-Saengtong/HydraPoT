"""
core/snapshot.py -- the machine as plugins/image_snapshot.py read it from docker.

The configured stock image is the source of truth for the OS files: release, accounts,
dotfiles, crontab. It is never a source for the machine running docker: kernel, CPU and
memory are declared in config.yaml, because a container would report the operator's real
hardware.
Stdlib only, so config_loader, the generator and the shell can all import it.
"""
import datetime as _dt
import hashlib
import json
import os

DEFAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "plugins", "snapshot")
_cache = {}


class Snapshot:
    def __init__(self, directory: str):
        self.dir = directory
        with open(os.path.join(directory, "manifest.json"), encoding="utf-8") as fh:
            self.manifest = json.load(fh)
        self.files = self.manifest["files"]
        self.image = self.manifest["image"]

    # ── files ──────────────────────────────────────────────────────────────

    def meta(self, path: str):
        return self.files.get(path)

    def resolve(self, path: str, _depth: int = 0):
        """The path holding the bytes: follows a symlink recorded in the snapshot."""
        m = self.files.get(path)
        if m and m["type"] == "link" and m["target"] and _depth < 5:
            target = m["target"]
            if not target.startswith("/"):
                target = os.path.normpath(os.path.join(os.path.dirname(path), target))
            return self.resolve(target, _depth + 1)
        return path

    def read(self, path: str):
        real = self.resolve(path)
        try:
            with open(os.path.join(self.dir, "files", real.lstrip("/")), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def text(self, path: str):
        data = self.read(path)
        return data.decode("utf-8", "replace") if data is not None else None

    def paths(self, prefix: str = "/"):
        return sorted(p for p in self.files if p.startswith(prefix))

    # ── identity ───────────────────────────────────────────────────────────

    def os_release(self) -> dict:
        out = {}
        for line in (self.text("/etc/os-release") or "").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k] = v.strip().strip('"')
        return out

    def users(self) -> dict:
        out = {}
        for line in (self.text("/etc/passwd") or "").splitlines():
            f = line.split(":")
            if len(f) >= 7:
                out[f[0]] = {"uid": int(f[2]), "gid": int(f[3]), "gecos": f[4],
                             "home": f[5], "shell": f[6]}
        return out

    def groups(self) -> dict:
        out = {}
        for line in (self.text("/etc/group") or "").splitlines():
            f = line.split(":")
            if len(f) >= 4:
                out[f[0]] = {"gid": int(f[2]), "members": [m for m in f[3].split(",") if m]}
        return out


def load(directory: str = DEFAULT_DIR):
    """The snapshot, or None when plugins/image_snapshot.py has not been run."""
    if directory not in _cache:
        try:
            _cache[directory] = Snapshot(directory)
        except (OSError, ValueError, KeyError):
            _cache[directory] = None
    return _cache[directory]


def apply(snap: Snapshot, honeypot, system_state: dict) -> None:
    """Make the image the base of the persona; config.yaml adds to it.

    The OS name comes from the image. Accounts and groups start as the image's, with
    the operator's declared ones added. Kernel, arch, CPU and memory stay as config
    declares them.
    """
    rel = snap.os_release()
    if rel.get("PRETTY_NAME"):
        honeypot.os = rel["PRETTY_NAME"]

    users = {k: dict(v) for k, v in snap.users().items()}
    for name, rec in (system_state.get("users") or {}).items():
        users[name] = {**users.get(name, {}), **rec}
    system_state["users"] = users

    groups = {k: {"gid": v["gid"], "members": list(v["members"])} for k, v in snap.groups().items()}
    for name, rec in (system_state.get("groups") or {}).items():
        have = groups.setdefault(name, {"gid": rec.get("gid", 0), "members": []})
        have["gid"] = rec.get("gid", have["gid"])
        have["members"] += [m for m in rec.get("members") or [] if m not in have["members"]]
    # a user's own `groups:` list is the same fact seen from the other side
    for name, rec in users.items():
        for g in rec.get("groups") or []:
            if g in groups and name not in groups[g]["members"]:
                groups[g]["members"].append(name)
    system_state["groups"] = groups


def machine_id(image: str, hostname: str) -> str:
    """/etc/machine-id: docker leaves it empty, so one is derived and then stays fixed."""
    return hashlib.md5(f"{image}:{hostname}:machine".encode()).hexdigest()


def boot_id(image: str, hostname: str) -> str:
    return hashlib.md5(f"{image}:{hostname}:boot".encode()).hexdigest()


def boot_datetime(start_label: str, boot: str, now: "_dt.datetime"):
    """When the host booted: PID 1's ps START ("Jul22") at an hour fixed by the boot id.

    The hour comes from the id, not from a per-session random draw, so `uptime`
    and `last` give the same boot time at every login.
    """
    day = _dt.datetime.strptime(f"{now.year} {start_label}", "%Y %b%d").replace(
        tzinfo=_dt.timezone.utc, hour=int(boot[0:2], 16) % 24, minute=int(boot[2:4], 16) % 60)
    return day.replace(year=now.year - 1) if day > now else day
