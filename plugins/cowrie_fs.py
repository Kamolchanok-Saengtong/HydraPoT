#!/usr/bin/env python3
"""
plugins/cowrie_fs.py — build everything Cowrie needs, from config.yaml.

Single source of truth for what the container shows an attacker. Writes:

    plugins/cowrie/fs.pickle            the fake filesystem (structure)
    plugins/cowrie/cowrie.env           hostname + kernel identity
    plugins/cowrie/honeyfs/proc/version
    plugins/cowrie/honeyfs/etc/os-release
    plugins/cowrie/honeyfs/etc/issue

Structure and identity must be generated together. Fixing only the tree still
leaves `uname -a | cat` and `cat /proc/version` answering svr04/Debian, which
is a sharper tell than the tree ever was: one session, two different machines.

Reads config.yaml's `filesystem:` section, starts from Cowrie's stock tree,
applies the declared additions and removals, writes a new fs.pickle. The
container then loads ours instead of its own; Cowrie's copy is never touched.

Why not build from empty
------------------------
Cowrie's tree is one binary file covering the WHOLE filesystem — /usr/bin,
/etc, libraries, the lot. Declaring all of that by hand is not realistic, and
a honeypot whose `ls /usr/bin` shows five files is a worse tell than the stock
tree it replaced. So the stock tree is the base and config.yaml only says what
is different.

Why not edit Cowrie's copy in place
-----------------------------------
The container runs the official image. Editing inside it means a fork to
maintain and an edit lost on every `docker pull`. Mounting our file over a
path Cowrie reads keeps the image stock and makes the change revertible by
deleting two lines of docker-compose.yml.

fs.pickle node format (from Cowrie's own createfs.py):

    [name, type, uid, gid, size, mode, ctime, contents, target, realfile]

    type    1 = dir, 2 = file, 0 = symlink
    mode    stat mode bits: 0o040755 for a dir, 0o100644 for a file
    size    DECLARED, not real. Cowrie only reports the number, so a 4.8 GB
            backup.sql costs zero bytes on disk.
    contents  list of child nodes for a dir; inline bytes for a file, or None

Usage
-----
    python plugins/cowrie_fs.py             # build it
    python plugins/cowrie_fs.py --dry-run   # show what would change, write nothing
"""
import argparse
import calendar
import hashlib
import random
import re
import string
import os
import pickle
import sys
import time

import yaml

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))
from core.config_loader import load_config
from shell.fakefs import shadow_days
from shell import hardware, identity

_HERE = os.path.dirname(os.path.abspath(__file__))          # plugins/
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))          # repo root
# config.yaml lives at the repo root; the paths inside its `filesystem:`
# section are written relative to THIS file, so both anchors are needed.

# Node field indices, named the same way Cowrie names them.
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2


class _SafeUnpickler(pickle.Unpickler):
    """fs.pickle is plain nested lists. Refusing every class import makes
    loading it incapable of executing code, whatever the file contains."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"blocked class in fs.pickle: {module}.{name}")


def load_tree(path: str):
    with open(path, "rb") as fh:
        return _SafeUnpickler(fh).load()


def _child(node, name: str):
    for c in node[A_CONTENTS] or []:
        if c[A_NAME] == name:
            return c
    return None


def _split(path: str) -> list[str]:
    return [p for p in path.strip("/").split("/") if p]


def _mtime(value) -> int:
    """'2026-08-14 22:41' -> epoch. Missing means now."""
    if not value:
        return int(time.time())
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return calendar.timegm(time.strptime(str(value), fmt))
        except ValueError:
            continue
    raise SystemExit(f"filesystem: cannot parse mtime {value!r}")


def _mode(perms, is_dir: bool) -> int:
    base = 0o040000 if is_dir else 0o100000
    if perms is None:
        return base | (0o755 if is_dir else 0o644)
    return base | int(str(perms), 8)


def ensure_dir(root, path: str, spec: dict | None = None):
    """Walk to `path`, creating any missing directory on the way.

    Intermediate dirs get the parent's ownership rather than the spec's — only
    the directory actually named in config is configured, so declaring
    /var/www/coc-student-portal does not silently hand /var/www to www-data.
    """
    spec = spec or {}
    node = root
    parts = _split(path)
    for i, name in enumerate(parts):
        nxt = _child(node, name)
        if nxt is None:
            last = i == len(parts) - 1
            src = spec if last else {}
            nxt = [name, T_DIR,
                   int(src.get("uid", node[A_UID])),
                   int(src.get("gid", node[A_GID])),
                   4096,
                   _mode(src.get("perms"), True),
                   _mtime(src.get("mtime")),
                   [], None, None]
            node[A_CONTENTS].append(nxt)
        elif i == len(parts) - 1 and spec:
            # already there — apply the declared attributes
            nxt[A_UID] = int(spec.get("uid", nxt[A_UID]))
            nxt[A_GID] = int(spec.get("gid", nxt[A_GID]))
            nxt[A_MODE] = _mode(spec.get("perms"), True)
            if spec.get("mtime"):
                nxt[A_CTIME] = _mtime(spec["mtime"])
        node = nxt
    return node


def add_file(root, path: str, spec: dict) -> str:
    parent = ensure_dir(root, os.path.dirname(path))
    name = os.path.basename(path)
    content = spec.get("content")
    blob = content.encode() if isinstance(content, str) else None
    size = int(spec.get("size", len(blob) if blob else 0))

    node = [name, T_FILE,
            int(spec.get("uid", 0)),
            int(spec.get("gid", 0)),
            size,
            _mode(spec.get("perms"), False),
            _mtime(spec.get("mtime")),
            blob, None, None]

    existing = _child(parent, name)
    if existing is not None:
        parent[A_CONTENTS][parent[A_CONTENTS].index(existing)] = node
        return "replaced"
    parent[A_CONTENTS].append(node)
    return "added"


def remove(root, path: str) -> bool:
    parts = _split(path)
    node = root
    for name in parts[:-1]:
        node = _child(node, name)
        if node is None:
            return False
    target = _child(node, parts[-1])
    if target is None:
        return False
    node[A_CONTENTS].remove(target)
    return True


def count(node) -> tuple[int, int]:
    files = dirs = 0
    stack = [node]
    while stack:
        n = stack.pop()
        if n[A_TYPE] == T_DIR:
            dirs += 1
            stack.extend(n[A_CONTENTS] or [])
        else:
            files += 1
    return files, dirs


def split_os(os_string: str) -> tuple[str, str]:
    """"Ubuntu 22.04 LTS" -> ("Ubuntu", "22.04").

    Parsed rather than looked up in a table: the wizard already offers several
    distributions and hand-editing config.yaml is supported, so a table here
    would silently produce the wrong answer for anything not in it. Falls back
    to the whole string when there is no version token.
    """
    parts = os_string.split()
    name = parts[0] if parts else os_string
    version = ""
    for p in parts[1:]:
        if p[:1].isdigit():
            version = p
            break
    return name, version



_UBUNTU = identity.UBUNTU
_DEB_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
_RESOLV = """# This file is managed by man:systemd-resolved(8). Do not edit.
#
# This is a dynamic resolv.conf file for connecting local clients to the
# internal DNS stub resolver of systemd-resolved. This file lists all
# configured search domains.
#
# Run "resolvectl status" to see details about the uplink DNS servers
# currently in use.
#
# Third party programs must not access this file directly, but only through the
# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,
# replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 127.0.0.53
options edns0 trust-ad
"""
_CRONTAB = """# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
"""
_SHELLS = """# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/usr/bin/sh
/bin/dash
/usr/bin/dash
"""


def _fill_decoys(text: str, seed: str) -> str:
    """Swap @AWS_KEY_ID@ / @AWS_SECRET@ for random fake values.

    Kept out of git on purpose: a literal key-shaped string, fake or not, is
    blocked by GitHub push protection. Seeded by hostname so a rebuild gives the
    same values, and an attacker sees one stable file.
    """
    rng, n = random.Random(seed), [0]
    pools = {"AWS_KEY_ID": ("AKIA", string.ascii_uppercase + string.digits, 16),
             "AWS_SECRET": ("", string.ascii_letters + string.digits + "+/", 40)}

    def one(m):
        prefix, alphabet, length = pools[m.group(1)]
        n[0] += 1
        return prefix + "".join(rng.choice(alphabet) for _ in range(length))
    return re.sub(r"@(AWS_KEY_ID|AWS_SECRET)@", one, text)


def build_persona(cfg) -> dict[str, str]:
    hp = cfg.honeypot
    name, version = split_os(hp.os)
    ident = name.lower()
    majmin = ".".join(version.split(".")[:2])
    codename, nick, _deb = _UBUNTU.get(majmin, ("", "", "")) if ident == "ubuntu" else ("", "", "")
    versions = (cfg.system_state or {}).get("versions") or {}

    # COWRIE_<SECTION>_<KEY>, per Cowrie's Docker docs. These override
    # cowrie.cfg, so `uname` agrees with us no matter how it is invoked --
    # piped, substituted, or behind &&.
    env = "\n".join([
        "# Generated by plugins/cowrie_fs.py — DO NOT EDIT BY HAND.",
        "# Regenerate after changing honeypot.os / kernel / arch in config.yaml.",
        f"COWRIE_HONEYPOT_HOSTNAME={hp.hostname}",
        f"COWRIE_SHELL_KERNEL_VERSION={hp.kernel}",
        f"COWRIE_SHELL_KERNEL_BUILD_STRING={hp.kernel_build}",
        f"COWRIE_SHELL_HARDWARE_PLATFORM={hp.arch}",
        "COWRIE_SHELL_OPERATING_SYSTEM=GNU/Linux",
        "",
    ])

    # /proc/version: Linux version <release> (<builder>) (<gcc>, <ld>) <build>
    # The compiler and linker come from the same `versions:` the `gcc` command
    # answers with, so the two cannot disagree. Without them (other distros) the
    # older shorter form is kept.
    gcc = versions.get("gcc")
    if gcc and ident == "ubuntu":
        arch = _DEB_ARCH.get(hp.arch, hp.arch)
        host = int(hashlib.sha1(hp.kernel_build.encode()).hexdigest()[:6], 16) % 120
        ld = versions.get("ld") or "GNU ld (GNU Binutils for Ubuntu)"
        proc_version = (f"Linux version {hp.kernel} (buildd@lcy02-{arch}-{host:03d}) "
                        f"({gcc}, {ld}) {hp.kernel_build}\n")
    else:
        proc_version = (f"Linux version {hp.kernel} (buildd@{ident}-{hp.arch}) "
                        f"(gcc version 11.4.0 ({name} {version})) {hp.kernel_build}\n")

    pretty = hp.os
    if codename:
        os_release = "\n".join([
            f'NAME="{name}"',
            f'VERSION="{version} LTS ({nick})"',
            f"ID={ident}",
            "ID_LIKE=debian",
            f'PRETTY_NAME="{pretty}"',
            f'VERSION_ID="{majmin}"',
            'HOME_URL="https://www.ubuntu.com/"',
            'SUPPORT_URL="https://help.ubuntu.com/"',
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"',
            'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"',
            f"VERSION_CODENAME={codename}",
            f"UBUNTU_CODENAME={codename}",
            "",
        ])
    else:
        os_release = "\n".join([
            f'PRETTY_NAME="{pretty}"',
            f'NAME="{name}"',
            f'VERSION_ID="{version}"',
            f'VERSION="{version} ({name})"',
            f"ID={ident}",
            f"HOME_URL=\"https://www.{ident}.com/\"",
            f"SUPPORT_URL=\"https://help.{ident}.com/\"",
            "",
        ])

    issue = f"{pretty} \\n \\l\n\n"

    return {
        "cowrie.env": env,
        os.path.join("honeyfs", "proc", "version"): proc_version,
        os.path.join("honeyfs", "etc", "os-release"): os_release,
        os.path.join("honeyfs", "etc", "issue"): issue,
    }


def persona_tree_files(cfg) -> dict[str, str]:
    """Identity files Cowrie serves from the tree itself (no mount needed).

    Cowrie's stock tree names the machine `svr04` (/etc/hostname) and `nas3`
    (/etc/hosts); both survive a hostname change in config.yaml unless
    rewritten, and `hostname` then disagrees with the file.
    """
    hp = cfg.honeypot
    name, version = split_os(hp.os)
    ident = name.lower()
    majmin = ".".join(version.split(".")[:2])
    # /proc/version is stored inline in Cowrie's stock tree and wins over
    # honeyfs, so a mounted file alone still answered "Debian 6.1". Written into
    # the tree, the three files below cannot go stale behind a bind mount either.
    out = {
        "/" + rel[len("honeyfs/"):]: body
        for rel, body in build_persona(cfg).items() if rel.startswith("honeyfs/")}
    out.update({
        "/etc/hostname": f"{hp.hostname}\n",
        "/etc/hosts": "\n".join([
            "127.0.0.1 localhost", f"127.0.1.1 {hp.hostname}", "",
            "# The following lines are desirable for IPv6 capable hosts",
            "::1 ip6-localhost ip6-loopback", "fe00::0 ip6-localnet",
            "ff00::0 ip6-mcastprefix", "ff02::1 ip6-allnodes",
            "ff02::2 ip6-allrouters", ""]),
    })
    groups = (cfg.system_state or {}).get("groups")
    if groups:
        out["/etc/group"] = "\n".join(
            f"{n}:x:{g['gid']}:{','.join(g.get('members') or [])}" for n, g in groups.items()) + "\n"
    machine_id = ((cfg.system_state or {}).get("network") or {}).get("machine_id")
    if machine_id:
        out["/etc/machine-id"] = machine_id + "\n"
    hw = (cfg.system_state or {}).get("hardware")
    if hw:
        out["/proc/meminfo"] = hardware.meminfo(hw)
    if ident == "ubuntu":
        # Ubuntu resolves through systemd-resolved's stub, which `ss` shows on
        # 127.0.0.53; Cowrie's stock file names 8.8.8.8 directly.
        out["/etc/resolv.conf"] = _RESOLV
        out["/etc/shells"] = _SHELLS
        out["/etc/crontab"] = _CRONTAB
    if ident == "ubuntu" and majmin in _UBUNTU:
        codename, _nick, deb = _UBUNTU[majmin]
        out["/etc/lsb-release"] = "\n".join([
            "DISTRIB_ID=Ubuntu", f"DISTRIB_RELEASE={majmin}",
            f"DISTRIB_CODENAME={codename}", f'DISTRIB_DESCRIPTION="{hp.os}"', ""])
        out["/etc/issue.net"] = f"{hp.os}\n"
        out["/etc/debian_version"] = f"{deb}\n"
    return out


def _perm_to_octal(perms: str, is_dir: bool) -> str:
    """'drwxr-xr-x' / '-rw-r-----' -> '0755' / '0640'.

    config.yaml's system_state.starting_files writes permissions the way `ls`
    prints them, because that is where they are also shown to the attacker.
    The pickle wants octal, so convert rather than asking the operator to
    write the same thing twice in two notations.
    """
    if not perms or len(perms) < 10:
        return "0755" if is_dir else "0644"
    bits = 0
    for i, (r, w, x) in enumerate(((1, 2, 3), (4, 5, 6), (7, 8, 9))):
        v = (4 if perms[r] == "r" else 0) | (2 if perms[w] == "w" else 0) | (1 if perms[x] in "xs" else 0)
        bits |= v << (6 - 3 * i)
    return f"0{bits:03o}"


def sync_system_state(root, conf) -> list[str]:
    """Push config.yaml's system_state into Cowrie's tree.

    HydraPoT and Cowrie each held their own idea of the filesystem and the two
    disagreed in both directions, in one session:

        cd coc-student-portal  -> Cowrie had it, HydraPoT denied it existed
        touch / chmod / rm     -> HydraPoT had it, Cowrie never heard of it

    Forwarding commands one at a time (see _cowrie_sync in main.py) closes the
    gap DURING a session. This closes it at the START, so the two never begin
    from different machines. Same config drives both sides.

    Returns lines describing what changed, for the caller to print.
    """
    log = []
    st = conf.system_state or {}
    users = st.get("users") or {}
    shadow = st.get("shadow") or {}

    # /etc/passwd — Cowrie's stock file still lists `phil`, which is the single
    # most recognisable Cowrie fingerprint there is.
    if users:
        lines = []
        for name, u in users.items():
            uid = u.get("uid", 1000)
            lines.append(":".join([
                name, "x", str(uid), str(u.get("gid", uid)),
                u.get("gecos", name),
                u.get("home", f"/home/{name}"),
                u.get("shell", "/bin/sh"),
            ]))
        body = "\n".join(lines) + "\n"
        add_file(root, "/etc/passwd", {"content": body, "perms": "0644"})
        log.append(f"  /etc/passwd            {len(users)} accounts from config")

    if shadow:
        days = shadow_days(st.get("shadow_changed"))
        lines = [f"{n}:{shadow.get(n, '*')}:{days}:0:99999:7:::" for n in users or shadow]
        add_file(root, "/etc/shadow",
                 {"content": "\n".join(lines) + "\n", "perms": "0640", "gid": 42})
        log.append(f"  /etc/shadow            {len(lines)} entries")

    # A home directory for every real account. Cowrie's tree has /home/phil and
    # nothing else, so `cd ~` for any configured user landed nowhere.
    for name, u in users.items():
        home = u.get("home", f"/home/{name}")
        if home in ("/", "/nonexistent") or not home.startswith(("/home", "/root")):
            continue                      # system accounts point at /bin, /usr/sbin...
        if u.get("uid", 0) < 1000 and name != "root":
            continue                      # a daemon's home is not a login directory
        # dated when the accounts were set up, not when this script ran
        ensure_dir(root, home, {"uid": u.get("uid", 0), "gid": u.get("gid", 0),
                                "perms": "0700", "mtime": st.get("shadow_changed")})
        log.append(f"  {home:<22} home for {name}")

    for path in st.get("known_dirs") or []:
        ensure_dir(root, path, {})

    for path, spec in (st.get("starting_files") or {}).items():
        perms = spec.get("perms", "")
        if perms.startswith("d"):
            ensure_dir(root, path, {"perms": _perm_to_octal(perms, True)})
        else:
            add_file(root, path, {"perms": _perm_to_octal(perms, False)})
    if st.get("starting_files"):
        log.append(f"  starting_files         {len(st['starting_files'])} entries")

    return log


COMPOSE_OVERRIDE = """\
# Generated by plugins/cowrie_fs.py — do not edit, and do not commit.
# Compose merges this over docker-compose.yml automatically. Delete it to go
# back to stock Cowrie.
#
# Mounted at NEW paths, never on top of Cowrie's own directories: their docs
# warn that mounting /cowrie/cowrie-git/etc hides the files already there
# (userdb.txt, cowrie.cfg.dist) and breaks logins. Single-file mounts hide
# nothing.
services:
  cowrie:
    env_file:
      - ./plugins/cowrie/cowrie.env
    volumes:
      - ./plugins/cowrie/fs.pickle:/myfs/fs.pickle:ro
      - ./plugins/cowrie/honeyfs/proc/version:/cowrie/cowrie-git/honeyfs/proc/version:ro
      - ./plugins/cowrie/honeyfs/etc/os-release:/cowrie/cowrie-git/honeyfs/etc/os-release:ro
      - ./plugins/cowrie/honeyfs/etc/issue:/cowrie/cowrie-git/honeyfs/etc/issue:ro
    environment:
      COWRIE_SHELL_FILESYSTEM: /myfs/fs.pickle
"""


def write_compose_override() -> None:
    """Switch the container onto the generated filesystem."""
    path = os.path.join(_ROOT, "docker-compose.override.yml")
    with open(path, "w") as fh:
        fh.write(COMPOSE_OVERRIDE)
    print(f"wrote  {os.path.relpath(path, _ROOT)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change, write nothing")
    args = ap.parse_args()

    with open(os.path.join(_ROOT, "config.yaml")) as fh:
        cfg = (yaml.safe_load(fh) or {}).get("filesystem")
    if not cfg:
        sys.exit("config.yaml has no `filesystem:` section — nothing to build.")

    base = os.path.join(_HERE, cfg["base"])
    out = os.path.join(_HERE, cfg["out"])
    if not os.path.exists(base):
        sys.exit(f"base tree not found: {base}")

    root = load_tree(base)
    print(f"base : {cfg['base']}  ({'%d files, %d dirs' % count(root)})")

    # system_state first, so anything named explicitly under `filesystem:`
    # below overrides it rather than the other way round.
    conf = load_config()
    for line in sync_system_state(root, conf):
        print(line)

    since = str((conf.system_state or {}).get("shadow_changed") or "")
    for path, body in persona_tree_files(conf).items():
        what = add_file(root, path, {"content": body, "perms": "0644", "mtime": since})
        print(f"  {path:<22} {what} (identity)")

    for path in cfg.get("remove") or []:
        print(f"  remove {path:<42} {'ok' if remove(root, path) else 'NOT PRESENT'}")

    for path, spec in (cfg.get("dirs") or {}).items():
        ensure_dir(root, path, spec or {})
        print(f"  dir    {path}")

    for path, spec in (cfg.get("files") or {}).items():
        spec = dict(spec or {})
        if spec.get("source"):
            # contents kept as a file beside the generator, relative to plugins/
            with open(os.path.join(_HERE, spec.pop("source")), encoding="utf-8") as fh:
                spec["content"] = _fill_decoys(fh.read(), conf.honeypot.hostname + path)
        what = add_file(root, path, spec)
        size = spec.get("size", len(spec.get("content") or ""))
        print(f"  file   {path:<42} {what}, size {size}")

    f, d = count(root)
    print(f"result: {f:,} files, {d:,} dirs")

    if args.dry_run:
        print("\nDRY RUN — nothing written.")
        return

    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "wb") as fh:
        pickle.dump(root, fh)
    os.replace(tmp, out)          # atomic: a half-written pickle stops Cowrie booting
    print(f"wrote  {cfg['out']}  ({os.path.getsize(out) / 1024:.0f} KB)")

    # ── identity ────────────────────────────────────────────────────────
    # Structure alone is not enough. `uname` answered by Cowrie still says
    # svr04/Debian the moment it is piped or substituted — `uname -a | cat`,
    # `echo $(uname -r)`, `cat /proc/version`. Those come from Cowrie's own
    # config and honeyfs, so they are generated here from the same
    # config.yaml that drives everything else.
    out_dir = os.path.dirname(out)
    print()
    for rel, content in build_persona(conf).items():
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        print(f"wrote  {os.path.relpath(path, _HERE)}")

    write_compose_override()

    print(f"\n{conf.honeypot.hostname} / {conf.honeypot.os} / {conf.honeypot.kernel}")
    print("\nNext: docker-compose down && docker-compose up -d"
          "   (Compose v2: docker compose ...)")


if __name__ == "__main__":
    main()
