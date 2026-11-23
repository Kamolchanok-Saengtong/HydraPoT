"""`git clone` of a public repo, built from the hosting site's real file list.

Cowrie has no git, so `git clone` used to fall through to the cloud model, which
invented a repo (a LICENSE and a one-line README) that never matched the real
one. Here the tree comes from the host's API and Cowrie fetches each file with
its own sandboxed wget, so a later `ls` and `cat` return real content.

Anything this cannot serve returns None and takes the old path, so enabling it
can only make a clone more faithful, never fail one that used to work.
"""
import json
import os
import re
import shlex
import time
import urllib.error
import urllib.parse
import urllib.request

_URL = re.compile(
    r"^https?://(?P<host>[A-Za-z0-9.-]+)/(?P<owner>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$")
_PART = re.compile(r"^[A-Za-z0-9._@+=,-]+$")
_DEST = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._/-]*$")
# Accepted and ignored: they change how git fetches, not what it leaves behind.
_IGNORED = {"-q", "--quiet", "--single-branch", "--no-tags", "--recursive"}

_TTL = 600
_trees = {}          # (host, owner, repo) -> (fetched_at, entries)


class _NotFound(Exception):
    pass


class _Unavailable(Exception):
    pass


def parse(cmd: str):
    """-> (host, owner, repo, dest) or None when this is not a plain clone."""
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if tokens[:2] != ["git", "clone"]:
        return None
    args, i = [], 2
    while i < len(tokens):
        t = tokens[i]
        if t in _IGNORED:
            pass
        elif t == "--depth" and i + 1 < len(tokens) and tokens[i + 1].isdigit():
            i += 1
        elif re.fullmatch(r"--depth=\d+", t):
            pass
        elif t.startswith("-"):
            return None             # an option we do not model: let the model answer
        else:
            args.append(t)
        i += 1
    if not 1 <= len(args) <= 2:
        return None
    m = _URL.match(args[0])
    if not m:
        return None
    dest = args[1] if len(args) == 2 else m["repo"]
    if not _DEST.match(dest) or ".." in dest.split("/"):
        return None
    return m["host"], m["owner"], m["repo"], dest.rstrip("/")


def _fetch_tree(hc, owner, repo, token):
    url = hc["tree"].format(owner=owner, repo=repo)
    headers = {"Accept": "application/json", "User-Agent": "HydraPoT"}   # GitHub 403s an API client posing as git
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                    timeout=8) as r:
            return json.load(r).get("tree") or []
    except urllib.error.HTTPError as e:
        raise (_NotFound() if e.code == 404 else _Unavailable()) from e
    except Exception as e:
        raise _Unavailable() from e


def _tree(host, hc, owner, repo, token):
    key, now = (host, owner, repo), time.time()
    hit = _trees.get(key)
    if hit and now - hit[0] < _TTL:
        return hit[1]
    entries = _fetch_tree(hc, owner, repo, token)
    _trees[key] = (now, entries)
    return entries


def _safe(path: str) -> bool:
    parts = path.split("/")
    return all(_PART.match(p) and p not in (".", "..") for p in parts)


def _pick(entries, cfg):
    """Files to fetch. The top level first (README, LICENSE: what an attacker
    reads first, dotfiles last), then one per folder before a second from any,
    so every folder has something in it when the cap cuts off the rest."""
    files = [e for e in entries
             if e.get("type") == "blob" and _safe(e.get("path", ""))
             and int(e.get("size") or 0) <= cfg.max_file_bytes]
    top = sorted((e for e in files if "/" not in e["path"]),
                 key=lambda e: (e["path"].startswith("."), e["path"]))
    deep = sorted((e for e in files if "/" in e["path"]), key=lambda e: e["path"])
    rank = {}
    for e in deep:
        d = os.path.dirname(e["path"])
        rank[e["path"]] = sum(1 for k in rank if os.path.dirname(k) == d)
    deep.sort(key=lambda e: (rank[e["path"]], e["path"].count("/"), e["path"]))
    keep = cfg.max_files // 2
    return (top[:keep] + deep + top[keep:])[:cfg.max_files]


_LS_ROW = re.compile(r"\s(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(\S+)")
def _fetch(run, target, url, want, attempts, wait):
    """Fetch one file through Cowrie's wget. -> True once it has its full size.

    Cowrie's wget returns at once and downloads in the background, and from some
    networks it fails about two times in three ("Connection timed out. Retrying"),
    so the trailing `ls -l` is the only completion signal and a failed file is
    simply asked for again. The ls also gives the command output, which keeps
    the round trip short (a silent command costs an idle wait). One file per
    command: chained wgets run at once and starve each other.
    """
    listing = f"ls -l {shlex.quote(target)}"
    for _ in range(attempts):
        end = time.time() + wait
        out = run(f"wget -q -O {shlex.quote(target)} {shlex.quote(url)}; {listing}")
        while True:
            # Cowrie prints absolute paths; the attacker's cwd is not ours to assume
            sizes = [int(m[1]) for m in _LS_ROW.finditer(out or "")
                     if m[2] == target or m[2].endswith("/" + target)]
            if want == 0 and sizes or want in sizes:
                return True
            if time.time() > end:
                break
            time.sleep(0.25)
            out = run(listing)
    return False


def clone(cmd, cfg, run, write, mkdir, register):
    """Run a clone. -> the text shown to the attacker, or None to fall through.

    run(cmd)                 send a command to Cowrie, return its output
    write(text)              stream text to the attacker as it happens
    mkdir(cmd)               record a directory Cowrie created
    register(path, url, n)   record a file Cowrie fetched
    """
    parsed = parse(cmd)
    if not parsed:
        return None
    host, owner, repo, dest = parsed
    hc = cfg.hosts.get(host)
    if not hc:
        return None
    try:
        entries = _tree(host, hc, owner, repo, os.environ.get(cfg.token_env, ""))
    except _Unavailable:
        return None
    except _NotFound:
        text = (f"Cloning into '{dest}'...\r\n"
                f"remote: Repository not found.\r\n"
                f"fatal: repository 'https://{host}/{owner}/{repo}/' not found\r\n")
        write(text)
        return text

    t0 = time.time()
    head = f"Cloning into '{dest}'...\r\n"
    write(head)
    files = _pick(entries, cfg)
    # One mkdir per directory, parents first: Cowrie's mkdir has no -p (it makes
    # a directory literally named "-p"), and the tracker records one path each.
    dirs = {dest, f"{dest}/.git"}
    for e in entries:
        if e.get("type") == "tree" and _safe(e.get("path", "")):
            dirs.add(f"{dest}/{e['path']}")
    dirs = set(sorted(dirs, key=lambda d: (d.count("/"), d))[:cfg.max_dirs])
    for f in files:
        parts = f["path"].split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add(f"{dest}/" + "/".join(parts[:i]))
    lines = [f"mkdir {shlex.quote(d)}" for d in sorted(dirs, key=lambda d: (d.count("/"), d))]
    for i in range(0, len(lines), 20):      # one round trip per 20, not per folder
        run("; ".join(lines[i:i + 20]))
    for line in lines:
        mkdir(line)

    for f in files:
        if time.time() - t0 > cfg.max_seconds:
            break
        target = f"{dest}/{f['path']}"
        url = hc["raw"].format(owner=owner, repo=repo, path=urllib.parse.quote(f["path"]))
        size = int(f.get("size") or 0)
        if _fetch(run, target, url, size, cfg.file_attempts, cfg.file_timeout):
            register(target, url, size)

    n = len(entries)
    kib = sum(int(e.get("size") or 0) for e in entries if e.get("type") == "blob") / 1024
    secs = max(time.time() - t0, 0.1)
    tail = (f"remote: Enumerating objects: {n}, done.\r\n"
            f"remote: Counting objects: 100% ({n}/{n}), done.\r\n"
            f"remote: Compressing objects: 100% ({n}/{n}), done.\r\n"
            f"remote: Total {n} (delta 0), reused {n} (delta 0), pack-reused 0\r\n"
            f"Receiving objects: 100% ({n}/{n}), {kib:.2f} KiB | "
            f"{kib / secs:.2f} KiB/s, done.\r\n")
    write(tail)
    return head + tail
