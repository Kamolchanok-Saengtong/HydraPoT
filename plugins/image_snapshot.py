#!/usr/bin/env python3
"""
plugins/image_snapshot.py -- read the machine's identity from a real container.

The honeypot's OS files come from the docker image named in config.yaml
system_state.stock_image: its OS release, accounts, dotfiles, crontab and skel. That
is the image's own content, the same for anyone who pulls it.

It deliberately reads NOTHING about the machine running docker. A container shares the
host's kernel and /proc, so `uname`, /proc/cpuinfo and /proc/meminfo would be the
operator's real hardware; the kernel, CPU and memory the honeypot shows are declared in
config.yaml instead.

Writes plugins/snapshot/:
    manifest.json    image, date, per-file mode/uid/gid/mtime
    files/<path>     file contents (etc/os-release, etc/passwd, root/.bashrc ...)

Not captured: /etc/hostname, /etc/hosts, /etc/resolv.conf and /etc/machine-id (docker
writes them per container), and anything under /proc.

    python plugins/image_snapshot.py                     # image from config.yaml
    python plugins/image_snapshot.py --image ubuntu:22.04
"""
import argparse
import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile

_HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(_HERE, "snapshot")

# What to read from the image's filesystem (directories are read recursively).
TREE = ["/etc/os-release", "/usr/lib/os-release", "/etc/lsb-release", "/etc/issue", "/etc/issue.net",
        "/etc/debian_version", "/etc/shells", "/etc/crontab", "/etc/passwd", "/etc/group",
        "/etc/shadow", "/etc/skel", "/root/.bashrc", "/root/.profile", "/etc/cron.d",
        "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
        "/var/spool/cron/crontabs", "/etc/environment", "/etc/default/locale"]


def _run(image, script, text=True, timeout=300):
    out = subprocess.run(["docker", "run", "--rm", image, "bash", "-c", script],
                         capture_output=True, timeout=timeout)
    if out.returncode != 0 and not out.stdout:
        raise SystemExit(f"{image}: {out.stderr.decode(errors='replace').strip()[:300]}")
    return out.stdout.decode(errors="replace") if text else out.stdout


def snapshot(image: str, out_dir: str = OUT) -> dict:
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    files_dir = os.path.join(out_dir, "files")
    os.makedirs(files_dir)
    meta = {}

    # the filesystem part, as one tar stream so modes, owners and dates are the image's own
    probe = " ".join(f'"{p}"' for p in TREE)
    raw = _run(image, f'tar -cf - --numeric-owner $(for p in {probe}; do [ -e "$p" ] && echo "$p"; done) 2>/dev/null',
               text=False)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for m in tar:
            path = "/" + m.name.strip("/")
            meta[path] = {"type": "dir" if m.isdir() else "link" if m.issym() else "file",
                          "mode": m.mode, "uid": m.uid, "gid": m.gid,
                          "mtime": m.mtime, "size": m.size, "target": m.linkname or None}
            if m.isfile():
                dest = os.path.join(files_dir, path.lstrip("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(tar.extractfile(m).read())

    manifest = {"image": image, "taken": str(datetime.date.today()), "files": meta}
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    return manifest


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--image", default=None,
                    help="docker image to read (default: config.yaml system_state.stock_image)")
    args = ap.parse_args()
    image = args.image
    if not image:
        sys.path.insert(0, os.path.dirname(_HERE))
        from core.config_loader import load_config
        image = load_config().system_state.get("stock_image", "ubuntu:20.04")
    m = snapshot(image)
    print(f"{image}: {len(m['files'])} entries -> {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
