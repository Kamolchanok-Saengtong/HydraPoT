"""
plugins/ubuntu_commands.py -- snapshot what a stock Ubuntu image ships.

Writes two files:
    plugins/ubuntu_commands.txt   one "command /path/to/it" per line
    plugins/ubuntu_packages.txt   one "package version" per line
They are the honeypot's "already installed" set, so config.yaml lists only what
the persona adds (extra_tools, pre_installed) or lacks (missing_tools).

Only commands that exist as files are listed, with the path `which` prints. Bash's
own builtins and keywords come from bash itself (shell/software.py), so they cannot
drift from this file.

    python plugins/ubuntu_commands.py                    # image from config.yaml
    python plugins/ubuntu_commands.py --image ubuntu:22.04
"""
import argparse
import datetime
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(_HERE, "ubuntu_commands.txt")
OUT_PACKAGES = os.path.join(_HERE, "ubuntu_packages.txt")
# Every name bash knows, kept only if a file backs it, with that file's path
_LIST = ('for c in $( (compgen -c; compgen -b) | sort -u ); do '
         'p=$(type -P "$c" 2>/dev/null); [ -n "$p" ] && echo "$c $p"; done; true')


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
    out = subprocess.run(["docker", "run", "--rm", image, "bash", "-c", _LIST],
                         capture_output=True, text=True, timeout=300)
    if out.returncode != 0 or not out.stdout.strip():
        raise SystemExit(f"could not read commands from {image}: {out.stderr.strip()[:200]}")
    rows = sorted(set(line.strip() for line in out.stdout.splitlines() if line.strip()))
    names = rows
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(f"# commands on {image}, generated {datetime.date.today()} by plugins/ubuntu_commands.py\n")
        fh.write("# do not edit: add or remove tools in config.yaml (extra_tools / missing_tools)\n")
        fh.write("\n".join(rows) + "\n")
    print(f"{len(rows)} commands from {image} -> {OUT}")

    pkgs = subprocess.run(["docker", "run", "--rm", image, "dpkg-query", "-W", "-f=${Package} ${Version}\\n"],
                          capture_output=True, text=True, timeout=300)
    if pkgs.returncode != 0 or not pkgs.stdout.strip():
        raise SystemExit(f"could not read packages from {image}: {pkgs.stderr.strip()[:200]}")
    rows = sorted(set(pkgs.stdout.strip().splitlines()))
    with open(OUT_PACKAGES, "w", encoding="utf-8") as fh:
        fh.write(f"# packages on {image}, generated {datetime.date.today()} by plugins/ubuntu_commands.py\n")
        fh.write("# do not edit: add packages in config.yaml (pre_installed)\n")
        fh.write("\n".join(rows) + "\n")
    print(f"{len(rows)} packages from {image} -> {OUT_PACKAGES}")


if __name__ == "__main__":
    main()
