"""
tools/install_service.py — render systemd units for this checkout.

Without supervision a crashed honeypot stays down until somebody notices, and
a honeypot that is quiet because it died looks exactly like one that is quiet
because nobody attacked it.

Paths are read from the running interpreter and this file's location, so the
rendered units are correct for wherever the repo actually lives — nothing is
hard coded to one machine.

Writes to ./deploy/ by default and prints the install commands rather than
running them, because installing needs root and this script does not.

Usage
-----
    python tools/install_service.py                  # render + print next steps
    python tools/install_service.py --user           # ~/.config/systemd/user units
    python tools/install_service.py --memmax 4G
    python tools/install_service.py --print          # show rendered units
"""
import argparse
import getpass
import grp
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

TEMPLATES = {
    "hydrapot.service":           "deploy/hydrapot.service.template",
    "hydrapot-dashboard.service": "deploy/hydrapot-dashboard.service.template",
}


def _hp_executable() -> str:
    """The `hp` entry point that belongs to the interpreter running this."""
    cand = os.path.join(os.path.dirname(sys.executable), "hp")
    if os.path.exists(cand):
        return cand
    # fall back to whatever is on PATH, but say so — a wrong ExecStart is the
    # most common reason one of these units fails on first start
    import shutil
    found = shutil.which("hp")
    if found:
        print(f"[warn] no `hp` beside {sys.executable}; using {found} from PATH")
        return found
    sys.exit("Could not locate the `hp` executable. Run this with the "
             "interpreter from the project virtualenv:\n"
             "  honeypot_new/bin/python tools/install_service.py")


def main():
    ap = argparse.ArgumentParser(description="Render systemd units for HydraPoT")
    ap.add_argument("--user", action="store_true",
                    help="render for `systemctl --user` instead of system-wide")
    ap.add_argument("--memmax", default="4G", help="MemoryMax for the sensor")
    ap.add_argument("--dash-host", default="127.0.0.1")
    ap.add_argument("--dash-port", default="8050")
    ap.add_argument("--out", default=os.path.join(_ROOT, "deploy"))
    ap.add_argument("--print", dest="show", action="store_true",
                    help="print the rendered units")
    a = ap.parse_args()

    user = getpass.getuser()
    try:
        group = grp.getgrgid(os.getgid()).gr_name
    except KeyError:
        group = user
    exe = _hp_executable()

    subs = {
        "@USER@": user, "@GROUP@": group, "@DIR@": _ROOT, "@EXEC@": exe,
        "@MEMMAX@": a.memmax,
        "@DASHHOST@": a.dash_host, "@DASHPORT@": str(a.dash_port),
    }

    os.makedirs(a.out, exist_ok=True)
    written = []
    for name, tmpl in TEMPLATES.items():
        src = os.path.join(_ROOT, tmpl)
        if not os.path.exists(src):
            sys.exit(f"missing template: {src}")
        text = open(src, encoding="utf-8").read()
        for k, v in subs.items():
            text = text.replace(k, v)
        if a.user:
            # `systemctl --user` has no User=/Group=, and the hardening
            # directives that need root are dropped rather than silently
            # ignored.
            drop = ("User=", "Group=", "ProtectSystem=", "ProtectHome=",
                    "ProtectKernelTunables=", "ProtectControlGroups=",
                    "ReadWritePaths=")
            text = "\n".join(l for l in text.splitlines()
                             if not l.startswith(drop))
            text = text.replace("WantedBy=multi-user.target",
                                "WantedBy=default.target")
        dest = os.path.join(a.out, name)
        open(dest, "w", encoding="utf-8").write(text)
        written.append(dest)
        if a.show:
            print(f"\n===== {name} =====\n{text}")

    print("rendered:")
    for w in written:
        print(f"  {w}")
    print(f"\n  User={user}  Group={group}")
    print(f"  WorkingDirectory={_ROOT}")
    print(f"  ExecStart={exe} run")

    print("\nnext steps:")
    if a.user:
        print("  mkdir -p ~/.config/systemd/user")
        print(f"  cp {a.out}/*.service ~/.config/systemd/user/")
        print("  systemctl --user daemon-reload")
        print("  systemctl --user enable --now hydrapot.service")
        print("  systemctl --user status hydrapot.service")
        print("  journalctl --user -u hydrapot -f")
        print("\n  # keep user units running when you are not logged in:")
        print(f"  sudo loginctl enable-linger {user}")
    else:
        print(f"  sudo cp {a.out}/*.service /etc/systemd/system/")
        print("  sudo systemctl daemon-reload")
        print("  sudo systemctl enable --now hydrapot.service")
        print("  sudo systemctl status hydrapot.service")
        print("  sudo journalctl -u hydrapot -f")

    print("\n  Stop any hand-started process first, or the unit fails to bind "
          "the port:")
    print("    pkill -f 'hp run'    # check with: ps -eo pid,cmd | grep 'hp run'")


if __name__ == "__main__":
    main()
