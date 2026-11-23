"""
shell/packages.py -- `dpkg -l` and `apt list --installed`, from the image's own package database.

Both went to a model, which invented a list that changed between calls. The image knows
exactly what it has installed (plugins/image_snapshot.py reads dpkg's own table), so the
two commands print that, plus the server packages the operator declares and whatever the
attacker installed this session.
"""
import fnmatch
import re

# Binary packages built from one source share its version, so a package the image does not
# carry takes the version of a sibling it does (systemd's binaries all carry systemd's).
SIBLING = {"systemd": "libsystemd0", "systemd-sysv": "libsystemd0", "udev": "libudev1",
           "dbus": "libdbus-1-3", "openssh-server": "openssh-client"}
# No sibling in the image: the focal-updates version, from
# https://ubuntuupdates.org/package/core/focal/main/base/rsyslog
FIXED_VERSION = {"rsyslog": "8.2001.0-1ubuntu1.3"}
SUMMARY = {
    "systemd": "system and service manager",
    "systemd-sysv": "system and service manager - SysV links",
    "udev": "/dev/ and hotplug management daemon",
    "dbus": "simple interprocess messaging system (daemon and utilities)",
    "openssh-server": "secure shell (SSH) server, for secure access from remote machines",
    "rsyslog": "reliable system and kernel logging daemon",
}
# Versions from the security/updates pockets add a point to the Ubuntu revision
# (2.31-0ubuntu9.9, 4ubuntu3.19); the release pocket's have none (3.118ubuntu2)
_UPDATED = re.compile(r"ubuntu\d+\.\d+|~20\.04|\+esm")


def table(image_rows, extra_names, session_facts):
    """[{name, version, arch, summary, auto}] sorted by name: image + declared + installed."""
    rows = {r["name"]: dict(r) for r in image_rows}
    for name in extra_names or []:
        if name in rows:
            continue
        sib = rows.get(SIBLING.get(name, ""))
        version = FIXED_VERSION.get(name) or (sib["version"] if sib else None)
        if version:
            rows[name] = {"name": name, "version": version, "arch": "amd64",
                          "summary": SUMMARY.get(name, ""), "auto": False}
    for name, (version, _text) in (session_facts or {}).items():
        rows.setdefault(name, {"name": name, "version": version, "arch": "amd64",
                               "summary": "", "auto": False})
    return [rows[k] for k in sorted(rows)]


def _selected(rows, patterns):
    if not patterns:
        return rows
    return [r for r in rows if any(fnmatch.fnmatchcase(r["name"], p) for p in patterns)]


def dpkg_list(rows, argv, cols=80):
    """`dpkg -l [pattern...]` in dpkg-query's layout, or None for flags not modelled."""
    flags = [a for a in argv[1:] if a.startswith("-")]
    patterns = [a for a in argv[1:] if not a.startswith("-")]
    if any(f not in ("-l", "--list") for f in flags) or not flags:
        return None
    chosen = _selected(rows, patterns)
    if patterns and not chosen:
        return "\n".join(f"dpkg-query: no packages found matching {p}" for p in patterns)
    w_name = max([len(r["name"]) for r in chosen] + [4])
    w_ver = max([len(r["version"]) for r in chosen] + [7])
    w_arch = max([len(r["arch"]) for r in chosen] + [12])
    w_desc = max(cols - (4 + w_name + 1 + w_ver + 1 + w_arch + 1), 4)
    out = ["Desired=Unknown/Install/Remove/Purge/Hold",
           "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend",
           "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)",
           f"||/ {'Name':<{w_name}} {'Version':<{w_ver}} {'Architecture':<{w_arch}} Description",
           f"+++-{'=' * w_name}-{'=' * w_ver}-{'=' * w_arch}-{'=' * w_desc}"]
    for r in chosen:
        out.append(f"ii  {r['name']:<{w_name}} {r['version']:<{w_ver}} {r['arch']:<{w_arch}} "
                   f"{r['summary']}"[: 4 + w_name + 1 + w_ver + 1 + w_arch + 1 + w_desc])
    return "\n".join(out)


def apt_list(rows, argv, piped, quiet):
    """`apt list --installed [pattern...]`, or None (a plain `apt list` needs the archive)."""
    args = argv[2:]
    if argv[1:2] != ["list"] or not any(a in ("--installed", "-i") for a in args):
        return None
    if any(a.startswith("-") and a not in ("--installed", "-i") for a in args):
        return None
    patterns = [a for a in args if not a.startswith("-")]
    lines = [] if quiet else ["", "WARNING: apt does not have a stable CLI interface. "
                              "Use with caution in scripts.", ""]
    lines.append("Listing..." if piped else "Listing... Done")
    for r in _selected(rows, patterns):
        suite = "focal-updates,focal-security" if _UPDATED.search(r["version"]) else "focal"
        flag = "installed,automatic" if r.get("auto") else "installed"
        lines.append(f"{r['name']}/{suite},now {r['version']} {r['arch']} [{flag}]")
    return "\n".join(lines)
