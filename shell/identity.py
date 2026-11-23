"""
shell/identity.py -- what the configured OS calls itself, in one place.

The generator writes /etc/os-release and /etc/lsb-release from this, and
`lsb_release` / `hostnamectl` answer from it, so they cannot disagree.
Release facts: releases.ubuntu.com and base-files in packages.ubuntu.com.
"""
# major.minor -> (codename, full name used in os-release, debian_version)
UBUNTU = {
    "18.04": ("bionic", "Bionic Beaver", "buster/sid"),
    "20.04": ("focal", "Focal Fossa", "bullseye/sid"),
    "22.04": ("jammy", "Jammy Jellyfish", "bookworm/sid"),
    "24.04": ("noble", "Noble Numbat", "trixie/sid"),
}


def split_os(os_string: str):
    """"Ubuntu 22.04 LTS" -> ("Ubuntu", "22.04"); the whole string when no version."""
    parts = os_string.split()
    name = parts[0] if parts else os_string
    for p in parts[1:]:
        if p[:1].isdigit():
            return name, p
    return name, ""


def lsb(os_string: str):
    """{id, description, release, codename} for `lsb_release`, or None off Ubuntu."""
    name, version = split_os(os_string)
    majmin = ".".join(version.split(".")[:2])
    if name.lower() != "ubuntu" or majmin not in UBUNTU:
        return None
    return {"id": name, "description": os_string, "release": majmin,
            "codename": UBUNTU[majmin][0]}
