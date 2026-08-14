"""
threat_intel/mitre_mapper.py — tag attacker commands with MITRE ATT&CK techniques.

Two clearly separated halves, because they have different sources of truth:

  1. DETECTION (ours).  MITRE publishes the taxonomy, not a way to decide which
     technique a given shell command represents — no package does that. So the
     command -> technique_id rules below are ours, written mechanism-first in
     the same style as fi_manager.FI_RULES and router's pattern sets: match on
     what a command *does* (downloads a payload, decodes a blob, clears
     history), never on a hardcoded list of known-bad values, so they
     generalise to attackers we have not seen.

  2. TAXONOMY (MITRE's).  Technique names and tactics come from MITRE's own
     enterprise-attack STIX bundle via mitreattack-python — never hand-typed
     here, so they cannot drift from the official knowledge base.

The 46 MB STIX bundle is far too slow to parse inside a live honeypot, so
build_catalog() distills just the techniques we map into a small JSON file
(mitre_catalog.json) that runtime reads instead. The catalog is generated,
never hand-edited — regenerate it after changing MITRE_RULES:

    python threat_intel/mitre_mapper.py --build

Usage:
    from threat_intel.mitre_mapper import tag
    tag("wget http://x/y.sh")
    # {'technique_id': 'T1105', 'technique': 'Ingress Tool Transfer',
    #  'tactic': 'Command And Control'}
"""

import json
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
STIX_PATH    = os.path.join(_HERE, "enterprise-attack.json")
CATALOG_PATH = os.path.join(_HERE, "mitre_catalog.json")

# ── DETECTION RULES (ours) ────────────────────────────────────────────────────
# Ordered most-specific first; the first match wins, exactly like FI_RULES.
# A command that matches nothing is left untagged rather than force-fitted into
# a technique — an untagged command is honest, a wrong technique is not.
MITRE_RULES = [
    # ── execution of fetched content — more specific than the download alone ──
    (r"\b(?:curl|wget|fetch)\b[^|;]*\|\s*(?:ba)?sh\b",        "T1059.004"),
    (r"\b(?:curl|wget)\b.*&&\s*(?:\./|(?:ba)?sh)\b",           "T1059.004"),
    (r"\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:ba)?sh\b",        "T1059.004"),

    # ── obfuscation / decoding ──────────────────────────────────────────────
    (r"\bbase64\s+(?:-d|--decode)\b",                          "T1140"),
    (r"\b(?:xxd\s+-r|uudecode|openssl\s+enc\s+-d)\b",          "T1140"),
    (r"echo\s+-\w*e\w*\s+['\"]?(?:\\x[0-9a-fA-F]{2}){4,}",     "T1027"),

    # ── credential access ───────────────────────────────────────────────────
    (r"\b(?:cat|less|more|head|tail|strings)\b[^|;]*/etc/(?:shadow|passwd)\b", "T1003.008"),
    (r"\b(?:cat|less|more)\b[^|;]*(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem)\b", "T1552.004"),
    (r"\b(?:cat|grep)\b[^|;]*(?:\.bash_history|\.mysql_history)\b",            "T1552.003"),

    # ── persistence ─────────────────────────────────────────────────────────
    (r">>?\s*[^\s;|]*authorized_keys\b",                       "T1098.004"),
    (r"\bcrontab\b|/etc/cron|\bat\s+\d",                       "T1053.003"),
    (r"\bsystemctl\s+enable\b|/etc/systemd/system",            "T1543.002"),
    (r"\b(?:useradd|adduser)\b",                               "T1136.001"),

    # ── defense evasion ─────────────────────────────────────────────────────
    (r"\bhistory\s+-c\b|>\s*[^\s;|]*\.bash_history\b|\bunset\s+HISTFILE\b", "T1070.003"),
    (r"\b(?:iptables|ufw|firewall-cmd)\b.*(?:-F|--flush|disable|stop)",     "T1686"),
    (r"\b(?:setenforce\s+0|systemctl\s+stop\s+(?:apparmor|auditd))\b",      "T1685"),
    (r"\btouch\s+-[amdt]\b",                                                "T1070.006"),

    # ── impact ──────────────────────────────────────────────────────────────
    (r"\brm\s+(?:-\w*[rf]\w*\s+)+/(?:\s|$|\*)",                "T1485"),
    (r"\brm\s+-\w*[rf]",                                       "T1485"),
    (r"\b(?:xmrig|minerd|cpuminer|stratum\+tcp)\b",            "T1496"),
    (r"\b(?:kill|killall|pkill)\b.*-9\b|\bsystemctl\s+stop\b", "T1489"),
    (r"\bpasswd\b(?!\s*$)|\bchpasswd\b",                       "T1531"),

    # ── privilege escalation / valid accounts ───────────────────────────────
    (r"^\s*sudo\s+",                                           "T1548.003"),
    (r"^\s*su\s+",                                             "T1078.003"),

    # ── lateral movement ────────────────────────────────────────────────────
    (r"^\s*(?:ssh|scp|sftp)\s+",                               "T1021.004"),

    # ── file transfer (plain download, after the pipe-to-shell cases) ───────
    (r"^\s*(?:wget|curl|tftp|ftpget|scp)\b",                   "T1105"),

    # ── discovery ───────────────────────────────────────────────────────────
    (r"^\s*(?:nmap|masscan|zmap)\b",                           "T1046"),
    (r"^\s*(?:netstat|ss|lsof)\b",                             "T1049"),
    (r"^\s*(?:ifconfig|ip\s+a|ip\s+addr|arp|route)\b",         "T1016"),
    (r"^\s*(?:ps|top|htop|pgrep)\b",                           "T1057"),
    (r"^\s*(?:whoami|id|who|w|users|groups|logname)\b",        "T1033"),
    (r"^\s*(?:uname|hostname|lscpu|lsb_release|arch)\b|/proc/(?:cpuinfo|meminfo|version)", "T1082"),
    (r"^\s*(?:dpkg|rpm|apt\s+list|yum\s+list|which|whereis)\b","T1518"),
    (r"^\s*(?:ls|dir|find|locate|tree|du)\b",                  "T1083"),
    (r"^\s*(?:chmod|chown|chgrp|chattr)\b",                    "T1222.002"),
]
_COMPILED = [(re.compile(p, re.I), tid) for p, tid in MITRE_RULES]


def classify(cmd: str):
    """technique_id for `cmd`, or None when nothing matches (left untagged)."""
    if not cmd:
        return None
    s = cmd.strip()
    if s.startswith("sudo "):
        # `sudo <x>` is privilege escalation AND whatever x does; the more
        # informative answer is x, so retry on the inner command first.
        inner = classify(s[5:])
        if inner:
            return inner
    for rx, tid in _COMPILED:
        if rx.search(s):
            return tid
    return None


# ── TAXONOMY (MITRE's) ────────────────────────────────────────────────────────

_catalog = None


def _load_catalog() -> dict:
    global _catalog
    if _catalog is None:
        try:
            with open(CATALOG_PATH, encoding="utf-8") as f:
                _catalog = json.load(f)
        except Exception:
            _catalog = {}
    return _catalog


def tag(cmd: str):
    """Full tag for a command: {technique_id, technique, tactic} or None.

    Names/tactics are whatever MITRE's own STIX bundle says (via the generated
    catalog) — this module never invents them. A technique we can map but that
    is missing from the catalog still returns its ID, so a stale catalog
    degrades to 'ID only' rather than dropping the tag entirely."""
    tid = classify(cmd)
    if not tid:
        return None
    meta = _load_catalog().get(tid, {})
    return {
        "technique_id": tid,
        "technique": meta.get("name"),
        "tactic": meta.get("tactic"),
    }


def build_catalog(stix_path: str = STIX_PATH, out_path: str = CATALOG_PATH) -> dict:
    """Distill the techniques MITRE_RULES uses out of the official STIX bundle.

    Run after editing MITRE_RULES. Keeps the honeypot's runtime dependency to a
    ~4 KB JSON instead of parsing a 46 MB bundle on every start."""
    from mitreattack.stix20 import MitreAttackData

    wanted = {tid for _, tid in MITRE_RULES}
    data = MitreAttackData(stix_path)

    by_id = {}
    for t in data.get_techniques(remove_revoked_deprecated=True):
        ext = next((r for r in t.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext.get("external_id")
        if tid in wanted:
            phases = [p["phase_name"] for p in t.get("kill_chain_phases", [])
                      if p.get("kill_chain_name") == "mitre-attack"]
            by_id[tid] = {
                "name": t["name"],
                # a technique can belong to several tactics; keep the first for
                # the dashboard's single-tactic grouping, all of them for detail
                "tactic": phases[0].replace("-", " ").title() if phases else None,
                "tactics": [p.replace("-", " ").title() for p in phases],
                "url": ext.get("url"),
            }

    missing = sorted(wanted - set(by_id))
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(by_id, f, indent=2, ensure_ascii=False, sort_keys=True)

    print(f"[mitre] catalog written -> {out_path} ({len(by_id)}/{len(wanted)} techniques)")
    if missing:
        print(f"[mitre] WARNING: not found in STIX (typo or revoked?): {missing}")
    return by_id


if __name__ == "__main__":
    import sys
    if "--build" in sys.argv:
        build_catalog()
    else:
        for c in sys.argv[1:]:
            print(f"{c!r} -> {tag(c)}")
