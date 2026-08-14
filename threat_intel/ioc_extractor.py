"""
threat_intel/ioc_extractor.py — extract Indicators of Compromise from honeypot logs.

Turns raw attacker activity (session command logs + auth logs) into STRUCTURED,
exportable indicators — the core of a threat-intelligence platform. Everything
here is MECHANISM-BASED: we match on what an IOC *looks like* (URL/IP/hash/
wallet shape), never on a hardcoded list of known-bad values, so it generalises
to attackers we've never seen.

IOC types extracted:
  ipv4 / ipv6   — attacker source IPs + any IP referenced in a command
                  (wget/curl targets, /dev/tcp reverse shells, etc.)
  url           — http/https/ftp(s) URLs (payload downloads, C2)
  domain        — bare domains referenced in commands
  md5/sha1/sha256 — file hashes appearing in commands/output
  wallet        — BTC / ETH / Monero cryptocurrency addresses (miner configs)
  cve           — CVE identifiers referenced in commands/output (exploit tools
                  frequently name the CVE they target, e.g. log4shell scripts)
  email         — email addresses (C2 drop addresses, spam/phishing tooling)
  credential    — username:password pairs tried against the honeypot

Each indicator is aggregated with metadata: occurrence count, first/last seen,
the sessions and source IPs it appeared in, and the max FI score of the
commands it came from (a rough severity signal).

Export formats: JSON, CSV, and a minimal STIX 2.1 bundle (so the feed can be
ingested by MISP / OpenCTI / any TAXII consumer).
"""
import os
import re
import csv
import json
import uuid
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone

# ── IOC patterns (shape-based, not value-based) ───────────────────────────────
_RE = {
    "url":    re.compile(r'\b(?:https?|ftps?)://[^\s\'"<>|;`)\]]+', re.I),
    "ipv4":   re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'),
    "ipv6":   re.compile(r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b', re.I),
    "sha256": re.compile(r'\b[a-f0-9]{64}\b', re.I),
    "sha1":   re.compile(r'\b[a-f0-9]{40}\b', re.I),
    "md5":    re.compile(r'\b[a-f0-9]{32}\b', re.I),
    # crypto wallets
    "wallet_btc": re.compile(r'\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    "wallet_eth": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "wallet_xmr": re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
    # bare domain (has a dot + a TLD-ish suffix), matched loosely then filtered
    "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b', re.I),
    # CVE identifiers — canonical form is CVE-YYYY-NNNN+ (4-digit year, 4+ digit sequence)
    "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I),
    "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b'),
}

# domains that are the honeypot's own noise / not attacker infrastructure
_DOMAIN_IGNORE = {"example.com", "www.example.com", "example.org", "example.net",
                  "company.com", "localhost", "localdomain"}
# domain suffixes to drop wholesale (documentation/placeholder ranges)
_DOMAIN_IGNORE_SUFFIX = (".example.com", ".example.org", ".example.net", ".local")

# hashes that carry no intel: the empty-file hashes, and degenerate all-same-char
_EMPTY_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5 of ""
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1 of ""
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256 of ""
}

# File/script extensions that the domain regex mistakes for a TLD — e.g. the
# busybox malware droppers wget "bins.sh"/"tftp1.sh", which are FILENAMES, not
# Saint-Helena (.sh) domains. Excluding these by extension is structural (a file
# suffix, not a hardcoded bad value), and correct for an SSH-honeypot context
# where "<name>.sh" is overwhelmingly a script, not a domain.
_FILE_EXT_TLDS = {
    "sh", "bash", "py", "pl", "php", "rb", "lua", "js", "pyc",
    "txt", "log", "conf", "cfg", "dat", "sql", "csv", "json", "xml",
    "yml", "yaml", "md", "ini", "lock", "pid", "tmp", "bak", "old",
    "bin", "elf", "exe", "dll", "so", "ko", "o", "c", "h", "img",
    "tar", "gz", "tgz", "bz2", "xz", "zip", "rar", "7z", "z", "arj",
    "out", "run", "mips", "mpsl", "arm", "arm7", "x86", "x86_64", "i586", "i686",
    "spc", "sparc", "ppc", "m68k", "sh4", "nippon",
    # systemd unit suffixes (systemctl output looks like domains)
    "service", "slice", "socket", "target", "mount", "timer", "device", "scope",
    # key/cert filenames
    "pub", "key", "pem", "crt", "cert", "gpg", "asc", "csr",
}


def _is_public_ip(value: str) -> bool:
    """Keep only routable public IPs — private/loopback/link-local are the
    honeypot's own network, not attacker infrastructure."""
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def extract_from_text(text: str) -> list:
    """Return [(ioc_type, value), ...] found in a single string. Longest/most
    specific patterns first so a sha256 isn't also reported as md5, etc."""
    if not text:
        return []
    found = []
    seen = set()

    def add(t, v):
        key = (t, v)
        if key not in seen:
            seen.add(key)
            found.append((t, v))

    # URLs first (so their host isn't separately double-counted as a domain)
    url_spans = []
    for m in _RE["url"].finditer(text):
        add("url", m.group(0).rstrip('.,);'))
        url_spans.append((m.start(), m.end()))

    def _inside_url(pos):
        return any(a <= pos < b for a, b in url_spans)

    # Emails next (so an email's domain half isn't separately double-counted
    # as a bare "domain", same reasoning as URLs above)
    email_spans = []
    for m in _RE["email"].finditer(text):
        add("email", m.group(0).lower())
        email_spans.append((m.start(), m.end()))

    def _inside_email(pos):
        return any(a <= pos < b for a, b in email_spans)

    for m in _RE["cve"].finditer(text):
        add("cve", m.group(0).upper())

    for t in ("sha256", "sha1", "md5"):
        for m in _RE[t].finditer(text):
            h = m.group(0).lower()
            if h in _EMPTY_HASHES or len(set(h)) <= 1:  # empty-file / all-same-char
                continue
            add(t, h)

    for t in ("wallet_btc", "wallet_eth", "wallet_xmr"):
        for m in _RE[t].finditer(text):
            add(t, m.group(0))

    for m in _RE["ipv4"].finditer(text):
        v = m.group(0)
        if _is_public_ip(v):
            add("ipv4", v)
    for m in _RE["ipv6"].finditer(text):
        v = m.group(0)
        if _is_public_ip(v):
            add("ipv6", v)

    for m in _RE["domain"].finditer(text):
        v = m.group(0).lower().rstrip('.')
        if _inside_url(m.start()) or _inside_email(m.start()):
            continue
        if v in _DOMAIN_IGNORE or v.endswith(_DOMAIN_IGNORE_SUFFIX):
            continue
        # skip things that are actually IPs
        if _RE["ipv4"].fullmatch(v):
            continue
        # skip filenames whose "TLD" is really a file/script/unit extension
        if v.rsplit(".", 1)[-1] in _FILE_EXT_TLDS:
            continue
        add("domain", v)

    return found


class IOCStore:
    """Aggregates indicators with metadata across many events."""

    def __init__(self):
        # key=(type,value) -> record
        self._iocs = {}

    def add(self, ioc_type, value, *, session_id=None, src_ip=None,
            timestamp=None, fi=0, context=None):
        key = (ioc_type, value)
        rec = self._iocs.get(key)
        if rec is None:
            rec = {
                "type": ioc_type, "value": value, "count": 0,
                "first_seen": timestamp, "last_seen": timestamp,
                "sessions": set(), "src_ips": set(), "max_fi": 0,
                "sample_context": context,
            }
            self._iocs[key] = rec
        rec["count"] += 1
        if session_id:
            rec["sessions"].add(session_id)
        if src_ip:
            rec["src_ips"].add(src_ip)
        if timestamp:
            if not rec["first_seen"] or timestamp < rec["first_seen"]:
                rec["first_seen"] = timestamp
            if not rec["last_seen"] or timestamp > rec["last_seen"]:
                rec["last_seen"] = timestamp
        rec["max_fi"] = max(rec["max_fi"], fi or 0)

    def records(self):
        out = []
        for rec in self._iocs.values():
            r = dict(rec)
            r["sessions"] = sorted(r["sessions"])
            r["src_ips"] = sorted(r["src_ips"])
            r["session_count"] = len(r["sessions"])
            out.append(r)
        # most-seen, highest-severity first
        out.sort(key=lambda r: (r["max_fi"], r["count"]), reverse=True)
        return out

    def __len__(self):
        return len(self._iocs)


def build_iocs(session_rows, auth_rows=None) -> IOCStore:
    """Extract + aggregate IOCs from session command logs and (optionally) auth
    logs. `session_rows` = list of dicts with cmd/response/src_ip/session_id/
    fi_score/timestamp. `auth_rows` = list of dicts with username/password/
    src_ip/timestamp."""
    store = IOCStore()

    for r in session_rows or []:
        sid = r.get("session_id")
        ip = r.get("src_ip")
        ts = r.get("timestamp")
        fi = r.get("fi_score", 0) or 0
        cmd = r.get("cmd", "") or ""
        resp = r.get("response", "") or ""

        # the attacker's own source IP is itself an IOC
        if ip and _is_public_ip(ip):
            store.add("ipv4" if ":" not in ip else "ipv6", ip,
                      session_id=sid, src_ip=ip, timestamp=ts, fi=fi,
                      context="attacker source IP")

        for t, v in extract_from_text(cmd):
            store.add(t, v, session_id=sid, src_ip=ip, timestamp=ts, fi=fi,
                      context=cmd[:160])
        for t, v in extract_from_text(resp):
            store.add(t, v, session_id=sid, src_ip=ip, timestamp=ts, fi=fi,
                      context=f"(in response) {cmd[:120]}")

    for a in auth_rows or []:
        u = a.get("username")
        p = a.get("password")
        ip = a.get("src_ip")
        ts = a.get("timestamp")
        if u is not None and p is not None:
            store.add("credential", f"{u}:{p}", src_ip=ip, timestamp=ts, fi=0,
                      context="login attempt")
        if ip and _is_public_ip(ip):
            store.add("ipv4" if ":" not in ip else "ipv6", ip,
                      src_ip=ip, timestamp=ts, fi=0, context="auth source IP")

    return store


# ── exporters ─────────────────────────────────────────────────────────────────

def to_json(store: IOCStore, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store.records(), f, indent=2, ensure_ascii=False)
    return path


def to_csv(store: IOCStore, path: str):
    fields = ["type", "value", "count", "session_count", "max_fi",
              "first_seen", "last_seen", "src_ips", "sample_context"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in store.records():
            row = dict(r)
            row["src_ips"] = ";".join(r["src_ips"])
            w.writerow(row)
    return path


# STIX type mapping — bare-minimum STIX 2.1 indicators so the feed is ingestible
_STIX_PATTERN = {
    "ipv4":   lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv6":   lambda v: f"[ipv6-addr:value = '{v}']",
    "url":    lambda v: "[url:value = '{}']".format(v.replace("'", "\\'")),
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "md5":    lambda v: f"[file:hashes.'MD5' = '{v}']",
    "sha1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "email":  lambda v: "[email-addr:value = '{}']".format(v.replace("'", "\\'")),
    # cve has no standard STIX Cyber Observable type — falls through to the
    # generic x-honeypot pattern below, same as wallets/credentials.
}


def to_stix(store_or_records, path: str):
    """Minimal STIX 2.1 bundle of indicator SDOs. Wallets/credentials have no
    standard STIX object type, so they're emitted as generic indicators with a
    custom pattern comment rather than skipped.

    Accepts either a live IOCStore (the `hp intel` CLI path) or a plain list
    of already-computed record dicts (IOCStore.records()'s own output shape —
    the dashboard's Threat Intel page caches just the records, since an
    IOCStore itself isn't JSON-serializable into a browser-side dcc.Store)."""
    records = store_or_records.records() if hasattr(store_or_records, "records") else store_or_records
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    for r in records:
        t, v = r["type"], r["value"]
        patt_fn = _STIX_PATTERN.get(t)
        pattern = patt_fn(v) if patt_fn else f"[x-honeypot:{t} = '{v}']"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"{t}: {v}",
            "description": f"Observed {r['count']}x across {r['session_count']} "
                           f"honeypot session(s); max FI {r['max_fi']}.",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": r["first_seen"] or now,
            "labels": [f"honeypot-observed", f"ioc-{t}"],
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    return path
