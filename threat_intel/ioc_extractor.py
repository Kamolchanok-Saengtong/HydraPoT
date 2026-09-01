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
from urllib.parse import unquote, urlparse

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

# ── defanged-IOC support ───────────────────────────────────────────────────────
# Attacker-fetched dropper scripts and pasted content sometimes carry IOCs in
# "defanged" form to dodge naive auto-linking/scanners: 1[.]2[.]3[.]4,
# hxxp://evil[.]com, user[at]evil[.]com. Matched with their own patterns, then
# normalised (refanged) back to the real form before being stored — so a
# defanged IOC lands in the same "ipv4"/"url"/"domain"/"email" bucket as a
# plain one, never a separate type the rest of the pipeline (STIX export,
# dashboard) would have to know about. Modeled on msticpy's IoCExtract
# (microsoft/msticpy), which does the same thing more generally.
_DOT_DF = r'(?:\[\.\]|\(\.\)|\[dot\])'
_AT_DF  = r'(?:\[at\]|\(at\))'

_RE_DEFANGED = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)' + _DOT_DF + r'){3}'
        r'(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'),
    "url": re.compile(r'\bhxxps?://[^\s\'"<>`]+', re.I),
    "domain": re.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?' + _DOT_DF + r')+'
        r'[a-z]{2,24}\b', re.I),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+-]+' + _AT_DF + r'[a-zA-Z0-9-]+(?:' + _DOT_DF +
        r'[a-zA-Z0-9-]+)*' + _DOT_DF + r'[a-zA-Z]{2,24}\b'),
}


def _refang(value: str) -> str:
    """Normalise a defanged observable back to its real form."""
    v = re.sub(r'\[\.\]|\(\.\)|\[dot\]', '.', value, flags=re.I)
    v = re.sub(r'\[at\]|\(at\)', '@', v, flags=re.I)
    v = re.sub(r'^hxxp', 'http', v, flags=re.I)
    return v


# Matches just the protocol marker, used to find a SECOND url start embedded
# further inside an already-decoded url (see _add_url below).
_PROTO_START = re.compile(r'(?:https?|ftps?)://', re.I)

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


# ══════════════════════════════════════════════════════════════════════════════
# FALSE-POSITIVE SUPPRESSION
# ══════════════════════════════════════════════════════════════════════════════
# Two independent problems, two independent fixes.
#
# 1. VALID-LOOKING BUT BENIGN. `8.8.8.8`, `google.com`, `archive.ubuntu.com`
#    are real observables, correctly extracted, and useless as indicators —
#    attackers curl them to test egress. Suppressed using MISP's warninglists,
#    which exist for exactly this and are maintained far better than a list we
#    would keep ourselves.
#
# 2. NOT A DOMAIN AT ALL. The domain regex is `(label\.)+[a-z]{2,24}`, so the
#    Linux daemon name `rpc.idmapd` parses as a domain with TLD "idmapd" — 131
#    observations of a false domain. Fixed by requiring the last label to be a
#    real IANA-delegated TLD.
#
# Both degrade safely: if the network is unavailable the cached copy is used,
# and if there is no cache the filters no-op rather than dropping real IOCs.

_FP_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fp_cache")
_MISP_BASE = ("https://raw.githubusercontent.com/MISP/misp-warninglists/"
              "main/lists/{}/list.json")
# Only lists that describe "well-known benign", never "known malicious".
_MISP_LISTS = {
    "public-dns-v4":  ("ipv4",),
    "public-dns-v6":  ("ipv6",),
    "cisco_top1000":  ("domain", "url"),
    "cisco_top10k":   ("domain", "url"),
}
_TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# Enough to keep domain extraction sane when the IANA list cannot be fetched.
_TLD_FALLBACK = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "us", "uk",
    "de", "fr", "nl", "ru", "cn", "jp", "br", "in", "au", "ca", "ch", "it",
    "es", "se", "no", "pl", "cz", "tr", "kr", "tw", "hk", "sg", "th", "vn",
    "id", "my", "ph", "info", "biz", "name", "pro", "xyz", "top", "site",
    "online", "club", "shop", "app", "dev", "cloud", "tech", "space", "live",
    "icu", "cc", "tv", "me", "ws", "su", "ua", "ir", "il", "za", "mx", "ar",
    "cl", "pe", "nz", "be", "at", "dk", "fi", "gr", "pt", "ro", "hu", "bg",
    "sk", "lt", "lv", "ee", "by", "kz", "eu", "asia", "mobi", "onion",
}

_fp_state = {"loaded": False, "sets": {}, "tlds": None}


def _fp_fetch(url: str, cache_name: str) -> bytes:
    """Fetch with an on-disk cache. Network failure falls back to the cache;
    no cache returns b"" so the caller can no-op."""
    import urllib.request
    os.makedirs(_FP_CACHE, exist_ok=True)
    path = os.path.join(_FP_CACHE, cache_name)
    if os.path.exists(path):
        try:
            return open(path, "rb").read()
        except OSError:
            pass
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HydraPoT"})
        data = urllib.request.urlopen(req, timeout=30).read()
        with open(path, "wb") as f:
            f.write(data)
        return data
    except Exception:
        return b""


def load_fp_lists(force: bool = False) -> dict:
    """Load MISP warninglists + the IANA TLD list. Cached in-process."""
    if _fp_state["loaded"] and not force:
        return _fp_state
    sets = {}
    for name, types in _MISP_LISTS.items():
        raw = _fp_fetch(_MISP_BASE.format(name), f"{name}.json")
        if not raw:
            continue
        try:
            entries = json.loads(raw).get("list") or []
        except Exception:
            continue
        for t in types:
            sets.setdefault(t, set()).update(str(e).lower() for e in entries)
    raw = _fp_fetch(_TLD_URL, "tlds.txt")
    tlds = None
    if raw:
        try:
            tlds = {ln.strip().lower() for ln in raw.decode().splitlines()
                    if ln.strip() and not ln.startswith("#")}
        except Exception:
            tlds = None
    _fp_state.update({"loaded": True, "sets": sets, "tlds": tlds or set(_TLD_FALLBACK)})
    return _fp_state


def is_valid_tld(value: str) -> bool:
    """Does this hostname end in a real IANA-delegated TLD?

    Without this `rpc.idmapd`, `libnss.so`, `foo.bar` all register as domains.
    An empty/unavailable TLD set returns True so the filter never silently
    deletes every domain.
    """
    st = load_fp_lists()
    tlds = st.get("tlds")
    if not tlds:
        return True
    last = str(value).strip().lower().rstrip(".").split(".")[-1]
    return last in tlds


def is_known_benign(ioc_type: str, value: str) -> bool:
    """True when MISP's warninglists say this observable is well-known benign.

    Checks the registrable parent too, so `www.google.com` is caught by an
    entry for `google.com`.
    """
    st = load_fp_lists()
    pool = st["sets"].get(ioc_type)
    v = str(value).strip().lower()
    if ioc_type in ("domain", "url"):
        host = v.split("://")[-1].split("/")[0].split(":")[0].rstrip(".")
        pool = st["sets"].get("domain") or set()
        parts = host.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in pool:
                return True
        return host in pool
    if not pool:
        return False
    return v in pool


def extract_from_text(text: str, _depth: int = 0) -> list:
    """Return [(ioc_type, value), ...] found in a single string. Longest/most
    specific patterns first so a sha256 isn't also reported as md5, etc.

    Also matches defanged IOCs (hxxp://, 1[.]2[.]3[.]4, user[at]domain[.]com)
    and refangs them into the same bucket as a plain match, and re-scans a
    matched URL's percent-decoded form once for an IOC hiding in a
    redirector/proxy's query string (?url=http%3A%2F%2Fevil.com%2Fx.sh).
    `_depth` bounds that recursion since this processes attacker-controlled
    input — it must not be able to make this call itself unboundedly."""
    if not text or _depth > 2:
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

    def _consider_url(raw):
        """Reject a URL whose host is a fake/reserved-placeholder domain —
        the same is_valid_tld()/_DOMAIN_IGNORE checks the domain and email
        paths already apply. A bare-IP host has no TLD to check and is
        validated separately where ipv4/ipv6 IOCs are extracted, so it's
        exempt here."""
        v = raw.rstrip('.,);')
        host = (urlparse(v).hostname or "").lower().rstrip('.')
        if host and ':' not in host and not _RE["ipv4"].fullmatch(host):
            if host in _DOMAIN_IGNORE or host.endswith(_DOMAIN_IGNORE_SUFFIX):
                return None
            if not is_valid_tld(host):
                return None
        return v

    def _add_url(raw):
        v = _consider_url(raw)
        if not v:
            return
        add("url", v)
        decoded = unquote(v)
        if decoded == v:
            return
        # A redirector/proxy URL often hides its real target percent-encoded
        # in a query parameter (?url=http%3A%2F%2Fevil.com%2Fx.sh). The url
        # regex applied to the whole decoded string would just re-swallow it
        # as one big match (its char class doesn't stop at an embedded
        # "http://"), so instead look for a SECOND protocol marker further in
        # and isolate + extract just that nested URL on its own.
        starts = [m.start() for m in _PROTO_START.finditer(decoded)]
        for pos in starts[1:]:
            nested = _RE["url"].match(decoded, pos)
            if nested:
                for t, dv in extract_from_text(nested.group(0), _depth + 1):
                    add(t, dv)

    for m in _RE["url"].finditer(text):
        _add_url(m.group(0))
        url_spans.append((m.start(), m.end()))
    for m in _RE_DEFANGED["url"].finditer(text):
        _add_url(_refang(m.group(0)))
        url_spans.append((m.start(), m.end()))

    def _inside_url(pos):
        return any(a <= pos < b for a, b in url_spans)

    # Emails next (so an email's domain half isn't separately double-counted
    # as a bare "domain", same reasoning as URLs above)
    def _consider_email(raw):
        """Reject an email whose domain half isn't a real one — same checks
        the bare-domain path below already applies. Without this,
        `jdoe@machine.example`/`user@x.test` (RFC 5322's own illustrative
        examples, `.example`/`.test` are IANA-reserved, never delegated)
        extracted as real observables 63 times against a clean baseline."""
        v = raw.lower()
        domain = v.rsplit("@", 1)[-1]
        if domain in _DOMAIN_IGNORE or domain.endswith(_DOMAIN_IGNORE_SUFFIX):
            return None
        if not is_valid_tld(domain):
            return None
        return v

    email_spans = []
    for m in _RE["email"].finditer(text):
        email_spans.append((m.start(), m.end()))
        v = _consider_email(m.group(0))
        if v:
            add("email", v)
    for m in _RE_DEFANGED["email"].finditer(text):
        email_spans.append((m.start(), m.end()))
        v = _consider_email(_refang(m.group(0)))
        if v:
            add("email", v)

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
    for m in _RE_DEFANGED["ipv4"].finditer(text):
        v = _refang(m.group(0))
        if _is_public_ip(v):
            add("ipv4", v)
    for m in _RE["ipv6"].finditer(text):
        v = m.group(0)
        if _is_public_ip(v):
            add("ipv6", v)

    def _consider_domain(raw, pos):
        v = raw.lower().rstrip('.')
        if _inside_url(pos) or _inside_email(pos):
            return
        if v in _DOMAIN_IGNORE or v.endswith(_DOMAIN_IGNORE_SUFFIX):
            return
        # skip things that are actually IPs
        if _RE["ipv4"].fullmatch(v):
            return
        # The regex accepts any 2-24 char final label, so `rpc.idmapd`,
        # `libnss.so` and `foo.bar` all look like domains. Require a real
        # IANA-delegated TLD. `rpc.idmapd` alone was 131 false observations.
        if not is_valid_tld(v):
            return
        # skip filenames whose "TLD" is really a file/script/unit extension
        if v.rsplit(".", 1)[-1] in _FILE_EXT_TLDS:
            return
        add("domain", v)

    for m in _RE["domain"].finditer(text):
        _consider_domain(m.group(0), m.start())
    for m in _RE_DEFANGED["domain"].finditer(text):
        _consider_domain(_refang(m.group(0)), m.start())

    return found


class IOCStore:
    """Aggregates indicators with metadata across many events."""

    def __init__(self):
        # key=(type,value) -> record
        self._iocs = {}

    def add(self, ioc_type, value, *, session_id=None, src_ip=None,
            timestamp=None, fi=0, context=None, techniques=None):
        key = (ioc_type, value)
        rec = self._iocs.get(key)
        if rec is None:
            rec = {
                "type": ioc_type, "value": value, "count": 0,
                "first_seen": timestamp, "last_seen": timestamp,
                "sessions": set(), "src_ips": set(), "max_fi": 0,
                "sample_context": context,
                # ATT&CK techniques of the commands this IOC appeared in.
                # Carried so to_stix() can emit attack-pattern objects and
                # indicator->attack-pattern relationships; without them a STIX
                # bundle is a flat list and a visualizer draws 0 edges.
                "techniques": set(),
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
        if techniques:
            rec["techniques"].update(t for t in techniques if t)

    def records(self):
        out = []
        for rec in self._iocs.values():
            r = dict(rec)
            r["sessions"] = sorted(r["sessions"])
            r["src_ips"] = sorted(r["src_ips"])
            r["techniques"] = sorted(r.get("techniques") or [])
            r["session_count"] = len(r["sessions"])
            # Flag, don't drop. A suppressed IOC is still something the
            # honeypot genuinely saw; hiding it from the table is a display
            # decision, and silently deleting it would make the totals lie.
            try:
                r["benign"] = is_known_benign(r["type"], r["value"])
            except Exception:
                r["benign"] = False
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
        # Reuse whatever the row already carries; fall back to tagging live.
        techs = r.get("technique_ids")
        if not techs:
            tid = r.get("technique_id")
            techs = [tid] if tid else []
        if not techs and cmd:
            try:
                from threat_intel.mitre_mapper import tag_all
                techs = [x["technique_id"] for x in tag_all(cmd)]
            except Exception:
                techs = []

        # the attacker's own source IP is itself an IOC
        if ip and _is_public_ip(ip):
            store.add("ipv4" if ":" not in ip else "ipv6", ip,
                      session_id=sid, src_ip=ip, timestamp=ts, fi=fi,
                      context="attacker source IP", techniques=techs)

        for t, v in extract_from_text(cmd):
            store.add(t, v, session_id=sid, src_ip=ip, timestamp=ts, fi=fi,
                      context=cmd[:160], techniques=techs)
        for t, v in extract_from_text(resp):
            store.add(t, v, session_id=sid, src_ip=ip, timestamp=ts, fi=fi,
                      context=f"(in response) {cmd[:120]}", techniques=techs)

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
def _stix_str(v) -> str:
    """Escape a value for a STIX pattern string literal.

    STIX patterning quotes literals in single quotes, so a backslash and a
    single quote both have to be escaped — backslash FIRST, or the escape
    character introduced for the quote gets escaped again. Only `url` and
    `email` did this before, which left credentials like
    `root:asdfghjkl;'` producing a pattern with unbalanced quotes.
    """
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def _stix_ts(v) -> str:
    """Normalise a timestamp to the RFC3339 form STIX 2.1 requires.

    IOC records carry `first_seen` in SQLite's "YYYY-MM-DD HH:MM:SS" form.
    Passing that straight into `valid_from` made every indicator invalid —
    stix2.parse() rejected 14,017 of 14,017 objects, so the bundle would not
    open in a STIX visualizer at all. Anything unparseable falls back to the
    caller's `now`, which is always well-formed.
    """
    from datetime import datetime, timezone
    if not v:
        return ""
    if isinstance(v, datetime):
        dt = v
    else:
        text = str(v).strip().replace("Z", "").replace("T", " ")
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


_STIX_PATTERN = {
    "ipv4":   lambda v: f"[ipv4-addr:value = '{_stix_str(v)}']",
    "ipv6":   lambda v: f"[ipv6-addr:value = '{_stix_str(v)}']",
    "url":    lambda v: f"[url:value = '{_stix_str(v)}']",
    "domain": lambda v: f"[domain-name:value = '{_stix_str(v)}']",
    "md5":    lambda v: f"[file:hashes.'MD5' = '{_stix_str(v)}']",
    "sha1":   lambda v: f"[file:hashes.'SHA-1' = '{_stix_str(v)}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{_stix_str(v)}']",
    "email":  lambda v: f"[email-addr:value = '{_stix_str(v)}']",
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
        pattern = patt_fn(v) if patt_fn else f"[x-honeypot:{t} = '{_stix_str(v)}']"
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
            "valid_from": _stix_ts(r.get("first_seen")) or now,
            "labels": [f"honeypot-observed", f"ioc-{t}"],
        })
    # ── attack-pattern objects + relationships ───────────────────────────
    # A bundle of indicators alone has no edges, so a STIX visualizer renders
    # it as an unconnected dot cloud ("Relationships: 0"). Every IOC here was
    # observed in a command HydraPoT had already mapped to an ATT&CK technique,
    # so emitting those techniques as attack-pattern SDOs and linking each
    # indicator to them with an `indicates` SRO turns the same data into a
    # graph: C2 address -> Ingress Tool Transfer <- payload URL.
    #
    # A deterministic UUIDv5 keeps one attack-pattern per technique across
    # re-exports, so bundles merged in a TIP do not accumulate duplicates.
    _AP_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
    ap_ids, ap_objs, rels = {}, [], []
    try:
        from threat_intel.mitre_mapper import _load_catalog
        catalog = _load_catalog()
    except Exception:
        catalog = {}

    for ind, r in zip(objects, records):
        for tid in (r.get("techniques") or []):
            if tid not in ap_ids:
                meta = catalog.get(tid) or {}
                apid = f"attack-pattern--{uuid.uuid5(_AP_NS, tid)}"
                ap_ids[tid] = apid
                ap_objs.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": apid,
                    "created": now,
                    "modified": now,
                    "name": meta.get("name") or tid,
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": meta.get("url")
                               or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                    }],
                })
            rels.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind["id"],
                "target_ref": ap_ids[tid],
            })

    # ── identity: who observed all this ──────────────────────────────────
    # Every SDO gets created_by_ref, which is both correct STIX provenance and
    # the thing that stops a merged bundle losing track of its source.
    ident_id = f"identity--{uuid.uuid5(_AP_NS, 'hydrapot-sensor')}"
    identity = {
        "type": "identity", "spec_version": "2.1", "id": ident_id,
        "created": now, "modified": now,
        "name": "HydraPoT SSH honeypot",
        "identity_class": "system",
        "description": "Multi-agent SSH honeypot; indicators are observations "
                       "of attacker behaviour, not curated threat intel.",
    }
    for o in objects + ap_objs:
        o["created_by_ref"] = ident_id

    # ── malware: payload files seen being fetched ────────────────────────
    # Real filenames pulled out of observed download URLs. `is_family` is
    # false and malware_types is "unknown" on purpose: we saw the honeypot
    # asked to download these, we did not execute or classify them, so naming
    # a family would be an assertion the data does not support.
    # Two ways a URL names a payload, because extension alone misses the most
    # important one: the top download in this corpus is `/.x15cache`, which has
    # no extension at all.
    #   (a) the host is a BARE IP — legitimate sites use domain names, droppers
    #       hardcode addresses, so any file fetched from a raw IP is a payload;
    #   (b) any host, but the filename carries a payload extension
    #       (covers y2khom3.evonet.ro/unixcod.tar.gz).
    # Directory URLs and well-known sites (nmap.org, schema.org) fall out.
    _URL_PARTS = re.compile(r"^\w+://([^/]+)(/.*)?$", re.I)
    _BARE_IP_HOST = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")
    _PAYLOAD_EXT = re.compile(
        r"\.(?:sh|arm[0-9]?|x86(?:_64)?|mips|mpsl|ppc|m68k|arc|bin|elf|"
        r"tar|gz|tgz|txt|py|pl)$", re.I)

    def _payload_name(url: str):
        m = _URL_PARTS.match(str(url or ""))
        if not m:
            return None
        host, path = m.group(1), (m.group(2) or "")
        name = path.rstrip("/").rsplit("/", 1)[-1] if path.strip("/") else ""
        if not name or len(name) > 64:
            return None
        if _BARE_IP_HOST.match(host) or _PAYLOAD_EXT.search(name):
            return name
        return None
    mal_ids, mal_objs = {}, []
    for ind, r in zip(objects, records):
        if r.get("type") != "url":
            continue
        fname = _payload_name(r.get("value"))
        if not fname:
            continue
        if fname not in mal_ids:
            mid = f"malware--{uuid.uuid5(_AP_NS, 'payload:' + fname)}"
            mal_ids[fname] = mid
            mal_objs.append({
                "type": "malware", "spec_version": "2.1", "id": mid,
                "created": now, "modified": now,
                "created_by_ref": ident_id,
                "name": fname,
                "is_family": False,
                "malware_types": ["unknown"],
                "description": f"Payload file requested from attacker-controlled "
                               f"infrastructure and observed by the honeypot. "
                               f"Not executed or classified.",
            })
        rels.append({
            "type": "relationship", "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now, "modified": now, "created_by_ref": ident_id,
            "relationship_type": "indicates",
            "source_ref": ind["id"], "target_ref": mal_ids[fname],
        })
        # the payload is delivered by whatever techniques that command used
        for tid in (r.get("techniques") or []):
            if tid in ap_ids:
                rels.append({
                    "type": "relationship", "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now, "modified": now, "created_by_ref": ident_id,
                    "relationship_type": "uses",
                    "source_ref": mal_ids[fname], "target_ref": ap_ids[tid],
                })

    objects = [identity] + objects + ap_objs + mal_objs + rels
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    return path
