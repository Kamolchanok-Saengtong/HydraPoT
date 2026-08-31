"""
threat_intel/sigma_import.py — import ready-made SigmaHQ rules and run them.

Nothing here is authored by HydraPoT. Rules are downloaded from the SigmaHQ
community repository, parsed as-is, and their MITRE ATT&CK tags are read
straight out of each file's `tags:` block.

Why this exists
---------------
threat_intel/rules/ holds HydraPoT's own rules, which match Cowrie command
TEXT. SigmaHQ rules match STRUCTURED FIELDS instead (`logtype`, `CommandLine`,
`Image`), so they cannot be dropped into that engine unchanged. This module is
the adapter: it parses arbitrary Sigma field names and evaluates them against a
plain dict event.

What SigmaHQ actually ships for honeypots
-----------------------------------------
There is no `rules/application/honeypot` directory, and no Cowrie, Dionaea or
Honeytrap rules. The honeypot rules live in `rules/application/opencanary`
(24 files, verified 2026-08-26). They match on OpenCanary's numeric event
codes, e.g.

    detection:
      selection:
        logtype: 4002        # SSH login attempt
      condition: selection
    tags: [attack.t1021, attack.t1078, attack.t1133]

So to use them, a HydraPoT event must be projected into an OpenCanary-shaped
dict first — see `project_auth_event()`. `rules/linux/process_creation` is also
importable and matches on CommandLine/Image.

Usage
-----
    python threat_intel/sigma_import.py --sync          # download + cache
    python threat_intel/sigma_import.py --list          # rules + their techniques
    python threat_intel/sigma_import.py --fields        # what fields rules need
    python threat_intel/sigma_import.py --demo          # run against real DB rows
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from threat_intel.mitre_mapper import _compile_condition, RuleError  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))

# ── two-tier rule layout ─────────────────────────────────────────────────────
#   rules/upstream/      Global Community Tier - SigmaHQ, authored by the
#                        community, refreshed with --sync. Never hand-edited.
#   rules/local_custom/  Local Threat Intel Tier - HydraPoT's own rules, in the
#                        same Sigma schema, covering honeypot command text that
#                        SigmaHQ does not (ls, top, nproc, chmod ...).
UPSTREAM_DIR = os.path.join(_HERE, "rules", "upstream")
LOCAL_DIR    = os.path.join(_HERE, "rules", "local_custom")
CACHE = UPSTREAM_DIR                      # back-compat alias
API = "https://api.github.com/repos/SigmaHQ/sigma/contents/"

# SigmaHQ directories worth importing for a honeypot. Add more freely.
SOURCES = {
    "opencanary":         "rules/application/opencanary",
    "linux_process":      "rules/linux/process_creation",
    "linux_auditd":       "rules/linux/auditd",
    "linux_builtin":      "rules/linux/builtin",
    "linux_file_event":   "rules/linux/file_event",
    "linux_network":      "rules/linux/network_connection",
}

# ── MITRE tag extraction ─────────────────────────────────────────────────────
# Sigma encodes techniques as `attack.t1021.004`. Sub-techniques keep the dot,
# so a plain .upper() would give T1021.004 correctly, but tactics
# (`attack.lateral-movement`) and groups (`attack.g0016`) must be dropped.
_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
_TACTIC = re.compile(r"^attack\.([a-z][a-z-]+)$", re.I)


def extract_techniques(tags) -> list:
    """['attack.t1021.004', 'attack.lateral-movement'] -> ['T1021.004']"""
    out = []
    for t in tags or []:
        m = _TECH.match(str(t).strip())
        if m:
            tid = m.group(1).upper()
            if tid not in out:
                out.append(tid)
    return out


def extract_tactics(tags) -> list:
    """['attack.lateral-movement'] -> ['lateral-movement'] (technique tags skipped)."""
    out = []
    for t in tags or []:
        s = str(t).strip()
        if _TECH.match(s):
            continue
        m = _TACTIC.match(s)
        if m and m.group(1).lower() not in out:
            out.append(m.group(1).lower())
    return out


# ── detection compilation (generic fields, not just command text) ────────────
_MODS = ("contains", "startswith", "endswith", "re", "all", "cased",
         "exists", "lt", "lte", "gt", "gte", "cidr")


def _values_of(event, field):
    """Field lookup with dotted-path support: `logdata.USERNAME`."""
    cur = event
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return []
    return cur if isinstance(cur, list) else [cur]


def _compile_matcher(field_expr: str, values):
    parts = field_expr.split("|")
    field, mods = parts[0], [m.lower() for m in parts[1:]]
    for m in mods:
        if m not in _MODS:
            raise RuleError(f"unsupported modifier {m!r} in {field_expr!r}")

    if not isinstance(values, list):
        values = [values]
    require_all = "all" in mods
    cased = "cased" in mods

    if "cidr" in mods:
        import ipaddress
        nets = []
        for v in values:
            try:
                nets.append(ipaddress.ip_network(str(v), strict=False))
            except ValueError:
                pass

        def predicate(ev):
            for g in _values_of(ev, field):
                try:
                    ip = ipaddress.ip_address(str(g))
                except ValueError:
                    continue
                if any(ip in n for n in nets):
                    return True
            return False
        return predicate

    if "exists" in mods:
        want = bool(values[0]) if values else True
        return lambda ev: (len(_values_of(ev, field)) > 0) is want

    if "re" in mods:
        flags = 0 if cased else re.I
        pats = [re.compile(str(v), flags) for v in values]
        test = lambda s, p: p.search(s) is not None
    elif {"lt", "lte", "gt", "gte"} & set(mods):
        op = next(m for m in ("lt", "lte", "gt", "gte") if m in mods)
        nums = [float(v) for v in values]
        import operator
        fn = {"lt": operator.lt, "lte": operator.le,
              "gt": operator.gt, "gte": operator.ge}[op]

        def predicate(ev):
            got = _values_of(ev, field)
            return any(_isnum(g) and any(fn(float(g), n) for n in nums) for g in got)
        return predicate
    elif "contains" in mods:
        pats = [str(v) if cased else str(v).lower() for v in values]
        test = lambda s, p: p in (s if cased else s.lower())
    elif "startswith" in mods:
        pats = [str(v) if cased else str(v).lower() for v in values]
        test = lambda s, p: (s if cased else s.lower()).startswith(p)
    elif "endswith" in mods:
        pats = [str(v) if cased else str(v).lower() for v in values]
        test = lambda s, p: (s if cased else s.lower()).endswith(p)
    else:
        # bare value: exact match. Sigma compares numbers and strings loosely,
        # so `logtype: 4002` must match both 4002 and "4002".
        pats = values
        def test(s, p):
            if p is None:
                return s in ("", None)
            if _isnum(p) and _isnum(s):
                return float(s) == float(p)
            return str(s).lower() == str(p).lower()

    def predicate(ev):
        got = _values_of(ev, field)
        if not got:
            return False
        agg = all if require_all else any
        return agg(any(test(g, p) for g in (str(x) if not _isnum(x) else x for x in got))
                   for p in pats)
    return predicate


def _isnum(v):
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


def _flatten_values(ev):
    """Every scalar in the event, for keyword search."""
    out = []
    stack = [ev]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
        elif cur is not None:
            out.append(str(cur))
    return out


def _compile_selection(name, block):
    if isinstance(block, list):
        # A list of MAPS is an OR of selections. A list of bare SCALARS is a
        # Sigma keyword search: match the string anywhere in the event. SigmaHQ
        # uses this in `keywords:` blocks (lnx_buffer_overflows and friends).
        if block and all(isinstance(b, dict) for b in block):
            subs = [_compile_selection(name, b) for b in block]
            return lambda ev: any(s(ev) for s in subs)
        needles = [str(b).lower() for b in block]
        return lambda ev: any(n in hay.lower()
                              for hay in _flatten_values(ev) for n in needles)
    if isinstance(block, str):           # single bare keyword
        needle = block.lower()
        return lambda ev: any(needle in hay.lower() for hay in _flatten_values(ev))
    if not isinstance(block, dict):
        raise RuleError(f"selection {name!r} must be a mapping, list or string")
    preds = [_compile_matcher(f, v) for f, v in block.items()]
    return lambda ev: all(p(ev) for p in preds)


class SigmaRule:
    """One imported SigmaHQ rule. Authored by the SigmaHQ community, not us."""

    def __init__(self, doc: dict, source: str, path: str):
        self.doc, self.source, self.path = doc, source, path
        self.id = doc.get("id", "")
        self.title = doc.get("title", path)
        self.level = doc.get("level", "")
        self.status = doc.get("status", "")
        self.author = doc.get("author", "")
        ls = doc.get("logsource") or {}
        self.product = ls.get("product", "")
        self.category = ls.get("category", "")
        self.service = ls.get("service", "")
        self.tags = doc.get("tags") or []
        self.techniques = extract_techniques(self.tags)
        self.tactics = extract_tactics(self.tags)

        det = doc.get("detection") or {}
        cond = det.get("condition")
        sels = {k: _compile_selection(k, v) for k, v in det.items() if k != "condition"}
        if isinstance(cond, list):       # multiple conditions = OR
            subs = [_compile_condition(str(c), sels) for c in cond]
            self._match = lambda ev: any(s(ev) for s in subs)
        else:
            self._match = _compile_condition(str(cond), sels)
        self.fields = sorted({f.split("|")[0]
                              for k, v in det.items() if k != "condition"
                              for f in (v if isinstance(v, dict) else {})})

    def matches(self, event: dict) -> bool:
        try:
            return bool(self._match(event))
        except Exception:
            return False

    def __repr__(self):
        return f"<SigmaRule {self.title!r} {self.techniques}>"


# ── fetching ─────────────────────────────────────────────────────────────────
def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "HydraPoT-sigma-import"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def sync(sources: dict = None, verbose=True) -> dict:
    """Download every .yml from each SigmaHQ directory into .sigma_cache/."""
    sources = sources or SOURCES
    counts = {}
    for name, path in sources.items():
        dest = os.path.join(UPSTREAM_DIR, name)
        os.makedirs(dest, exist_ok=True)
        listing = json.loads(_get(API + path))
        n = 0
        for entry in listing:
            if entry.get("type") != "file" or not entry["name"].endswith((".yml", ".yaml")):
                continue
            out = os.path.join(dest, entry["name"])
            if not os.path.exists(out):
                open(out, "wb").write(_get(entry["download_url"]))
            n += 1
        counts[name] = n
        if verbose:
            print(f"[sigma] {name:16} {n:>4} rules -> {dest}")
    return counts


def _load_dir(root: str, tier: str) -> tuple:
    """Recursively load every Sigma YAML under `root`."""
    rules, errors = [], []
    if not os.path.isdir(root):
        return rules, errors
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                for doc in yaml.safe_load_all(open(path, encoding="utf-8")):
                    if isinstance(doc, dict) and doc.get("detection"):
                        r = SigmaRule(doc, tier, rel)
                        r.tier = tier
                        rules.append(r)
            except Exception as e:
                errors.append((f"{tier}/{rel}", str(e)))
    return rules, errors


_cache = {}


def load(sources=None, force=False) -> tuple:
    """Upstream (SigmaHQ) rules only. -> (rules, errors)"""
    if "upstream" in _cache and not force:
        return _cache["upstream"]
    _cache["upstream"] = _load_dir(UPSTREAM_DIR, "upstream")
    return _cache["upstream"]


def load_local(force=False) -> tuple:
    """Local custom rules, parsed with THIS parser (generic Sigma fields).

    Note these same files are also loaded by mitre_mapper with its own
    command-text engine; this loader exists so the audit surface is uniform -
    every rule in the system can be enumerated through one code path.
    """
    if "local" in _cache and not force:
        return _cache["local"]
    _cache["local"] = _load_dir(LOCAL_DIR, "local_custom")
    return _cache["local"]


def load_all(force=False) -> tuple:
    """Both tiers merged, upstream first. -> (rules, errors)"""
    ur, ue = load(force=force)
    lr, le = load_local(force=force)
    return ur + lr, ue + le


# ── projecting HydraPoT events into the shape these rules expect ─────────────
# OpenCanary numeric event codes, from opencanary/logger.py. Only the ones a
# HydraPoT SSH honeypot can genuinely produce are listed; do not invent others.
OPENCANARY_LOGTYPE = {
    "ssh.new_connection": 4001,
    "ssh.login_attempt":  4002,
}


def project_auth_event(row: dict) -> dict:
    """HydraPoT `auth` table row -> OpenCanary-shaped event."""
    is_login = (row.get("auth_type") or "").lower() in ("password", "publickey", "keyboard-interactive")
    return {
        "logtype": OPENCANARY_LOGTYPE["ssh.login_attempt" if is_login else "ssh.new_connection"],
        "src_host": row.get("src_ip"),
        "src_port": row.get("src_port"),
        "logdata": {"USERNAME": row.get("username"), "PASSWORD": row.get("password")},
    }


def project_command_event(row: dict) -> dict:
    """HydraPoT `sessions` row -> process_creation-shaped event."""
    cmd = row.get("cmd") or ""
    first = cmd.strip().split()[0] if cmd.strip() else ""
    return {"CommandLine": cmd,
            "Image": first if first.startswith("/") else f"/usr/bin/{first}",
            "User": "root", "LogonId": row.get("session_id", "")}


def classify_command(cmd: str, rules=None) -> list:
    """Run a raw command string through the UPSTREAM (SigmaHQ) rules.

    Returns [{technique_id, rule_id, rule_title, level, source, tactics}, ...],
    one entry per distinct technique, or [] when nothing matches. This is the
    first stage of the priority pipeline in mitre_mapper.tag().
    """
    hits = classify(project_command_event({"cmd": cmd}), rules)
    out, seen = [], set()
    for h in hits:
        for tid in h["techniques"]:
            if tid in seen:
                continue
            seen.add(tid)
            out.append({"technique_id": tid, "rule_id": h["rule_id"],
                        "rule_title": h["title"], "level": h["level"],
                        "source": "sigmahq", "tactics": h["tactics"]})
    return out


def classify(event: dict, rules=None) -> list:
    """Every imported rule that fires, with the techniques it carries."""
    rules = rules if rules is not None else load()[0]
    hits = []
    for r in rules:
        if r.matches(event):
            hits.append({"rule_id": r.id, "title": r.title, "source": r.source,
                         "level": r.level, "techniques": r.techniques,
                         "tactics": r.tactics})
    return hits


# ── CLI ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Import SigmaHQ rules into HydraPoT")
    ap.add_argument("--sync", action="store_true", help="download rules from SigmaHQ")
    ap.add_argument("--list", action="store_true", help="list rules + techniques")
    ap.add_argument("--fields", action="store_true", help="which fields the rules need")
    ap.add_argument("--demo", action="store_true", help="run against real DB rows")
    a = ap.parse_args()

    if a.sync:
        sync()
        return

    rules, errors = load()
    if not rules:
        sys.exit("no cached rules - run with --sync first")
    print(f"[sigma] loaded {len(rules)} rules, {len(errors)} failed to parse")
    for p, e in errors[:5]:
        print(f"        ERROR {p}: {e[:90]}")

    if a.list:
        by = {}
        for r in rules:
            by.setdefault(r.source, []).append(r)
        for src, rs in by.items():
            print(f"\n=== {src}  ({len(rs)} rules) ===")
            for r in rs:
                print(f"  {r.level:9} {','.join(r.techniques) or '(no technique tag)':22} {r.title[:58]}")
        techs = sorted({t for r in rules for t in r.techniques})
        print(f"\ntotal distinct MITRE techniques available: {len(techs)}")
        print("  " + " ".join(techs))

    if a.fields:
        import collections
        c = collections.Counter(f for r in rules for f in r.fields)
        print("\nfields these rules match on (you must supply them):")
        for f, n in c.most_common():
            print(f"   {f:28} {n} rules")

    if a.demo:
        import sqlite3
        db = os.path.join(os.path.dirname(_HERE), "data/logs/hydrapot.db")
        con = sqlite3.connect(db); con.row_factory = sqlite3.Row
        print("\n--- auth events -> opencanary rules ---")
        for row in con.execute("select * from auth limit 5"):
            ev = project_auth_event(dict(row))
            hits = classify(ev, rules)
            techs = sorted({t for h in hits for t in h["techniques"]})
            print(f"  {row['username']!r:14} {row['auth_type']!r:12} logtype={ev['logtype']} -> {techs or '(none)'}")
        print("\n--- command events -> linux process_creation rules ---")
        for row in con.execute("select * from sessions where cmd is not null limit 8"):
            ev = project_command_event(dict(row))
            hits = classify(ev, rules)
            techs = sorted({t for h in hits for t in h["techniques"]})
            if techs:
                print(f"  {row['cmd'][:56]:58} -> {techs}")


if __name__ == "__main__":
    main()
