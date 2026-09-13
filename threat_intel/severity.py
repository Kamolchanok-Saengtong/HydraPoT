"""
threat_intel/severity.py — SOC severity: how bad is this behaviour?

The layer after Detection:

    Aggregation -> Correlation -> Detection -> SEVERITY -> UI

Two entry points, one ruleset:
  evaluate()          rates a SESSION from its own MITRE chain
  rate_relationship() rates a CORRELATION RELATIONSHIP from the shared
                      sequence its members have in common
  rate_detections()   annotates a whole detect() result

Both inputs are the ATT&CK footprint of a command chain, which is exactly what
session_severity.yml was written against -- so the relationship path reuses the
rules rather than introducing a second, drifting ruleset.

Pure rule evaluation: no database, no MITRE tagging, no I/O beyond reading
the ruleset once. Callers hand it a facts dict (threat_intel/aggregator.py
builds one from the session's re-tagged MITRE chain) and get back a severity
plus the rules that produced it. That keeps this module trivially testable
and means the dependency runs one way only -- aggregator -> severity, never
back.

Rules live in threat_intel/rules/session_severity.yml. That file is the one
place severity is defined; adding or re-scoping a rule never touches this
code. Note the Sigma loader in mitre_mapper.py walks
threat_intel/rules/local_custom/ specifically, so a sibling ruleset here is
not picked up as a malformed Sigma rule.

Severity is deliberately NOT derived from FI -- see the header of
session_severity.yml. FI decides which agent answers a command; it is not a
statement about attacker intent.
"""
import os

import yaml

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "rules", "session_severity.yml")

# Ascending. A session's severity is the highest severity that fired.
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Every condition severity.py knows how to evaluate. A rule using anything
# else is skipped loudly at load time rather than silently never firing --
# a typo'd condition that quietly matches nothing is the worst failure mode
# for a detection rule.
_CONDITIONS = {"any_techniques", "all_techniques", "any_tactics",
               "min_distinct_tactics", "min_commands_per_minute"}

# Keyed BY PATH — same fix as correlation.py and detection.py. A single global
# slot made the `path` argument silently ignored once any ruleset had loaded,
# so a caller asking for a different file got the first one back with no error.
_rules = {}             # path -> [rule, ...]
_load_errors = {}       # path -> [(id, message), ...]


def load_rules(path: str = RULES_PATH, force: bool = False) -> list:
    """Parse and validate session_severity.yml. Cached after the first call.

    A malformed rule is skipped with a warning rather than breaking the
    dashboard, and the reason is kept in load_errors() -- same philosophy as
    mitre_mapper.load_rules().
    """
    if path in _rules and not force:
        return _rules[path]

    rules, errors = [], []
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[severity] cannot read {path}: {e}")
        _rules[path] = []
        _load_errors[path] = [(os.path.basename(path), str(e))]
        return _rules[path]

    for raw in (doc.get("rules") or []):
        rid = raw.get("id", "<no id>")
        try:
            sev = raw.get("severity")
            if sev not in _SEVERITY_RANK:
                raise ValueError(
                    f"severity must be one of {list(SEVERITY_ORDER)}, got {sev!r}")
            when = raw.get("when") or {}
            if not when:
                raise ValueError("rule has no `when` conditions")
            unknown = set(when) - _CONDITIONS
            if unknown:
                raise ValueError(f"unknown condition(s): {sorted(unknown)}")
            rules.append({
                "id": rid,
                "title": raw.get("title", rid),
                "severity": sev,
                "description": (raw.get("description") or "").strip(),
                "when": when,
            })
        except Exception as e:
            errors.append((rid, str(e)))
            print(f"[severity] skipping rule {rid}: {e}")

    seen = set()
    for r in rules:
        if r["id"] in seen:
            errors.append((r["id"], "duplicate rule id"))
            print(f"[severity] WARNING: duplicate rule id {r['id']}")
        seen.add(r["id"])

    _rules[path], _load_errors[path] = rules, errors
    return rules


def load_errors(path: str = RULES_PATH) -> list:
    """[(rule_id, message)] from the last load of `path` — for the rule
    validator."""
    load_rules(path)
    return _load_errors.get(path, [])


def _fires(when: dict, technique_ids: set, tactics: set,
           commands_per_minute) -> bool:
    """Every condition in `when` must hold (AND)."""
    if "any_techniques" in when:
        if not technique_ids & set(when["any_techniques"]):
            return False
    if "all_techniques" in when:
        if not set(when["all_techniques"]) <= technique_ids:
            return False
    if "any_tactics" in when:
        if not tactics & set(when["any_tactics"]):
            return False
    if "min_distinct_tactics" in when:
        if len(tactics) < when["min_distinct_tactics"]:
            return False
    if "min_commands_per_minute" in when:
        # None = the session was too short to have a meaningful rate (a single
        # command, or every command inside the same second). Pacing can't be
        # judged from an instant, so the rule is skipped rather than guessed.
        if commands_per_minute is None:
            return False
        if commands_per_minute < when["min_commands_per_minute"]:
            return False
    return True


def rate_relationship(relationship: dict, path: str = RULES_PATH) -> dict:
    """Severity for ONE correlation relationship.

    Rates the BEHAVIOUR THE MEMBERS SHARE -- the relationship's `evidence`
    block, which carries the technique IDs and tactics of the shared command
    sequence. That is the same kind of input this ruleset was written for (a
    command chain's ATT&CK footprint), so no new rules are needed and none are
    invented here.

    Deliberately NOT folded in: how many sessions, sources or sensors the
    relationship spans. Those are real and important, but combining "what they
    did" with "how widely" produces a composite number nobody can argue with --
    the risk score this architecture keeps refusing to build. Spread is already
    handled where it belongs, by detection rules like cross-source-repetition
    deciding what gets surfaced. Severity says how bad the behaviour is;
    detection says whether to look. The UI shows both.

    Returns {"severity": None, "matched": []} when the relationship has no
    evidence -- indicator and source-address links share a value, not a command
    sequence, so a behaviour ruleset has nothing to read. That is reported as
    UNRATED rather than guessed at.
    """
    ev = (relationship or {}).get("evidence") or {}
    if not ev:
        return {"severity": None, "matched": []}
    return evaluate(technique_ids=ev.get("technique_ids") or (),
                    tactics=ev.get("tactics") or (), path=path)


def rate_detections(detect_result: dict, path: str = RULES_PATH) -> dict:
    """Annotate detection output with severity. Detection -> Severity -> UI.

    A separate pass rather than something detect() does, because the two
    answer different questions and must stay independently auditable:
    detection decides what an analyst SEES, severity decides how bad it is.
    Merging them would make a suppressed-but-critical finding impossible to
    reason about.

    Returns a NEW result; the input and every relationship inside it are left
    untouched, so correlation's output still reaches the UI byte-for-byte.
    Every bucket is rated, not just the surfaced one -- a suppressed
    relationship that turns out to be critical is exactly the thing a reviewer
    needs to be able to find.
    """
    out = dict(detect_result or {})
    for bucket in ("detections", "suppressed", "unmatched"):
        rated = []
        for verdict in out.get(bucket) or []:
            v = dict(verdict)
            r = rate_relationship(v.get("relationship"), path=path)
            v["severity"] = r["severity"]
            v["severity_rules"] = r["matched"]
            rated.append(v)
        out[bucket] = rated
    return out


def evaluate(technique_ids=(), tactics=(), commands_per_minute=None,
             path: str = RULES_PATH) -> dict:
    """-> {"severity": str|None, "matched": [rule, ...]}

    `severity` is the highest severity among fired rules, or None when nothing
    fired (a session of commands the ruleset can't tag at all). `matched` is
    every rule that fired, highest severity first -- that list IS the evidence
    the UI shows, so an analyst can always see why a session was rated the way
    it was instead of being handed an opaque number.
    """
    technique_ids = set(technique_ids or ())
    tactics = set(tactics or ())

    matched = [r for r in load_rules(path)
               if _fires(r["when"], technique_ids, tactics, commands_per_minute)]
    matched.sort(key=lambda r: -_SEVERITY_RANK[r["severity"]])

    return {
        "severity": matched[0]["severity"] if matched else None,
        "matched": matched,
    }
