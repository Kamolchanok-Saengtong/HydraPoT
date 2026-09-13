"""
threat_intel/detection.py — decides which correlation relationships surface.

    Aggregation -> Correlation -> DETECTION -> (later) Severity -> UI

Correlation establishes that observations are related and refuses to say
whether that matters. Detection is where "does this matter" is allowed to be
asked -- and the answer is policy, so it lives in a ruleset a human wrote, not
in this code. This module only evaluates rules; it knows nothing about what
any particular relationship means.

The layer boundaries this file exists to keep:

  * Correlation is READ-ONLY here. Relationships arrive as plain dicts and are
    never mutated, re-derived, or re-grouped. Detection adds a verdict ABOUT a
    relationship; the relationship itself comes back byte-for-byte.
  * Detection does NOT assign severity. severity.py answers "how bad", against
    per-session MITRE facts, and is deliberately not wired. Ranking a surfaced
    relationship by danger here would duplicate that layer and put two
    competing answers in the UI.
  * NOTHING IS DISCARDED. Every relationship handed in comes back in exactly
    one of three buckets -- detections / suppressed / unmatched -- each with
    the rule and reason that put it there. A detection layer that drops
    findings silently cannot be audited, and the analyst can never tell a
    deliberate filter from a bug.
  * NO SCORES. No rule yields a number or a weight. Surfaced relationships are
    ordered by where their rule sits in the YAML file: a human-authored reading
    order that is re-argued by moving a rule, not a computed risk ranking.
  * FI IS NOT AN INPUT. Not as a rank, not as a filter. FI decides which agent
    answers a command; it is an operational/routing metric and says nothing
    about attacker intent.

Rules live in threat_intel/rules/detection_rules.yml. Note the Sigma loader in
mitre_mapper.py walks threat_intel/rules/local_custom/ specifically, so a
sibling ruleset here is not picked up as a malformed Sigma rule.
"""
import os

import yaml

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "rules", "detection_rules.yml")

# Every condition detection.py knows how to evaluate. A rule using anything
# else is skipped LOUDLY at load time: a typo'd condition that quietly matches
# nothing looks exactly like "there was nothing to detect", which is the worst
# possible failure mode for a detection rule.
_STRUCTURAL_CONDITIONS = {"link_type_in", "min_members", "max_members",
                          "min_distinct_sources", "max_distinct_sources",
                          "min_distinct_scopes"}

# Conditions that read correlation's `evidence` block -- what the related
# observations actually SHARE, rather than how many of them there are. Only
# strategies with an evidence builder publish it (today: command sequences).
#
# These all FAIL CLOSED when evidence is absent, including the max_* ones.
# That is the whole reason they are tracked as a separate set: `max_distinct_
# commands: 1` read against a missing block would compare against zero and
# match every indicator and address relationship in the window, suppressing
# findings it knows nothing about. Absent evidence means UNKNOWN, never zero.
_EVIDENCE_CONDITIONS = {"min_sequence_length", "min_distinct_commands",
                        "max_distinct_commands", "min_distinct_tactics",
                        "max_distinct_tactics", "min_distinct_techniques",
                        "any_tactics", "any_techniques"}

_CONDITIONS = _STRUCTURAL_CONDITIONS | _EVIDENCE_CONDITIONS

_ACTIONS = {"surface", "suppress"}

# Keyed BY PATH, not a single slot — same reasoning as correlation.py: with
# one global slot the `path` argument is silently ignored once any ruleset has
# been loaded, so a caller asking for a different ruleset gets the first one
# back with no error. Invisible in production, quietly fatal in a test.
_rules = {}             # path -> [rule, ...]
_load_errors = {}       # path -> [(id, message), ...]


def load_rules(path: str = RULES_PATH, force: bool = False) -> list:
    """Parse and validate detection_rules.yml. Cached after the first call.

    A malformed rule is skipped with a warning rather than breaking the
    dashboard, and the reason is kept in load_errors() -- the same philosophy
    as mitre_mapper.load_rules() and severity.load_rules().

    Each rule keeps its `order`: its index in the file. That is the only
    ordering detection has, and it is deliberately authored rather than
    computed (see the module docstring).
    """
    if path in _rules and not force:
        return _rules[path]

    rules, errors = [], []
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[detection] cannot read {path}: {e}")
        _rules[path] = []
        _load_errors[path] = [(os.path.basename(path), str(e))]
        return _rules[path]

    for idx, raw in enumerate(doc.get("rules") or []):
        rid = raw.get("id", "<no id>")
        try:
            action = raw.get("action", "surface")
            if action not in _ACTIONS:
                raise ValueError(f"action must be one of {sorted(_ACTIONS)}, "
                                 f"got {action!r}")
            when = raw.get("when") or {}
            if not when:
                raise ValueError("rule has no `when` conditions")
            unknown = set(when) - _CONDITIONS
            if unknown:
                raise ValueError(f"unknown condition(s): {sorted(unknown)}")
            description = (raw.get("description") or "").strip()
            if not description:
                raise ValueError("rule has no `description` to explain itself")
            rules.append({
                "id": rid,
                "title": raw.get("title", rid),
                "action": action,
                "description": description,
                "when": when,
                "order": idx,
            })
        except Exception as e:
            errors.append((rid, str(e)))
            print(f"[detection] skipping rule {rid}: {e}")

    seen = set()
    for r in rules:
        if r["id"] in seen:
            errors.append((r["id"], "duplicate rule id"))
            print(f"[detection] WARNING: duplicate rule id {r['id']}")
        seen.add(r["id"])

    _rules[path], _load_errors[path] = rules, errors
    return rules


def load_errors(path: str = RULES_PATH) -> list:
    """[(rule_id, message)] from the last load of `path` — for the rule
    validator."""
    load_rules(path)
    return _load_errors.get(path, [])


def _fires(when: dict, rel: dict) -> bool:
    """Every condition in `when` must hold (AND).

    Reads only structural facts correlation already published. Missing fields
    count as zero rather than raising: a relationship shape that predates a
    field should fail a rule, not crash the dashboard.
    """
    if "link_type_in" in when:
        if rel.get("link_type") not in set(when["link_type_in"]):
            return False

    members = rel.get("member_count", len(rel.get("members") or ()))
    if "min_members" in when and members < when["min_members"]:
        return False
    if "max_members" in when and members > when["max_members"]:
        return False

    sources = rel.get("distinct_sources", 0)
    if "min_distinct_sources" in when and sources < when["min_distinct_sources"]:
        return False
    if "max_distinct_sources" in when and sources > when["max_distinct_sources"]:
        return False

    if "min_distinct_scopes" in when:
        if len(rel.get("scope") or ()) < when["min_distinct_scopes"]:
            return False

    # ── evidence conditions: fail closed when there is no evidence ──────────
    if when.keys() & _EVIDENCE_CONDITIONS:
        ev = rel.get("evidence")
        if not ev:
            return False

        if "min_sequence_length" in when:
            if ev.get("sequence_length", 0) < when["min_sequence_length"]:
                return False

        distinct_cmds = ev.get("distinct_commands", 0)
        if "min_distinct_commands" in when and distinct_cmds < when["min_distinct_commands"]:
            return False
        if "max_distinct_commands" in when and distinct_cmds > when["max_distinct_commands"]:
            return False

        tactics = set(ev.get("tactics") or ())
        if "min_distinct_tactics" in when and len(tactics) < when["min_distinct_tactics"]:
            return False
        if "max_distinct_tactics" in when and len(tactics) > when["max_distinct_tactics"]:
            return False
        if "any_tactics" in when and not tactics & set(when["any_tactics"]):
            return False

        techs = set(ev.get("technique_ids") or ())
        if "min_distinct_techniques" in when:
            if len(techs) < when["min_distinct_techniques"]:
                return False
        if "any_techniques" in when and not techs & set(when["any_techniques"]):
            return False

    return True


def _verdict(rel: dict, matched: list, bucket: str, reason: str = None) -> dict:
    """One verdict record. The relationship is embedded untouched -- detection
    annotates correlation's output, it never rewrites it."""
    return {
        "bucket": bucket,
        # File position of the rule that decided this, used only to order the
        # analyst's reading list. Not a score: see the module docstring.
        "_order": matched[0]["order"] if matched else len(matched),
        "rules": [{"id": r["id"], "title": r["title"],
                   "reason": r["description"]} for r in matched],
        # The single line a UI shows to justify the verdict. Always populated:
        # there is no such thing here as a finding without a stated reason.
        "reason": reason or (matched[0]["description"] if matched else ""),
        "relationship": rel,
    }


NO_RULE_REASON = ("No detection rule matched this relationship. It remains "
                  "available as evidence and is not a judgement that it is benign.")


def detect(relationships=None, path: str = RULES_PATH) -> dict:
    """Apply detection policy to correlation output.

    -> {"detections": [...], "suppressed": [...], "unmatched": [...],
        "evaluated": int}

    Every input relationship appears in exactly one bucket, so
    len(detections) + len(suppressed) + len(unmatched) == evaluated always.
    Nothing is dropped.

    A matching `suppress` rule beats any `surface` rule, so hiding a
    relationship is always attributable to one named rule rather than to the
    absence of something. `detections` is ordered by the surfacing rule's
    position in the ruleset, then by member count -- reading order, not a
    danger ranking.
    """
    relationships = relationships or []
    rules = load_rules(path)

    detections, suppressed, unmatched = [], [], []

    for rel in relationships:
        fired = [r for r in rules if _fires(r["when"], rel)]
        suppressors = [r for r in fired if r["action"] == "suppress"]
        surfacers = [r for r in fired if r["action"] == "surface"]

        if suppressors:
            suppressed.append(_verdict(rel, suppressors, "suppressed"))
        elif surfacers:
            # Lowest file position first, so a relationship is explained by the
            # earliest rule its author put in the file.
            surfacers.sort(key=lambda r: r["order"])
            detections.append(_verdict(rel, surfacers, "detection"))
        else:
            unmatched.append(_verdict(rel, [], "unmatched", NO_RULE_REASON))

    detections.sort(key=lambda d: (d["_order"],
                                   -d["relationship"].get("member_count", 0)))

    return {
        "detections": detections,
        "suppressed": suppressed,
        "unmatched": unmatched,
        "evaluated": len(relationships),
    }
