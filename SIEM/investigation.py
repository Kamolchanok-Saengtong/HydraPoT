"""
SIEM/investigation.py — view model for the investigation page.

Turns Correlation -> Detection output into the shape an ANALYST reads, without
touching either layer. Nothing here re-derives a fact, re-groups a
relationship, or invents a field: it joins what the pipeline already produced
(detections, relationships, session rollups, the ATT&CK catalog) into one
object per detection, so pages/investigate.py can be pure rendering.

Separated from the page for the same reason aggregator.py is separated from
summary.py: the join is testable on its own, and a layout change cannot quietly
alter what a detection claims.

SEVERITY IS READ, NEVER COMPUTED HERE.
threat_intel/severity.py rates each relationship before this file sees it
(SIEM/data.py runs Detection then Severity as separate passes). This module
copies the rating and the rules that produced it; it never decides a severity
of its own. A relationship with no shared command sequence -- an indicator or
source-address link -- comes back unrated, and stays unrated in the UI rather
than being given a guessed level.
"""
from threat_intel.alert_records import alert_key as _alert_key
from threat_intel.mitre_mapper import _load_catalog
from threat_intel.severity import SEVERITY_ORDER

# Ascending, matching severity.SEVERITY_ORDER. Unrated sorts BELOW everything:
# "the ruleset had nothing to read" is not a claim of safety, but it is not
# evidence of danger either, so it must not outrank a rated finding.
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
UNRATED_RANK = -1


def technique_name(tid: str) -> str:
    """Human-readable ATT&CK name for a technique ID.

    Falls back to the ID itself when the catalog does not carry it -- the ID is
    real data, so showing it is accurate, where "Not available" would hide a
    fact we do have.
    """
    return (_load_catalog().get(tid) or {}).get("name") or tid


def technique_url(tid: str) -> str:
    return (_load_catalog().get(tid) or {}).get("url") or ""


def technique_tactic(tid: str) -> str:
    """The tactic this technique belongs to, per the ATT&CK catalog.

    Lets the UI group techniques under the stage they belong to instead of
    listing them flat beside a repeated tactic chain. Empty when the catalog
    has no entry -- the caller groups those separately rather than guessing a
    stage for them.
    """
    return (_load_catalog().get(tid) or {}).get("tactic") or ""


def _plain_why(det, view) -> str:
    """One analyst-facing sentence for WHY THIS FIRED, built only from counted
    facts already in the relationship.

    The detection rule's full description stays available as secondary text;
    this is the version that fits in a queue row without becoming the wall of
    repeated paragraphs the old cards were.
    """
    n, s = view["member_count"], view["distinct_sources"]
    sess = f"{n} sessions" if n != 1 else "1 session"
    link = det["relationship"]["link_type"]

    if link == "same_sequence":
        base = f"The same command sequence was observed across {sess}"
        t = len(view["tactics"])
        if t > 1:
            base += f", and that sequence crosses {t} ATT&CK tactics"
    elif link == "shared_indicator":
        base = f"{sess} reference the same indicator value"
    elif link == "same_source_address":
        base = f"{sess} originate from the same recorded source address"
    else:
        # Unknown strategy: fall back to correlation's own statement rather
        # than guessing wording for a link type this file has not met.
        return det["relationship"]["statement"]

    if s > 1:
        base += f", from {s} independent source addresses"
    return base + "."


def build_detection_view(det, sessions_by_id) -> dict:
    """One detection -> one analyst-facing object.

    Every field is copied from the pipeline or counted from it. The raw
    relationship is carried through untouched so the Raw Evidence section can
    show exactly what the engine produced.
    """
    rel = det["relationship"]
    ev = rel.get("evidence") or {}
    rules = det.get("rules") or []
    # Copied from the severity pass, never derived here.
    sev = det.get("severity")
    sev_rules = det.get("severity_rules") or []

    members = [sessions_by_id.get(m) for m in rel.get("members", [])]
    members = [m for m in members if m]

    tids = list(ev.get("technique_ids") or [])
    return {
        # The view key IS the alert key: one identity for a finding across the
        # UI and the alerts table, so a row and its alert can never drift apart.
        "key": _alert_key(det),
        "alert": None,           # filled by build_investigation from the DB
        # The rule's own title, already written as a statement of what the
        # finding IS. Not composed from counts here -- a generated title would
        # drift from the rule that actually fired.
        "severity": sev,
        # The rules that produced the rating ARE the justification the UI
        # shows, so a severity is never an opaque label.
        "severity_rules": sev_rules,
        "title": rules[0].get("title") if rules else "Unclassified relationship",
        "link_type": rel["link_type"],
        "statement": rel["statement"],
        "rule_id": rules[0]["id"] if rules else None,
        "rule_reason": rules[0]["reason"] if rules else "",
        "member_ids": list(rel.get("members", [])),
        "member_count": rel["member_count"],
        "members": members,
        "distinct_sources": rel["distinct_sources"],
        "src_ips": rel.get("src_ips") or [],
        "scope": rel.get("scope") or [],
        # None (not 0) when the strategy publishes no sequence evidence. The UI
        # renders that as "Not available" rather than a zero that reads as a
        # measured absence.
        "command_count": ev.get("sequence_length"),
        "distinct_commands": ev.get("distinct_commands"),
        "tactics": list(ev.get("tactics") or []),
        "technique_ids": tids,
        "techniques": [{"id": t, "name": technique_name(t), "url": technique_url(t),
                        "tactic": technique_tactic(t)} for t in tids],
        "sample": list(ev.get("sample") or []),
        "first_seen": rel.get("first_seen"),
        "last_seen": rel.get("last_seen"),
        "relationship": rel,          # untouched, for Raw Evidence
        "why": None,                  # filled by build_investigation
    }


def build_investigation(detect_result, overview, instance=None) -> dict:
    """-> {"summary": {...}, "queue": [detection view, ...], "raw": detect_result}

    `overview` supplies the per-session rollups (aggregate_overview's
    "sessions"): command counts, tactics, technique IDs, first/last seen. Those
    are looked up, never recomputed.

    Queue order is severity first, then detect()'s own order underneath it.
    Severity is the later layer and is entitled to lead the analyst's queue;
    within one severity, detect()'s authored ordering is preserved exactly
    rather than replaced. Both terms are existing ordinals -- a severity level
    and a rule's file position -- so this is a sort, not a computed score.
    """
    sessions_by_id = {s["session_id"]: s for s in overview.get("sessions", [])}

    # Analyst state, joined in from the alerts table. It is the one thing on
    # this page that is NOT recomputed from the pipeline -- it exists only
    # because a person did something -- so it is looked up, never derived.
    # Scoped to the SAME instance the alerts were raised under. Querying every
    # instance and keying by alert_key alone looked equivalent and was not: the
    # same relationship legitimately produces one alert row PER sensor, so an
    # unfiltered lookup let an arbitrary row win -- the page showed one
    # sensor's state while the Acknowledge button wrote another's.
    try:
        import storage
        alerts_by_key = {a["alert_key"]: a for a in
                         storage.query_alerts(instance=instance or "default",
                                              limit=2000)}
    except Exception:
        alerts_by_key = {}       # no alert state is a degraded page, not a broken one

    queue = []
    for det in detect_result.get("detections", []):
        v = build_detection_view(det, sessions_by_id)
        v["why"] = _plain_why(det, v)
        v["alert"] = alerts_by_key.get(v["key"])
        queue.append(v)

    # Stable sort on severity alone: Python's sort preserves the existing order
    # of equal keys, so detect()'s ordering survives inside each level.
    queue.sort(key=lambda v: -SEVERITY_RANK.get(v["severity"], UNRATED_RANK))

    # Counts for the summary strip. Sessions/techniques/tactics are counted
    # DISTINCT across surfaced detections: one session appearing in three
    # relationships is one session under investigation, not three.
    by_rule, sess, techs, tacs = {}, set(), set(), set()
    by_sev = {}
    for v in queue:
        rid = v["rule_id"] or "unclassified"
        by_rule[rid] = by_rule.get(rid, 0) + 1
        by_sev[v["severity"] or "unrated"] = by_sev.get(v["severity"] or "unrated", 0) + 1
        sess.update(v["member_ids"])
        techs.update(v["technique_ids"])
        tacs.update(v["tactics"])

    # Correlation type is the only classifier this pipeline actually has until
    # the severity layer is wired, so it is what the queue filters on.
    by_type = {}
    for v in queue:
        by_type[v["link_type"]] = by_type.get(v["link_type"], 0) + 1

    act = overview.get("activity") or {}
    mitre_cov = (overview.get("mitre") or {}).get("coverage") or {}

    return {
        "summary": {
            "by_rule": by_rule,
            "by_type": by_type,
            "by_severity": by_sev,
            "detections": len(queue),
            "sessions": len(sess),
            "relationships": detect_result.get("evaluated", 0),
            "suppressed": len(detect_result.get("suppressed", [])),
            "unmatched": len(detect_result.get("unmatched", [])),
            "techniques": len(techs),
            "tactics": len(tacs),
            "alerts_open": sum(1 for v in queue if (v.get("alert") or {}).get("state")
                               in ("new", "acknowledged")),
            # Window totals, so each headline figure can state what it is a
            # share OF instead of floating free. Straight from aggregation.
            "window_sessions": act.get("session_count"),
            "window_commands": act.get("command_count"),
            "tagged_commands": mitre_cov.get("tagged"),
        },
        "queue": queue,
        "raw": detect_result,
    }
