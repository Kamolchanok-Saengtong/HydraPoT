"""
api/services/sessions.py — session investigation context and related activity.

Part of HydraPoT's application layer:

    route  ->  service (here)  ->  existing domain module  ->  storage

VERSION-AGNOSTIC ON PURPOSE. These services are shared by every API version.
api/v1/ shapes them into the v1 contract; a future api/v2/ would reuse the same
functions and change only the response shape. That is what keeps versioning
cheap -- the security logic is never copied per version, so v1 and v2 can never
disagree about what HydraPoT found.

Nothing here re-implements aggregation, correlation, detection, severity or
alerting.
"""

import storage

from api.services.common import page, pipeline, overview, _inst, detection_id, correlation_id
from api.services.findings import _mitre_dto

def list_sessions(since=None, instance=None, src_ip=None, technique=None,
                  category=None, min_fi=None, limit=50, offset=0) -> dict:
    """Session rollups from aggregation, filtered.

    min_fi is an OPERATIONAL filter -- "show me sessions that drew the most
    interaction" is a real investigation question. It does not order results,
    does not appear as severity, and a session's FI says nothing about how
    dangerous it was.
    """
    o = overview(since, instance)
    rows = o.get("sessions") or []

    if src_ip:
        rows = [r for r in rows if r.get("src_ip") == src_ip]
    if technique:
        rows = [r for r in rows if technique in (r.get("technique_ids") or [])]
    if category:
        rows = [r for r in rows if category in (r.get("tactics") or [])]

    items = [{
        "session_id": r.get("session_id"),
        "src_ip": r.get("src_ip"),
        "commands": r.get("commands"),
        "first_seen": r.get("first_seen"),
        "last_seen": r.get("last_seen"),
        "mitre": _mitre_dto(r.get("technique_ids"), r.get("tactics")),
    } for r in rows]

    if min_fi is not None:
        keep = _sessions_at_or_above_fi(int(min_fi), since, instance)
        items = [i for i in items if i["session_id"] in keep]
    return page(items, limit, offset)


def _sessions_at_or_above_fi(min_fi, since=None, instance=None) -> set:
    win = overview(since, instance)["window"]
    # Harmless today -- this set only ever narrows an already-filtered list --
    # but reading the raw table here is how the next caller drifts.
    rows = storage.real_rows(
        storage.query_range(win["start"], win["end"], instance=_inst(instance)))
    return {r.get("session_id") for r in rows
            if (r.get("fi_score") or 0) >= min_fi}


def get_session(session_id, instance=None) -> dict:
    """One session's investigation context, from aggregate_session() plus the
    stored command rows. No SQL is assembled here beyond the indexed lookup the
    storage layer already exposes."""
    from threat_intel.aggregator import aggregate_session
    summary = aggregate_session(session_id, instance=_inst(instance))
    if not summary:
        return None
    rows = storage.query_session(session_id, instance=_inst(instance))

    from SIEM.investigation import technique_name
    commands = [{
        "sequence": i + 1,
        "timestamp": r.get("timestamp"),
        "command": r.get("cmd"),
        "technique_id": r.get("technique_id"),
        "technique": technique_name(r["technique_id"]) if r.get("technique_id") else None,
        # FI and the agent are how the HONEYPOT responded, not what the
        # attacker did -- namespaced so no consumer mistakes them for a rating.
        "operational": {"fi_score": r.get("fi_score"), "agent": r.get("agent"),
                        "latency_ms": r.get("latency_ms")},
    } for i, r in enumerate(rows)]

    return {
        "session_id": session_id,
        "src_ip": summary.get("src_ip"),
        "scope": (rows[0].get("instance") if rows else None),
        "first_seen": summary.get("start_time"),
        "last_seen": summary.get("end_time"),
        "duration_s": summary.get("duration_s"),
        "command_count": summary.get("event_count"),
        "commands_per_minute": summary.get("commands_per_minute"),
        "mitre": _mitre_dto(summary.get("technique_ids"), summary.get("tactics")),
        "categories": {k: v for k, v in summary.items()
                       if k not in _SUMMARY_KEYS and isinstance(v, int)},
        "commands": commands,
        "operational": {
            "agents_used": summary.get("agents_used"),
            "avg_fi_score": summary.get("avg_fi_score"),
            "max_fi_score": summary.get("max_fi_score"),
            "avg_latency_ms": summary.get("avg_latency_ms"),
            "electricity_cost_thb": summary.get("electricity_cost_thb"),
            "cloud_cost_usd": summary.get("cloud_cost_usd"),
        },
    }


# Keys of aggregate_session()'s summary that are NOT config-defined categories.
_SUMMARY_KEYS = {
    "event_count", "src_ip", "start_time", "end_time", "duration_s",
    "commands_per_minute", "tactics", "technique_ids", "high_risk_count",
    "max_fi_score", "avg_fi_score", "agents_used", "electricity_cost_thb",
    "cloud_cost_usd", "total_latency_ms", "avg_latency_ms", "session_id",
}


def related_sessions(session_id, since=None, instance=None) -> dict:
    """Relationships this session takes part in, from the correlation engine.

    Each carries the engine's own statement. `same_sequence` means the same
    observed command sequence -- NOT the same attacker, operator or campaign,
    and the API does not upgrade it to one.
    """
    result = pipeline(since, instance)
    out = []
    for b in ("detections", "suppressed", "unmatched"):
        for det in result.get(b) or []:
            rel = det.get("relationship") or {}
            members = rel.get("members") or []
            if session_id not in members:
                continue
            out.append({
                "correlation_id": correlation_id(rel),
                "link_type": rel.get("link_type"),
                "statement": rel.get("statement"),
                "related_sessions": [m for m in members if m != session_id],
                "member_count": rel.get("member_count"),
                "distinct_sources": rel.get("distinct_sources"),
                "detection_id": detection_id(det),
                "surfaced": b == "detections",
                "severity": det.get("severity"),
            })
    return {"session_id": session_id, "relationships": out,
            "total": len(out)}


