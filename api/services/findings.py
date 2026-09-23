"""
api/services/findings.py — detections, correlations and alerts.

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
from threat_intel.alert_records import alert_key

from api.services.common import (page, pipeline, _inst, detection_id,
                                 correlation_id, _evidence_id, window_filter)

def _detection_dto(det, include_evidence=True) -> dict:
    """One detection, as an external consumer should see it.

    Carries the FACTS and the reasoning chain, never a verdict of its own:
    the correlation statement verbatim, the detection rule that surfaced it,
    the severity the severity layer assigned and the rules that produced it.
    """
    rel = det.get("relationship") or {}
    ev = rel.get("evidence") or {}
    rules = det.get("rules") or []
    rule = rules[0] if rules else {}

    out = {
        "detection_id": detection_id(det),
        "bucket": det.get("bucket"),
        "title": rule.get("title"),
        "detection_rule": rule.get("id"),
        "reason": rule.get("reason") or det.get("reason"),
        "severity": det.get("severity"),          # None = unrated, never guessed
        "severity_rules": [{"id": r.get("id"), "severity": r.get("severity"),
                            "title": r.get("title")}
                           for r in (det.get("severity_rules") or [])],
        "correlation": {
            "correlation_id": correlation_id(rel),
            "link_type": rel.get("link_type"),
            # The engine's own wording -- the only sentence it authorises a
            # consumer to render for a relationship.
            "statement": rel.get("statement"),
            "member_count": rel.get("member_count"),
            "distinct_sources": rel.get("distinct_sources"),
            "sessions": rel.get("members"),
            "src_ips": rel.get("src_ips"),
            "scope": rel.get("scope"),
            "first_seen": rel.get("first_seen"),
            "last_seen": rel.get("last_seen"),
        },
        "mitre": _mitre_dto(ev.get("technique_ids"), ev.get("tactics")),
        "operational": {},
    }
    if include_evidence:
        out["evidence"] = detection_evidence(det)
    return out


def _mitre_dto(technique_ids=None, tactics=None) -> dict:
    """Technique IDs with their human-readable names, from the ATT&CK catalog
    the MITRE layer already loads."""
    from SIEM.investigation import technique_name, technique_url
    tids = list(technique_ids or [])
    return {
        "tactics": list(tactics or []),
        "techniques": [{"technique_id": t, "name": technique_name(t),
                        "url": technique_url(t)} for t in tids],
    }


def detection_evidence(det) -> list:
    """The artifacts behind a detection, each traceable to its source.

    This is what lets a consumer -- a person or an AI -- answer "why do you
    believe that". Each item names the layer that produced it and the rule or
    session it came from.
    """
    rel = det.get("relationship") or {}
    ev = rel.get("evidence") or {}
    rules = det.get("rules") or []
    rule = rules[0] if rules else {}
    did = detection_id(det)
    out = []

    if rel.get("statement"):
        out.append({
            "evidence_id": _evidence_id(did, "correlation"),
            "type": "correlation", "source": "correlation",
            "rule": rel.get("link_type"), "value": rel.get("statement"),
            "first_seen": rel.get("first_seen"), "last_seen": rel.get("last_seen"),
        })
    if rule.get("id"):
        out.append({
            "evidence_id": _evidence_id(did, "detection"),
            "type": "detection", "source": "detection",
            "rule": rule.get("id"), "value": rule.get("reason"),
        })
    for r in (det.get("severity_rules") or []):
        out.append({
            "evidence_id": _evidence_id(did, "severity", r.get("id")),
            "type": "severity", "source": "severity", "rule": r.get("id"),
            "value": r.get("description") or r.get("title"),
            "severity": r.get("severity"),
        })
    for tid in (ev.get("technique_ids") or []):
        from SIEM.investigation import technique_name
        out.append({
            "evidence_id": _evidence_id(did, "mitre", tid),
            "type": "mitre", "source": "mitre_mapper",
            "technique": tid, "value": technique_name(tid),
        })
    for i, cmd in enumerate(ev.get("sample") or []):
        out.append({
            "evidence_id": _evidence_id(did, "command", i),
            "type": "command", "source": "session",
            "session_id": (rel.get("members") or [None])[0],
            "value": cmd, "sequence": i + 1,
        })
    return out


def list_detections(since=None, instance=None, severity_level=None,
                    bucket="detections", limit=50, offset=0) -> dict:
    result = pipeline(since, instance)
    buckets = (["detections", "suppressed", "unmatched"]
               if bucket == "all" else [bucket])
    items = []
    for b in buckets:
        for det in result.get(b) or []:
            det = dict(det, bucket=b)
            if severity_level and (det.get("severity") or "unrated") != severity_level:
                continue
            items.append(_detection_dto(det, include_evidence=False))
    return page(items, limit, offset)


def get_detection(det_id, since=None, instance=None):
    result = pipeline(since, instance)
    for b in ("detections", "suppressed", "unmatched"):
        for det in result.get(b) or []:
            if detection_id(det) == det_id:
                return _detection_dto(dict(det, bucket=b))
    return None


def get_correlation(corr_id, since=None, instance=None):
    """One relationship, exactly as the correlation engine produced it."""
    result = pipeline(since, instance)
    for b in ("detections", "suppressed", "unmatched"):
        for det in result.get(b) or []:
            rel = det.get("relationship") or {}
            if correlation_id(rel) == corr_id:
                ev = rel.get("evidence") or {}
                return {
                    "correlation_id": corr_id,
                    "link_type": rel.get("link_type"),
                    "link_value": rel.get("link_value"),
                    "statement": rel.get("statement"),
                    "members": rel.get("members"),
                    "member_count": rel.get("member_count"),
                    "distinct_sources": rel.get("distinct_sources"),
                    "src_ips": rel.get("src_ips"),
                    "first_seen": rel.get("first_seen"),
                    "last_seen": rel.get("last_seen"),
                    "scope": rel.get("scope"),
                    "evidence": {
                        "sequence_length": ev.get("sequence_length"),
                        "distinct_commands": ev.get("distinct_commands"),
                        "sample": ev.get("sample"),
                        "mitre": _mitre_dto(ev.get("technique_ids"),
                                            ev.get("tactics")),
                    } if ev else None,
                    "detection_id": detection_id(det),
                }
    return None


# ── alerts ──────────────────────────────────────────────────────────────────

def _alert_dto(row, det=None) -> dict:
    out = {
        "alert_id": row.get("alert_key"),
        "state": row.get("state"),
        "severity": row.get("severity"),
        "title": row.get("title"),
        "alert_rule": row.get("alert_rule"),
        "detection_rule": row.get("detection_rule"),
        "correlation": {"link_type": row.get("link_type"),
                        "correlation_id": f"{row.get('link_type')}:{row.get('link_value')}"},
        "member_count": row.get("member_count"),
        "distinct_sources": row.get("distinct_sources"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "acknowledged_by": row.get("acknowledged_by"),
        "acknowledged_at": row.get("acknowledged_at"),
        "closed_at": row.get("closed_at"),
        "delivered_at": row.get("routed_at"),
        "scope": row.get("instance"),
    }
    if det is not None:
        # The alert row carries counts and state; the DETECTION carries the
        # reasoning. Joined only on the detail route, so listing stays cheap.
        out["detection"] = _detection_dto(det)
    return out


def list_alerts(state=None, severity_level=None, instance=None, since=None,
                limit=50, offset=0) -> dict:
    rows = storage.query_alerts(state=state, severity=severity_level,
                                instance=_inst(instance) or "default", limit=2000)
    # Dated by the ACTIVITY where it is known, by the record otherwise -- the
    # same order query_alerts sorts by, so a window and the sort agree.
    rows = window_filter(rows, since, "last_seen", "updated_at")
    return page([_alert_dto(r) for r in rows], limit, offset)


def alert_counts(instance=None) -> dict:
    return storage.alert_counts(instance=_inst(instance) or "default")


def get_alert(alert_id, instance=None, since=None):
    row = storage.get_alert(alert_id, instance=_inst(instance) or "default")
    if not row:
        return None
    det = None
    result = pipeline(since, instance)
    for b in ("detections", "suppressed", "unmatched"):
        for d in result.get(b) or []:
            if alert_key(d) == alert_id:
                det = dict(d, bucket=b)
                break
    return _alert_dto(row, det)


