"""
api/services/investigations.py — the full picture for one subject.

These ARE the item endpoints. /sessions/{id}, /alerts/{id},
/threats/iocs/{ioc} and /sources/{ip} each serve one of these functions, so a
consumer asks for a thing once and gets its complete security context --
metadata, commands, correlations, detections, alerts, IOCs and evidence --
instead of reconstructing it from five calls it has to stitch itself.

A separate /investigations/* namespace used to serve them alongside thin
resource endpoints. Two URLs for one thing, and the consumer had to guess
which was authoritative. Measured before removing it: the expensive work is
WINDOW-scoped and cached, so one pipeline run serves every session in the
window and the marginal cost of the full picture is ~1ms per request. There
was nothing to buy with the second endpoint.

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

from api.services.common import pipeline, iocs, overview, _inst, _evidence_id
from api.services.findings import _detection_dto, _mitre_dto, get_alert
from api.services.intel import get_ioc, _ioc_dto
from api.services.sessions import get_session, related_sessions

def investigate_session(session_id, since=None, instance=None):
    """One coherent package about a session: what it did, what it is related
    to, and what the pipeline concluded -- assembled from the existing layers,
    not recomputed."""
    sess = get_session(session_id, instance)
    if sess is None:
        return None
    rel = related_sessions(session_id, since, instance)
    result = pipeline(since, instance)

    dets, alert_ids = [], []
    for b in ("detections", "suppressed", "unmatched"):
        for det in result.get(b) or []:
            if session_id in ((det.get("relationship") or {}).get("members") or []):
                dets.append(_detection_dto(dict(det, bucket=b),
                                           include_evidence=False))
    for d in dets:
        row = storage.get_alert(d["detection_id"],
                               instance=_inst(instance) or "default")
        if row:
            alert_ids.append(row["alert_key"])

    session_iocs = [_ioc_dto(i) for i in iocs(since, instance)
                    if session_id in (i.get("sessions") or [])]

    return {
        "summary": {
            "src_ip": sess.get("src_ip"),
            "commands": sess.get("command_count"),
            "first_seen": sess.get("first_seen"),
            "last_seen": sess.get("last_seen"),
            "techniques": len(sess["mitre"]["techniques"]),
            "tactics": len(sess["mitre"]["tactics"]),
            "relationships": rel["total"],
            "detections": len(dets),
            "alerts": len(alert_ids),
        },
        # Flattened: this IS /sessions/{id}, so wrapping the session inside a
        # "session" key would nest a resource inside itself. `timeline` and a
        # second `mitre` used to sit here too -- both byte-identical copies of
        # what `commands` and `mitre` already carry.
        **sess,
        "iocs": session_iocs,
        "correlations": rel["relationships"],
        "detections": dets,
        "alerts": alert_ids,
        "evidence": _session_evidence(session_id, sess, session_iocs),
    }


def _session_evidence(session_id, sess, session_iocs) -> list:
    out = []
    for c in (sess.get("commands") or [])[:100]:
        out.append({
            "evidence_id": _evidence_id(session_id, "cmd", c["sequence"]),
            "type": "command", "source": "session", "session_id": session_id,
            "timestamp": c.get("timestamp"), "value": c.get("command"),
        })
    for t in sess["mitre"]["techniques"]:
        out.append({
            "evidence_id": _evidence_id(session_id, "mitre", t["technique_id"]),
            "type": "mitre", "source": "mitre_mapper",
            "session_id": session_id, "technique": t["technique_id"],
            "value": t["name"],
        })
    for i in session_iocs:
        out.append({
            "evidence_id": _evidence_id(session_id, "ioc", i["ioc"]),
            "type": "ioc", "source": "ioc_extractor",
            "session_id": session_id, "value": i["ioc"],
            "first_seen": i.get("first_seen"),
        })
    return out


def investigate_alert(alert_id, since=None, instance=None):
    alert = get_alert(alert_id, instance, since)
    if alert is None:
        return None
    det = alert.get("detection") or {}
    members = (det.get("correlation") or {}).get("sessions") or []
    sessions = [s for s in (get_session(m, instance) for m in members[:25]) if s]

    return {
        "summary": {
            "severity": alert.get("severity"),
            "state": alert.get("state"),
            "title": alert.get("title"),
            "sessions": alert.get("member_count"),
            "sources": alert.get("distinct_sources"),
            "first_seen": alert.get("first_seen"),
            "last_seen": alert.get("last_seen"),
        },
        **alert,
        "detection": det,
        "correlation": det.get("correlation"),
        "mitre": det.get("mitre"),
        "sessions": sessions,
        "evidence": det.get("evidence") or [],
    }


def investigate_ip(ip, since=None, instance=None):
    """Everything HydraPoT observed from one source address.

    An address is not an identity: NAT collapses many hosts into one, rotation
    splits one actor across many, and an imported corpus may store a
    pseudonymised token. This returns what was recorded, not who it was.
    """
    o = overview(since, instance)
    ip_row = next((r for r in (o.get("source_ips") or [])
                   if r.get("src_ip") == ip), None)
    sessions = [s for s in (o.get("sessions") or []) if s.get("src_ip") == ip]
    if ip_row is None and not sessions:
        return None

    sids = {s["session_id"] for s in sessions}
    result = pipeline(since, instance)
    dets = []
    for b in ("detections", "suppressed", "unmatched"):
        for det in result.get(b) or []:
            rel = det.get("relationship") or {}
            if ip in (rel.get("src_ips") or []) or sids & set(rel.get("members") or []):
                dets.append(_detection_dto(dict(det, bucket=b),
                                           include_evidence=False))

    ip_iocs = [_ioc_dto(i) for i in iocs(since, instance)
               if ip in (i.get("src_ips") or [])]

    return {
        "src_ip": ip,
        "summary": {
            "commands": (ip_row or {}).get("commands"),
            "sessions": len(sessions),
            "login_attempts": (ip_row or {}).get("login_attempts"),
            "first_seen": (ip_row or {}).get("first_seen"),
            "last_seen": (ip_row or {}).get("last_seen"),
            "detections": len(dets),
        },
        "note": ("A source address is not an identity. NAT, proxies and address "
                 "rotation all break the assumption that one address is one actor."),
        "sessions": [{"session_id": s["session_id"], "commands": s["commands"],
                      "first_seen": s.get("first_seen"),
                      "last_seen": s.get("last_seen"),
                      "mitre": _mitre_dto(s.get("technique_ids"), s.get("tactics"))}
                     for s in sessions],
        "tactics": (ip_row or {}).get("tactics") or [],
        "iocs": ip_iocs,
        "detections": dets,
    }


def investigate_ioc(ioc, since=None, instance=None):
    rec = get_ioc(ioc, since, instance)
    if rec is None:
        return None
    sids = set(rec.get("sessions") or [])
    result = pipeline(since, instance)
    dets = [_detection_dto(dict(det, bucket=b), include_evidence=False)
            for b in ("detections", "suppressed", "unmatched")
            for det in (result.get(b) or [])
            if sids & set((det.get("relationship") or {}).get("members") or [])]

    return {
        "summary": {
            "type": rec["type"], "occurrences": rec["occurrences"],
            "sessions": rec["session_count"],
            "sources": len(rec.get("src_ips") or []),
            "first_seen": rec.get("first_seen"), "last_seen": rec.get("last_seen"),
            "detections": len(dets),
        },
        **rec,
        "sessions": rec.get("sessions"),
        "mitre": _mitre_dto(rec.get("techniques"), []),
        "detections": dets,
    }
