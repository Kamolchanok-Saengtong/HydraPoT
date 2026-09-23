"""
api/services/intel.py — MITRE activity and IOCs.

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

from api.services.common import page, pipeline, iocs, overview, _inst, detection_id

def mitre_activity(since=None, instance=None) -> dict:
    o = overview(since, instance)
    m = o.get("mitre") or {}
    from SIEM.investigation import technique_tactic, technique_url
    return {
        "tactics": m.get("tactics") or {},
        "techniques": [{
            "technique_id": t.get("technique_id"),
            "name": t.get("name"),
            "tactic": technique_tactic(t.get("technique_id")),
            "url": technique_url(t.get("technique_id")),
            "command_count": t.get("count"),
        } for t in (m.get("techniques") or [])],
        "coverage": m.get("coverage") or {},
        "window": o.get("window"),
    }


def mitre_technique(technique_id, since=None, instance=None):
    """Everything HydraPoT observed for one technique."""
    act = mitre_activity(since, instance)
    tech = next((t for t in act["techniques"]
                 if t["technique_id"] == technique_id), None)
    if tech is None:
        return None

    o = overview(since, instance)
    sessions = [s["session_id"] for s in (o.get("sessions") or [])
                if technique_id in (s.get("technique_ids") or [])]

    result = pipeline(since, instance)
    dets, alerts = [], []
    for b in ("detections", "suppressed", "unmatched"):
        for det in result.get(b) or []:
            ev = (det.get("relationship") or {}).get("evidence") or {}
            if technique_id in (ev.get("technique_ids") or []):
                dets.append(detection_id(det))
    for row in storage.query_alerts(instance=_inst(instance) or "default",
                                    limit=2000):
        if row.get("alert_key") in dets:
            alerts.append(row.get("alert_key"))

    ioc_hits = [i for i in iocs(since, instance)
                if technique_id in (i.get("techniques") or [])]
    return {**tech, "sessions": sessions, "session_count": len(sessions),
            "detections": dets, "alerts": alerts,
            "iocs": [_ioc_dto(i) for i in ioc_hits[:50]]}


def _ioc_dto(rec) -> dict:
    return {
        "ioc": f"{rec.get('type')}:{rec.get('value')}",
        "type": rec.get("type"),
        "value": rec.get("value"),
        "occurrences": rec.get("count"),
        "session_count": rec.get("session_count"),
        "sessions": rec.get("sessions"),
        "src_ips": rec.get("src_ips"),
        "first_seen": rec.get("first_seen"),
        "last_seen": rec.get("last_seen"),
        "techniques": rec.get("techniques"),
        # `benign` is the extractor's own allow-list judgement (a package
        # mirror, a public resolver), carried through rather than re-decided.
        "benign": rec.get("benign"),
    }


def list_iocs(since=None, instance=None, ioc_type=None, limit=50, offset=0):
    """Indicators. Observables flagged `benign` are NOT indicators.

    An attacker curling google.com is a real thing the honeypot saw, and it
    stays in the session log and in /sessions/{id}. It is not an indicator of
    compromise, and a consumer that ingests this endpoint as one would end up
    alerting on google.com. Same reasoning as to_stix().
    """
    recs = [r for r in iocs(since, instance) if not r.get("benign")]
    if ioc_type:
        recs = [r for r in recs if r.get("type") == ioc_type]
    recs = sorted(recs, key=lambda r: -(r.get("count") or 0))
    return page([_ioc_dto(r) for r in recs], limit, offset)


def get_ioc(ioc, since=None, instance=None):
    """Look up one indicator, by "type:value" or by bare value."""
    want_type, _, want_value = ioc.partition(":") if ":" in ioc else ("", "", ioc)
    for r in iocs(since, instance):
        if r.get("value") == (want_value or ioc) and \
           (not want_type or r.get("type") == want_type):
            return _ioc_dto(r)
    return None

