"""
api/services/system.py — operational health and feature discovery.

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
from threat_intel import correlation, detection, severity

def health() -> dict:
    """Operational status only. No configuration, no paths, no credentials."""
    db_ok, rows, sessions = True, None, None
    try:
        st = storage.stats()
        rows, sessions = st.get("rows"), st.get("sessions")
    except Exception:
        db_ok = False

    newest = None
    try:
        _, newest = storage.time_bounds()
    except Exception:
        pass

    return {
        "status": "healthy" if db_ok else "degraded",
        "api_version": "v1",
        "database": "ok" if db_ok else "unavailable",
        "events": rows,
        "sessions": sessions,
        "latest_event": newest,
    }


def capabilities() -> dict:
    """What this deployment can actually do, READ FROM THE RULESETS.

    Deliberately not a hardcoded list of trues: a feature is reported as
    available when the rules that implement it load. If someone empties
    detection_rules.yml, `detection` reports false rather than advertising a
    capability that will return nothing.
    """
    from threat_intel import alert_records, normalize
    from api.services import export

    def _count(fn, *a):
        try:
            return len(fn(*a))
        except Exception:
            return 0

    strategies = _count(correlation.load_strategies)
    det_rules = _count(detection.load_rules)
    sev_rules = _count(severity.load_rules)
    alert_rules = _count(alert_records.load_rules)
    sinks = sorted(alert_records.load_sinks().keys())

    return {
        "api_version": "v1",
        "features": {
            "mitre": True,
            "ioc": True,
            "correlation": strategies > 0,
            "detection": det_rules > 0,
            "severity": sev_rules > 0,
            "alerting": alert_rules > 0,
            "investigation": True,
            "websocket": True,
        },
        "rules": {
            "correlation_strategies": strategies,
            "detection_rules": det_rules,
            "severity_rules": sev_rules,
            "alert_rules": alert_rules,
        },
        "correlation_types": [s["id"] for s in correlation.load_strategies()],
        "severity_levels": list(severity.SEVERITY_ORDER),
        "alert_states": list(storage.ALERT_STATES),
        # Read from the export service, not retyped. This list used to be a
        # literal advertising four formats no v1 route served -- an integrator
        # was told a capability existed and found nothing to call.
        "export_formats": sorted(export.FORMATS),
        "export_classes": sorted(export.CLASSES),
        "export_endpoint": "/api/v1/ocsf",
        "ocsf_version": normalize.OCSF_VERSION,
        # Which sinks are ENABLED, so an integrator can see whether anything is
        # being forwarded. Never the destinations -- those are credentials.
        "enabled_alert_sinks": sinks,
        "time_windows": ["15m", "1h", "24h", "7d", "all"],
    }


