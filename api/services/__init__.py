"""
api/services — HydraPoT's application layer, one module per domain.

    common           windows, paging, stable ids, evidence provenance
    system           health, capabilities
    findings         detections, correlations, alerts
    sessions         session context, related activity
    intel            MITRE, IOCs, categories
    investigations   coherent packages per subject
    export           normalized telemetry -- OCSF / CEF / ECS

Re-exported here so routes import from one place and a later reshuffle of these
modules does not touch a single route file.
"""
from api.services.common import (resolve_since, page, overview, pipeline, iocs,
                                 detection_id, correlation_id)
from api.services.system import health, capabilities
from api.services.findings import (list_detections, get_detection,
                                   get_correlation, list_alerts, alert_counts,
                                   get_alert, detection_evidence)
from api.services.sessions import list_sessions, get_session, related_sessions
from api.services.intel import (mitre_activity, mitre_technique, list_iocs,
                                get_ioc, categories)
from api.services.investigations import (investigate_session, investigate_alert,
                                         investigate_ip, investigate_ioc)
from api.services.export import ocsf

__all__ = [
    "resolve_since", "page", "overview", "pipeline", "iocs",
    "detection_id", "correlation_id", "health", "capabilities",
    "list_detections", "get_detection", "get_correlation", "list_alerts",
    "alert_counts", "get_alert", "detection_evidence",
    "list_sessions", "get_session", "related_sessions",
    "mitre_activity", "mitre_technique", "list_iocs", "get_ioc", "categories",
    "investigate_session", "investigate_alert", "investigate_ip",
    "investigate_ioc", "ocsf",
]
