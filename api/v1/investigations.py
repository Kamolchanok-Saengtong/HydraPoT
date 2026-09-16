from fastapi import APIRouter

from api import services as svc
from api.v1.params import SINCE, INSTANCE, found

router = APIRouter()

# One coherent package per subject, assembled from the layers above.
#
# These exist so a consumer can investigate something without knowing which
# HydraPoT module owns which fact -- and so an AI agent has ONE call per
# question instead of six it must stitch together itself. They return evidence
# and structured facts with provenance, never a conclusion.


@router.get("/investigations/session/{session_id}",
            summary="Investigate a session", tags=["investigations"])
def investigate_session(session_id: str, since: str = SINCE,
                        instance: str = INSTANCE):
    """Subject, summary facts, timeline, commands, IOCs, MITRE, correlations,
    detections, alerts and evidence -- for one session."""
    return found(svc.investigate_session(session_id, since, instance), "session")


@router.get("/investigations/alert/{alert_id:path}",
            summary="Investigate an alert", tags=["investigations"])
def investigate_alert(alert_id: str, since: str = SINCE,
                      instance: str = INSTANCE):
    """The same package, starting from an alert: what fired, why, and the
    sessions underneath it."""
    return found(svc.investigate_alert(alert_id, since, instance), "alert")


@router.get("/investigations/ip/{ip}", summary="Investigate a source address",
            tags=["investigations"])
def investigate_ip(ip: str, since: str = SINCE, instance: str = INSTANCE):
    """Everything recorded from one address.

    The response carries an explicit note that an address is not an identity:
    NAT collapses many hosts into one, rotation splits one actor across many,
    and an imported corpus may store a pseudonymised token. This reports what
    was observed, not who it was.
    """
    return found(svc.investigate_ip(ip, since, instance), "ip")


@router.get("/investigations/ioc/{ioc:path}", summary="Investigate an indicator",
            tags=["investigations"])
def investigate_ioc(ioc: str, since: str = SINCE, instance: str = INSTANCE):
    """Which sessions referenced an indicator, what they did, and what the
    pipeline concluded about them."""
    return found(svc.investigate_ioc(ioc, since, instance), "ioc")
