from fastapi import APIRouter, Query

from api import services as svc
from api.v1.params import SINCE, INSTANCE, LIMIT, OFFSET, found

router = APIRouter()


@router.get("/threats/mitre", summary="ATT&CK activity", tags=["threats"])
def mitre(since: str = SINCE, instance: str = INSTANCE):
    """Tactic and technique distribution, with tagging coverage.

    Coverage matters: it says how much of the window the rules could read at
    all, so a small technique count is distinguishable from a quiet window.
    """
    return svc.mitre_activity(since, instance)


@router.get("/threats/mitre/{technique_id}", summary="One ATT&CK technique",
            tags=["threats"])
def mitre_technique(technique_id: str, since: str = SINCE,
                    instance: str = INSTANCE):
    """Where this technique was observed: sessions, detections, alerts and the
    indicators that appeared alongside it."""
    return found(svc.mitre_technique(technique_id, since, instance), "technique")


@router.get("/threats/iocs", summary="Indicators of compromise", tags=["threats"])
def list_iocs(since: str = SINCE, instance: str = INSTANCE,
              type: str = Query(None, description="url | ipv4 | domain | hash | ..."),
              limit: int = LIMIT, offset: int = OFFSET):
    """Indicators extracted from command text and responses.

    CREDENTIAL indicators are excluded: those are attacker-submitted passwords
    and this API is not a credential feed. /overview still counts them -- a
    count is not a disclosure.
    """
    return svc.list_iocs(since, instance, type, limit, offset)


@router.get("/threats/iocs/{ioc:path}", summary="One indicator, with context",
            tags=["threats"])
def get_ioc(ioc: str, since: str = SINCE, instance: str = INSTANCE):
    """Accepts "type:value" or a bare value."""
    return found(svc.get_ioc(ioc, since, instance), "ioc")


@router.get("/threats/categories", summary="Activity categories", tags=["threats"])
def categories(since: str = SINCE, instance: str = INSTANCE):
    """Category counts as defined in config.yaml's aggregation.categories.
    No category is invented for the API."""
    return svc.categories(since, instance)
