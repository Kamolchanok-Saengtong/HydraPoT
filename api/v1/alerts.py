from fastapi import APIRouter, Query

from api import services as svc
from api.v1.params import SINCE, INSTANCE, LIMIT, OFFSET, found

router = APIRouter()


@router.get("/alerts", summary="Alert queue", tags=["alerts"])
def list_alerts(state: str = Query(None, description="new | acknowledged | closed"),
                severity: str = Query(None,
                                      description="info | low | medium | high | critical"),
                instance: str = INSTANCE, since: str = SINCE,
                limit: int = LIMIT, offset: int = OFFSET):
    """The existing alert lifecycle.

    This API READS the queue; it sets no policy of its own. Which detections
    become alerts is decided by alert_rules.yml, and that file stays
    authoritative.

    `since` bounds the ITEMS only. `counts` stays whole-queue: a poller asking
    for the last 15 minutes still needs to know how many alerts are open
    overall, and silently shrinking that number would read as alerts having
    been closed.
    """
    return {**svc.list_alerts(state, severity, instance, since, limit, offset),
            "counts": svc.alert_counts(instance)}


@router.get("/alerts/{alert_id:path}", summary="One alert, in full",
            tags=["alerts"])
def get_alert(alert_id: str, since: str = SINCE, instance: str = INSTANCE):
    """Enough for an analyst or an AI agent to act on, in one call: identity,
    state, severity and the rules that produced it, the correlation it came
    from, MITRE mapping, the member sessions in full, and evidence with
    provenance.

    Preserves Detection -> Severity -> Alert as three distinct things rather
    than flattening them into a single verdict.
    """
    return found(svc.investigate_alert(alert_id, since, instance), "alert")
