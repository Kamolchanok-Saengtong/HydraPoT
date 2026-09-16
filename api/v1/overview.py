from fastapi import APIRouter

from api import services as svc
from api.v1.params import SINCE, INSTANCE

router = APIRouter()


@router.get("/overview", summary="High-level security picture", tags=["overview"])
def overview(since: str = SINCE, instance: str = INSTANCE):
    """The existing aggregation result, plus alert counts.

    Activity, timeline, top source addresses, MITRE distribution, IOC counts,
    categories, session statistics and the authentication funnel.

    Authentication and session activity are PARALLEL timelines and are never
    joined: the auth table carries no session_id, so any login-to-session
    mapping would be an invented correlation on (address, time).
    """
    return {**svc.overview(since, instance), "alerts": svc.alert_counts(instance)}
