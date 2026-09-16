from fastapi import APIRouter

from api import services as svc
from api.v1.params import SINCE, INSTANCE, found

router = APIRouter()


@router.get("/correlations/{correlation_id:path}",
            summary="One correlation relationship", tags=["correlations"])
def get_correlation(correlation_id: str, since: str = SINCE,
                    instance: str = INSTANCE):
    """The relationship exactly as the correlation engine produced it.

    `statement` is the engine's own wording and the only sentence a consumer
    should render for it. A shared command sequence means exactly that -- it
    does NOT mean the same attacker, the same operator, or the same campaign,
    and this API does not upgrade it into attribution.
    """
    return found(svc.get_correlation(correlation_id, since, instance),
                 "correlation")
