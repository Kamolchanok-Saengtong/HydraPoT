from fastapi import APIRouter

from api import services as svc
router = APIRouter()


@router.get("/health", summary="Operational health", tags=["service"])
def health():
    """Whether the system is running. NOT threat intelligence.

    Carries no configuration, no filesystem paths and no credentials -- this is
    the endpoint a monitoring system polls, often unauthenticated.
    """
    return svc.health()


@router.get("/capabilities", summary="What this deployment supports",
            tags=["service"])
def capabilities():
    """Feature discovery, READ FROM THE RULESETS rather than hardcoded.

    A feature reports true when the rules implementing it actually load, so an
    integrator is never told a capability exists when it would return nothing.
    Also reports the API version, the OCSF version, and which export formats
    the normalization layer can produce.
    """
    return svc.capabilities()
