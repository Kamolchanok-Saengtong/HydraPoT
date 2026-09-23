from fastapi import APIRouter

from api import services as svc
router = APIRouter()


@router.get("/health", summary="Operational health", tags=["service"])
def health():
    """Is HydraPoT working, and if not, WHAT do I go and fix? NOT threat
    intelligence, and deliberately not a resource dashboard.

    `status` is driven only by the components HydraPoT needs to do its job:
    the database, the SSH front door, the alert sweeper, and at least one
    working agent. Disk pressure, a quiet window and an optional exporter
    being off are reported as facts, never as faults -- a status light that
    goes red for a configuration choice is one people learn to ignore.

    Every dependency carries a `checks` field naming what was actually
    verified. A TCP connect proves Cowrie is listening, not that the shell
    behind it works; weights on disk do not prove a model is loaded. Saying
    so is what keeps this from being the hardcoded green light it replaced.

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
