"""
api/v1 — HydraPoT REST API version 1.

    HTTP  ->  api/v1/<resource>.py  ->  api/services/  ->  HydraPoT pipeline

WHY THE VERSION IS A PACKAGE, NOT A FILE. `/api/v1` is a public contract: once
an external SIEM or an AI agent is built against it, changing a response shape
breaks them silently. So v1 lives in its own package and STOPS CHANGING in ways
that break consumers. A future v2 becomes api/v2/, mounted alongside, importing
the SAME api/services -- so the two versions can differ in shape but can never
disagree about what HydraPoT actually found.

That split is the point: routes are versioned, security logic is not.

Routes are thin by design -- parse parameters, call one service, shape the
error. A handler that grows an `if` about security meaning belongs in a service
or in the domain module that already owns the question.
"""
from fastapi import APIRouter, Depends

from api.auth import require_api_key
from api.v1 import (alerts, correlations, detections, export,
                    overview, sessions, system, threats)

API_VERSION = "v1"
PREFIX = f"/api/{API_VERSION}"

# The key is checked on the ROUTER, not on each route: a resource module added
# later is protected by existing. See api/auth.py -- off until a key is set.
router = APIRouter(prefix=PREFIX, dependencies=[Depends(require_api_key)])
for _module in (system, overview, alerts, detections, correlations, sessions,
                threats, export):
    router.include_router(_module.router)

__all__ = ["router", "API_VERSION", "PREFIX"]
