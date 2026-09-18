"""
api/v1/export.py — the normalized export route.

One endpoint for every class and every wire format. Named /export, not /ocsf:
OCSF is the canonical shape INSIDE, but this route also serves CEF and ECS, and
naming it after one of the four formats it emits made the other three look like
they were somewhere else.

See api/services/export.py for why this is not one route per class.
"""
from fastapi import APIRouter, HTTPException, Query

from api.services.export import CLASSES, FORMATS, ocsf as _ocsf
from api.v1.params import SINCE, INSTANCE, LIMIT, OFFSET

router = APIRouter()


@router.get("/export", summary="Normalized security telemetry", tags=["export"])
def ocsf(cls: str = Query("finding", alias="class",
                          description="process | auth | finding"),
         format: str = Query("ocsf", description="ocsf | json | cef | ecs"),
         since: str = SINCE, instance: str = INSTANCE,
         limit: int = LIMIT, offset: int = OFFSET):
    """HydraPoT's telemetry in a schema another vendor's tooling already parses.

    `class` picks which records, `format` picks how they are rendered:

        process   commands typed        OCSF Process Activity   1007
        auth      login attempts        OCSF Authentication     3002
        finding   the analysed output   OCSF Detection Finding  2004

        ocsf/json  the canonical event
        cef        CEF:0, for syslog collectors
        ecs        Elastic Common Schema

    `finding` is the one that matters: correlation evidence, the detection rule
    that surfaced it, the severity the severity layer assigned, MITRE
    technique/tactic and the alert's lifecycle state -- the analysis, not just
    the raw commands.

    SEVERITY NEVER COMES FROM FI. FI is HydraPoT's routing metric and travels in
    `unmapped.hydrapot`; raw telemetry exports severity_id 0 (Unknown) because
    nothing has assessed it yet.
    """
    if cls not in CLASSES:
        raise HTTPException(422, f"class must be one of {sorted(CLASSES)}")
    if format not in FORMATS:
        raise HTTPException(422, f"format must be one of {sorted(FORMATS)}")
    return _ocsf(cls, format, since, instance, limit, offset)
