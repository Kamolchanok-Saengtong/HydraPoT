"""
api/v1/bridge.py — endpoints the console v2 (Next.js) needs that the original
v1 resources didn't expose yet: the live feed, geo rollup, attention queue,
MITRE tactics, top credentials, the DB schema + read-only query, a STIX bundle,
component health, the AI analyst, and the investigation workbench.

Each route is a thin HTTP shell: parse the query params, call one function in
api.services.console_views, return it. All the shaping, SQL validation and
secret masking live in that service -- see it for how each view is built and why
it matches what the Dash app shows.
"""
from fastapi import APIRouter, Query

from api.services import console_views as cv
from api.v1.params import SINCE, INSTANCE, LIMIT

router = APIRouter()


@router.get("/feed", summary="Live session feed", tags=["console"])
def feed(since: str = SINCE, instance: str = INSTANCE, limit: int = LIMIT):
    return cv.feed(instance, limit, since)


@router.get("/overview/geo", summary="Source geography", tags=["console"])
def geo(since: str = SINCE, instance: str = INSTANCE, limit: int = 500):
    return cv.geo_rollup(instance, limit, since)


@router.get("/overview/queue", summary="Attention queue", tags=["console"])
def queue(since: str = SINCE, instance: str = INSTANCE, limit: int = 20):
    return cv.attention_queue(since, instance, limit)


@router.get("/overview/series", summary="Attack timeline", tags=["console"])
def series(since: str = SINCE, instance: str = INSTANCE):
    return cv.attack_series(since, instance)


# NOT /threats/mitre/tactics: that collides with /threats/mitre/{technique_id}
# (the id route reads "tactics" as a technique id). Its own path instead.
@router.get("/threats/tactics", summary="ATT&CK tactic counts", tags=["console"])
def tactics(since: str = SINCE, instance: str = INSTANCE):
    return cv.tactic_counts(since, instance)


@router.get("/auth/top", summary="Top credentials tried", tags=["console"])
def auth_top(instance: str = INSTANCE, limit: int = 8):
    return cv.top_credentials(instance, limit)


@router.get("/schema", summary="Database schema", tags=["console"])
def schema():
    return cv.db_schema()


@router.get("/query", summary="Read-only SQL", tags=["console"])
def query(sql: str = Query(..., description="A single read-only SELECT. Parsed "
                                            "and run mode=ro; writes/multi-stmt "
                                            "rejected."),
          db: str = Query("capture", description="capture | login")):
    return cv.run_query(sql, db)


@router.get("/threats/stix", summary="STIX 2.1 bundle of IOCs", tags=["console"])
def stix():
    # No instance filter: the IOC extraction layer has no per-sensor scope
    # (console.ioc._scope_filter_rows does all / session / last_24h only), so
    # an `instance` param here would be a silent no-op. Dropped rather than faked.
    return cv.stix_bundle()


@router.get("/agents/health", summary="Component/agent health", tags=["console"])
def agents_health():
    return cv.agent_health_rows()


@router.post("/assistant", summary="Ask the AI security analyst", tags=["console"])
def assistant(payload: dict):
    return cv.ask_assistant(payload)


@router.get("/investigation", summary="Investigation workbench", tags=["console"])
def investigation(since: str = SINCE, instance: str = INSTANCE):
    return cv.investigation(since, instance)
