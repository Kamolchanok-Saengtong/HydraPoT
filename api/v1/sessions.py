from fastapi import APIRouter, Query

from api import services as svc
from api.v1.params import SINCE, INSTANCE, LIMIT, OFFSET, found

router = APIRouter()


@router.get("/sessions", summary="Sessions for a window", tags=["sessions"])
def list_sessions(since: str = SINCE, instance: str = INSTANCE,
                  src_ip: str = Query(None),
                  technique: str = Query(None, description="ATT&CK technique id"),
                  tactic: str = Query(None, description="ATT&CK tactic name"),
                  min_fi: int = Query(None, ge=0, le=4,
                                      description="OPERATIONAL filter only. FI is "
                                                  "HydraPoT's routing metric -- it "
                                                  "decides which agent answered a "
                                                  "command -- and is NOT security "
                                                  "severity."),
                  limit: int = LIMIT, offset: int = OFFSET):
    """Session rollups from the aggregation layer.

    min_fi is a legitimate investigation filter ("show me the sessions that
    drew the most interaction"). It never orders results and never appears as
    severity.
    """
    return svc.list_sessions(since, instance, src_ip, technique, tactic,
                             min_fi, limit, offset)


@router.get("/sessions/{session_id}",
            summary="One session's investigation context", tags=["sessions"])
def get_session(session_id: str, instance: str = INSTANCE):
    """Metadata, timeline, commands and MITRE mapping, from the existing
    aggregation logic.

    FI, the selected agent and latency appear under `operational` on each
    command: they describe how the HONEYPOT responded, not what the attacker
    did.
    """
    return found(svc.get_session(session_id, instance), "session")


@router.get("/sessions/{session_id}/related", summary="Related activity",
            tags=["sessions"])
def related(session_id: str, since: str = SINCE, instance: str = INSTANCE):
    """Relationships this session takes part in, from the correlation engine.

    Each carries the engine's own statement and whether a detection rule
    surfaced it, so a consumer can tell "this was correlated" from "this was
    considered worth showing".
    """
    return svc.related_sessions(session_id, since, instance)
