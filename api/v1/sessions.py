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
                                      description=
                                      "Keep sessions whose highest Fidelity Impact "
                                      "is at least this (0-4). FI is HydraPoT's "
                                      "ROUTING metric: it decides which agent "
                                      "answered a command -- 0 means Cowrie "
                                      "handled it, 4 means the cloud model was "
                                      "worth spending. So this filters by how much "
                                      "interaction a session drew, which is a "
                                      "useful place to start looking. It is NOT "
                                      "security severity, it never orders the "
                                      "results, and it never appears as a rating: "
                                      "severity comes from the severity layer "
                                      "alone."),
                  limit: int = LIMIT, offset: int = OFFSET):
    """Session rollups from the aggregation layer.

    min_fi is a legitimate investigation filter ("show me the sessions that
    drew the most interaction"). It never orders results and never appears as
    severity.
    """
    return svc.list_sessions(since, instance, src_ip, technique, tactic,
                             min_fi, limit, offset)


@router.get("/sessions/{session_id}", summary="One session, in full",
            tags=["sessions"])
def get_session(session_id: str, since: str = SINCE, instance: str = INSTANCE):
    """Everything HydraPoT knows about one session, in one call: metadata,
    commands, MITRE mapping, the correlations it belongs to, the detections
    and alerts that fired on it, the indicators it touched, and evidence with
    provenance.

    One call rather than five. An external analyst -- or an AI agent -- should
    not have to know which HydraPoT module owns which fact, nor stitch the
    join itself and risk getting it wrong.

    Costs ~1ms more than the metadata alone: the correlation and detection
    work is per-WINDOW and cached, so every session in a window shares one
    pipeline run.

    FI, the selected agent and latency appear under `operational`: they
    describe how the HONEYPOT responded, not what the attacker did. Never a
    severity.
    """
    return found(svc.investigate_session(session_id, since, instance), "session")


@router.get("/sources/{ip}", summary="One source address, in full",
            tags=["sources"])
def get_source(ip: str, since: str = SINCE, instance: str = INSTANCE):
    """Everything recorded from one address: its sessions, tactics, indicators
    and detections.

    The response says plainly that an address is not an identity. NAT
    collapses many hosts into one, rotation splits one actor across many, and
    an imported corpus may store a pseudonymised token. This reports what was
    observed, not who it was.
    """
    return found(svc.investigate_ip(ip, since, instance), "source")


# /sessions/{session_id}/related used to live here. The investigation package
# already carries the same correlations alongside the detections and alerts
# that give them meaning, so this was a second door into one room. Retired with
# a 410 in api_server.py; api/services/sessions.related_sessions stays -- the
# investigation is what calls it.
