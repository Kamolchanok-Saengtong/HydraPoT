from fastapi import APIRouter, HTTPException, Query

from api import services as svc
from api.v1.params import SINCE, INSTANCE, LIMIT, OFFSET, found

router = APIRouter()

BUCKETS = ("detections", "suppressed", "unmatched", "all")


@router.get("/detections", summary="Detections for a window", tags=["detections"])
def list_detections(since: str = SINCE, instance: str = INSTANCE,
                    severity: str = Query(None),
                    bucket: str = Query("detections",
                                        description=
                                        "Which stage of the detection engine to "
                                        "read. detections = a rule matched "
                                        "(the default). suppressed = a rule "
                                        "matched and a suppression rule filtered "
                                        "it; readable so the filtering is "
                                        "auditable. unmatched = no rule claimed "
                                        "the relationship, which is NOT a finding "
                                        "of benign. all = the three concatenated, "
                                        "each item still carrying its own "
                                        "`bucket`, for a consumer that wants the "
                                        "whole window in one call."),
                    limit: int = LIMIT, offset: int = OFFSET):
    """Output of the existing detection engine, with severity already applied.

    All three buckets are reachable. `unmatched` means no detection rule
    claimed the relationship -- it is NOT a finding of benign. Suppressed
    findings stay readable so a reviewer can audit what was filtered out and
    why, which is the whole reason detection returns them.
    """
    if bucket not in BUCKETS:
        raise HTTPException(422, f"bucket must be one of {list(BUCKETS)}")
    return svc.list_detections(since, instance, severity, bucket, limit, offset)


@router.get("/detections/{detection_id:path}",
            summary="One detection with evidence", tags=["detections"])
def get_detection(detection_id: str, since: str = SINCE,
                  instance: str = INSTANCE):
    """The full reasoning chain: correlation statement, the detection rule that
    surfaced it, the severity rules that rated it, MITRE mapping, and evidence
    items each carrying their own provenance."""
    return found(svc.get_detection(detection_id, since, instance), "detection")
