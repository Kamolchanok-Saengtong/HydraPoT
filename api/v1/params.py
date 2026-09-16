"""
api/v1/params.py — query parameters and error behaviour shared by v1 routes.

Declared once so every collection documents the SAME conventions in the
generated OpenAPI schema. An integrator learns `since`, `limit` and `offset`
once and they mean the same thing on every endpoint.
"""
from fastapi import HTTPException, Query

SINCE = Query(None, description="Time window: 15m, 1h, 24h, 7d, all. Measured "
                                "back from the newest event that EXISTS, not "
                                "from now -- a historical capture would "
                                "otherwise return an empty window.")
INSTANCE = Query(None, description="Sensor instance name, or 'all'.")
LIMIT = Query(50, ge=1, le=500, description="Page size.")
OFFSET = Query(0, ge=0, description="Page offset.")


def found(value, what: str):
    """404 naming the resource.

    An integrator debugging a call needs to know WHICH id failed, not merely
    that something did.
    """
    if value is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return value
