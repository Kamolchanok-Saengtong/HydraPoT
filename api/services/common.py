"""
api/services/common.py — windows, paging, identity, provenance.

Part of HydraPoT's application layer:

    route  ->  service (here)  ->  existing domain module  ->  storage

VERSION-AGNOSTIC ON PURPOSE. These services are shared by every API version.
api/v1/ shapes them into the v1 contract; a future api/v2/ would reuse the same
functions and change only the response shape. That is what keeps versioning
cheap -- the security logic is never copied per version, so v1 and v2 can never
disagree about what HydraPoT found.

Nothing here re-implements aggregation, correlation, detection, severity or
alerting.
"""

import hashlib
import time

import storage
from threat_intel.alert_records import alert_key

_IOC_TTL = 300.0
_ioc_cache = {}

def resolve_since(since: str = None) -> str:
    """`?since=24h` -> a preset the aggregation layer already understands.

    Presets are measured back from the newest event that EXISTS, not from the
    wall clock -- see aggregator.resolve_window. That matters here: a capture
    from 2019 would return an empty window for every duration if the API
    anchored on now(), and an integrator would reasonably report it as broken.
    """
    if not since:
        return "ALL"
    s = str(since).strip().lower()
    return {"15m": "15m", "1h": "1h", "24h": "24h", "7d": "7d",
            "all": "ALL"}.get(s, "ALL")


def page(items, limit=50, offset=0):
    """One paging envelope for every collection, so a consumer writes the
    pagination loop once."""
    total = len(items)
    limit = max(1, min(int(limit or 50), 500))
    offset = max(0, int(offset or 0))
    return {"items": items[offset:offset + limit], "total": total,
            "limit": limit, "offset": offset,
            "has_more": offset + limit < total}


def _inst(instance):
    return None if instance in (None, "", "all") else instance


# ── pipeline access ─────────────────────────────────────────────────────────

def overview(since=None, instance=None) -> dict:
    """aggregate_overview(), unchanged. THE existing aggregation result."""
    from SIEM.data import load_overview
    return load_overview(preset=resolve_since(since), instance=_inst(instance))


def pipeline(since=None, instance=None) -> dict:
    """correlation -> detection -> severity, for one window.

    Returns detect()'s three buckets with severity annotated. All three are
    kept: `unmatched` does NOT mean benign, it means no detection rule claimed
    it, and an API that returned only `detections` would quietly assert
    otherwise.
    """
    from SIEM.data import load_detections
    return load_detections(preset=resolve_since(since), instance=_inst(instance))


def iocs(since=None, instance=None) -> list:
    """Indicator records for the window, WITHOUT credentials.

    build_iocs() extracts credential pairs from the auth stream -- those are
    attacker-submitted passwords. They are dropped here, once, so no route can
    expose them by forgetting to filter. The IOC count in /overview still
    includes them because that is a count, not the values.
    """
    from threat_intel.ioc_extractor import build_iocs
    key = (resolve_since(since), instance or "all")
    now = time.time()
    hit = _ioc_cache.get(key)
    if hit and (now - hit[1]) < _IOC_TTL:
        return hit[0]

    win = overview(since, instance)["window"]
    rows = storage.query_range(win["start"], win["end"], instance=_inst(instance))
    # BOTH streams, matching what aggregate_overview() counts. Passing only
    # session rows made /threats/iocs list 99 indicators while /overview
    # reported 12,291 for the same window -- the auth stream is where
    # credential indicators come from, and omitting it is not a privacy
    # control, just an inconsistency.
    auth = storage.query_auth_range(win["start"], win["end"],
                                    instance=_inst(instance))
    recs = [r for r in build_iocs(rows, auth).records()
            if r.get("type") != "credential"]
    _ioc_cache[key] = (recs, now)
    return recs


# ── identity ────────────────────────────────────────────────────────────────

def detection_id(det) -> str:
    return alert_key(det)


def correlation_id(rel) -> str:
    return f"{rel.get('link_type')}:{rel.get('link_value')}"


def _evidence_id(*parts) -> str:
    """A short, stable handle for one evidence item, so a consumer can refer
    back to it ("evidence e3f91c said...") without repeating the whole object."""
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


