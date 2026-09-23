"""
api/services/export.py — the normalized export, one stream.

    route  ->  service (here)  ->  threat_intel/normalize.py

ONE ENDPOINT, NOT ONE PER CLASS. This replaced /api/ocsf/events and
/api/ocsf/findings, which were two routes for two of the three classes
normalize.py can produce -- Authentication (3002) had no route at all, because
adding a class meant adding a route and nobody did. OCSF records carry
class_uid and are self-describing, so the class is a FILTER on one stream, not
a separate resource: a SIEM wants one pipe and sorts by class itself.

Adding a fourth class is now a dict entry below.

Nothing here normalizes anything itself -- threat_intel/normalize.py owns every
mapping, and this module only chooses which rows to feed it.
"""

import storage
from threat_intel import normalize
from threat_intel.alert_records import alert_key

from api.services.common import overview, page, pipeline, _inst


# ── what each class reads ───────────────────────────────────────────────────
# Each returns a list of CANONICAL OCSF events. The format conversion below is
# applied afterwards, so every class supports every format automatically.

def _window(since, instance):
    """The same resolved window every other v1 service uses, so an export and a
    /overview for one `since` always describe the same slice of time."""
    win = overview(since, instance)["window"]
    return win["start"], win["end"]


def _process(since, instance):
    """Commands -> Process Activity (1007).

    Harness traffic excluded. This endpoint hands telemetry to somebody else's
    SIEM, so exporting our own replay runs would assert we observed attacks we
    staged -- 83% of the rows in a full window.
    """
    start, end = _window(since, instance)
    rows = storage.real_rows(
        storage.query_range(start, end, instance=_inst(instance)))
    return [normalize.normalize_command(r) for r in rows]


def _auth(since, instance):
    """Logins -> Authentication (3002).

    Exportable for the first time here. normalize_auth() has existed and been
    tested since the normalization layer landed; no route ever called it.
    Passwords are not emitted -- see normalize_auth.
    """
    start, end = _window(since, instance)
    rows = storage.real_rows(
        storage.query_auth_range(start, end, instance=_inst(instance)))
    return [normalize.normalize_auth(r) for r in rows]


def _finding(since, instance):
    """Correlation -> detection -> severity -> Detection Finding (2004).

    Joined to the alert record where one exists, so activity_id reflects
    whether an analyst has acknowledged or closed it.
    """
    result = pipeline(since, instance)
    alerts = {a["alert_key"]: a for a in
              storage.query_alerts(instance=_inst(instance) or "default", limit=2000)}
    return [normalize.normalize_finding(d, alerts.get(alert_key(d)))
            for d in result.get("detections") or []]


CLASSES = {"process": _process, "auth": _auth, "finding": _finding}

# to_json returns the canonical event unchanged; "json" and "ocsf" are the same
# thing and both are accepted because integrators ask for both names.
FORMATS = {"ocsf": normalize.to_json, "json": normalize.to_json,
           "cef": normalize.to_cef, "ecs": normalize.to_ecs}


def ocsf(cls="finding", fmt="ocsf", since=None, instance=None,
         limit=50, offset=0) -> dict:
    """One page of normalized events. Caller validates cls/fmt."""
    events = CLASSES[cls](since, instance)
    convert = FORMATS[fmt]
    return {**page([convert(e) for e in events], limit, offset),
            "class": cls, "format": fmt,
            "ocsf_version": normalize.OCSF_VERSION}
