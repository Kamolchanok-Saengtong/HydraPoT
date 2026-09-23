"""
api/services/system.py — operational health and feature discovery.

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

import shutil
from datetime import datetime

import storage
from threat_intel import correlation, detection, severity

# Above this, a honeypot that is "up" is not actually collecting anything, so
# the endpoint says so. Not a hard failure: the internet being quiet and the
# SSH listener being wedged look identical from here, and only a human can
# tell them apart.
STALE_AFTER_SEC = 3600

# A sweep runs every SWEEP_INTERVAL_SEC (300). Three missed sweeps is a dead
# thread, not a slow one.
SWEEP_STALE_AFTER_SEC = 900

DISK_WARN_PERCENT = 90

# Without these HydraPoT is not doing its job: no front door, nowhere to write,
# or nothing turning findings into alerts.
REQUIRED = ("database", "honeypot", "sweeper")

# At least one of these must work or no attacker gets an answer. WHICH one is
# a routing decision, not a health question -- a deployment that deliberately
# runs Cowrie-only is healthy.
AGENTS = ("cowrie", "on_device", "cloud")

# Everything else is an optional integration. A SIEM exporter that is switched
# off is a configuration choice, and a status light that goes red for a choice
# is a status light people learn to ignore.


def health() -> dict:
    """Is HydraPoT working, and if not, WHAT do I go and fix?

    Deliberately not a resource dashboard. CPU and GPU percentages are
    metrics -- you graph them and alert on a trend. This is polled every few
    seconds to answer one question, so everything here is something an
    operator could act on the moment they read it.

    The failure this exists for: Cowrie dies, the database stays fine, and a
    status built only on the database keeps answering "healthy" while the
    honeypot silently collects nothing.

    No configuration, no filesystem paths and no credentials -- a monitoring
    system polls this, often unauthenticated.
    """
    db_ok, rows, sessions = True, None, None
    try:
        st = storage.stats()
        rows, sessions = st.get("rows"), st.get("sessions")
    except Exception:
        db_ok = False

    newest = None
    try:
        _, newest = storage.time_bounds()
    except Exception:
        pass

    inst = _instance()
    deps = _dependencies(db_ok, inst)
    silence = _seconds_since(newest)

    # Disk pressure and a quiet window stay facts, not faults: a busy box is
    # not a broken one, and a honeypot nobody attacked today is working fine.
    broken = [n for n in REQUIRED if not deps.get(n, {}).get("ok")]
    if not any(deps.get(n, {}).get("ok") for n in AGENTS):
        broken.append("agents")
    return {
        "status": "healthy" if db_ok and not broken else "degraded",
        "api_version": "v1",
        "database": "ok" if db_ok else "unavailable",
        "events": rows,
        "sessions": sessions,
        "latest_event": newest,
        "seconds_since_last_event": silence,
        "collecting": silence is not None and silence < STALE_AFTER_SEC,
        "degraded_components": broken,
        "dependencies": deps,
        "disk": _disk(),
        "recent": {
            "cowrie_fallbacks_1h": storage.counter_total(
                "cowrie_fallback", hours=1, instance=inst),
            "cowrie_fallbacks_24h": storage.counter_total(
                "cowrie_fallback", hours=24, instance=inst),
        },
    }


def _instance() -> str:
    """The sensor name this process is reading for.

    The heartbeat and counter rows are keyed by instance, and the honeypot
    writes them under config.honeypot.instance_name. Reading them under a
    hardcoded "default" works on a single-sensor box and silently reports
    "never reported" on every named one -- which is exactly the deployment
    this endpoint exists for.
    """
    try:
        from config_loader import load_config
        return getattr(load_config().honeypot, "instance_name", "default") or "default"
    except Exception:
        return "default"


def _seconds_since(stamp) -> int:
    """Age of the newest event, against the WALL CLOCK.

    Every other window in this API is anchored on the newest event that
    exists, because the database spans 2019 to today. This one is the
    exception on purpose: "are we collecting right now" is the one question
    where an imported corpus SHOULD read as silent.
    """
    if not stamp:
        return None
    try:
        return int((datetime.now() - datetime.fromisoformat(stamp)).total_seconds())
    except (TypeError, ValueError):
        return None


def _dependencies(db_ok: bool, instance: str = "default") -> dict:
    """What each component is, and what we actually verified about it.

    `checks` is not decoration. A TCP connect proves Cowrie is listening; it
    does not prove the shell behind it works. Weights on disk do not prove a
    model is loaded. Reporting the probe alongside the verdict is what stops
    this becoming the hardcoded green light it replaced.
    """
    from SIEM.data import agent_health

    probes = {
        "Honeypot":    ("honeypot", "ssh port accepting connections"),
        "Cowrie Agent": ("cowrie", "tcp connect to the container"),
        "Local LLM":   ("on_device", "enabled and weights present on disk"),
        "Cloud LLM":   ("cloud", "enabled and api key present in environment"),
        "SIEM Export": ("siem_export", "an export plugin is configured and on"),
    }

    out = {"database": {
        "ok": db_ok and storage.db_writable(),
        "checks": "readable and writable",
        # Readable but not writable is the outage that looks like health:
        # every SELECT works, every INSERT is lost.
        "detail": "ok" if db_ok else "unavailable",
    }}

    try:
        rows = agent_health()
    except Exception:
        rows = []
    for name, ok, detail in rows:
        if name in probes:
            key, checks = probes[name]
            out[key] = {"ok": bool(ok), "checks": checks, "detail": detail}

    # Work that runs on a timer in the OTHER process. Its heartbeat is the
    # only evidence the API has that the thread is still alive.
    for component, stale_after in (("sweeper", SWEEP_STALE_AFTER_SEC),):
        beat = storage.read_health(instance).get(component)
        if beat is None:
            out[component] = {"ok": None, "checks": "last heartbeat",
                              "detail": "never reported -- honeypot not started?"}
        else:
            fresh = beat["age_sec"] is not None and beat["age_sec"] < stale_after
            out[component] = {
                "ok": bool(beat["ok"]) and fresh,
                "checks": "last heartbeat",
                "detail": beat["detail"] if fresh
                          else f"stale: last ran {beat['age_sec']}s ago",
                "age_sec": beat["age_sec"],
            }
    return out


def _disk() -> dict:
    """Free space where the database lives, as PERCENTAGES ONLY.

    No mount path: this endpoint is polled unauthenticated and a path is
    infrastructure detail. Retention ships off (retention_days: 0), so on a
    long-running sensor this number only goes up -- which is exactly why it
    is worth reporting.
    """
    import os
    try:
        usage = shutil.disk_usage(os.path.dirname(storage.DB_PATH))
    except Exception:
        return {"percent_used": None, "warn": False}
    percent = round(usage.used / usage.total * 100, 1) if usage.total else None
    return {
        "percent_used": percent,
        "free_gb": round(usage.free / 1e9, 1),
        "warn": percent is not None and percent >= DISK_WARN_PERCENT,
    }


def capabilities() -> dict:
    """What this deployment can actually do, READ FROM THE RULESETS.

    Deliberately not a hardcoded list of trues: a feature is reported as
    available when the rules that implement it load. If someone empties
    detection_rules.yml, `detection` reports false rather than advertising a
    capability that will return nothing.
    """
    from threat_intel import alert_records, normalize
    from api.services import export

    def _count(fn, *a):
        try:
            return len(fn(*a))
        except Exception:
            return 0

    strategies = _count(correlation.load_strategies)
    det_rules = _count(detection.load_rules)
    sev_rules = _count(severity.load_rules)
    alert_rules = _count(alert_records.load_rules)
    sinks = sorted(alert_records.load_sinks().keys())

    return {
        "api_version": "v1",
        "features": {
            "mitre": True,
            "ioc": True,
            "correlation": strategies > 0,
            "detection": det_rules > 0,
            "severity": sev_rules > 0,
            "alerting": alert_rules > 0,
            "investigation": True,
            "websocket": True,
        },
        "rules": {
            "correlation_strategies": strategies,
            "detection_rules": det_rules,
            "severity_rules": sev_rules,
            "alert_rules": alert_rules,
        },
        "correlation_types": [s["id"] for s in correlation.load_strategies()],
        "severity_levels": list(severity.SEVERITY_ORDER),
        "alert_states": list(storage.ALERT_STATES),
        # Read from the export service, not retyped. This list used to be a
        # literal advertising four formats no v1 route served -- an integrator
        # was told a capability existed and found nothing to call.
        "export_formats": sorted(export.FORMATS),
        "export_classes": sorted(export.CLASSES),
        "export_endpoint": "/api/v1/export",
        "ocsf_version": normalize.OCSF_VERSION,
        # Which sinks are ENABLED, so an integrator can see whether anything is
        # being forwarded. Never the destinations -- those are credentials.
        "enabled_alert_sinks": sinks,
        "time_windows": ["15m", "1h", "24h", "7d", "all"],
    }


