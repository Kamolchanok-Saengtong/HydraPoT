"""
threat_intel/alert_records.py — which detections become alerts, and where
they go.

The last layer:

    Aggregation -> Correlation -> Detection -> Severity -> ALERTING

Detection decides what an analyst SEES. Alerting decides what a human must ACT
on, and that is a narrower question with a durable consequence: raising an
alert creates a record with a lifecycle that outlives every page render.

NOT to be confused with threat_intel/alert_channels.py. That module delivers
push notifications (Slack/Discord/Telegram/email) for a single high-FI event as
it happens; this one owns the alert RECORD -- its identity, its lifecycle, and
its durable state. Two different meanings of the word "alert", kept in two
files so neither has to compromise.

Three separable jobs, deliberately not merged:

    evaluate()      pure policy — does this detection clear the bar?
    raise_alerts()  persistence — upsert into the alerts table
    route_alerts()  delivery   — hand undelivered alerts to their sinks

Keeping them apart is what makes the layer safe to reason about. evaluate() has
no side effects and is trivially testable. raise_alerts() writes but never
sends. route_alerts() sends but never decides. A bug in delivery can therefore
never lose an alert record, and a bug in policy can never half-send anything.

WHAT THIS LAYER NEVER DOES
  * Invent a severity. It reads the level severity.py produced, and UNRATED is
    a real answer it must not launder into a number.
  * Auto-close anything. An alert leaves the queue when a person says so.
    "It stopped appearing" is indistinguishable from "we lost it".
  * Mark something delivered that was not. routed_at is stamped only after a
    sink reports success, so a failed send leaves the alert to be retried.
  * Send anywhere by default. Every network sink ships disabled; see
    alert_sinks.yml for why that is a deliberate disclosure decision.
"""
import json
import os

import yaml

from threat_intel.severity import SEVERITY_ORDER

_HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(_HERE, "rules", "alert_rules.yml")
SINKS_PATH = os.path.join(_HERE, "rules", "alert_sinks.yml")
_ROOT = os.path.dirname(_HERE)

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
UNRATED = "unrated"

# Every condition alerting.py knows how to evaluate. Anything else is skipped
# LOUDLY at load time: a typo'd condition that matches nothing looks exactly
# like "nothing warranted an alert", which is the most dangerous possible
# failure mode for this particular layer.
_CONDITIONS = {"min_severity", "severity_in", "detection_rule_in",
               "link_type_in", "min_members", "min_distinct_sources",
               "min_distinct_scopes"}

# Keyed by path — same fix as correlation/detection/severity, where a single
# global slot made the `path` argument silently ignored after the first load.
_rules = {}
_rule_errors = {}
_sinks = {}


# ── rules ───────────────────────────────────────────────────────────────────

def load_rules(path: str = RULES_PATH, force: bool = False) -> list:
    """Parse and validate alert_rules.yml. Cached per path."""
    if path in _rules and not force:
        return _rules[path]

    rules, errors = [], []
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[alerting] cannot read {path}: {e}")
        _rules[path], _rule_errors[path] = [], [(os.path.basename(path), str(e))]
        return _rules[path]

    for raw in (doc.get("rules") or []):
        rid = raw.get("id", "<no id>")
        try:
            when = raw.get("when") or {}
            if not when:
                raise ValueError("rule has no `when` conditions")
            unknown = set(when) - _CONDITIONS
            if unknown:
                raise ValueError(f"unknown condition(s): {sorted(unknown)}")
            ms = when.get("min_severity")
            if ms is not None and ms not in _SEVERITY_RANK:
                raise ValueError(f"min_severity must be one of "
                                 f"{list(SEVERITY_ORDER)}, got {ms!r}")
            for lvl in (when.get("severity_in") or []):
                if lvl not in _SEVERITY_RANK and lvl != UNRATED:
                    raise ValueError(f"severity_in has unknown level {lvl!r}")
            description = (raw.get("description") or "").strip()
            if not description:
                raise ValueError("rule has no `description` to justify alerting")
            rules.append({
                "id": rid,
                "title": raw.get("title", rid),
                "description": description,
                "when": when,
                # Absent means "record it, never send it" -- a legitimate rule,
                # not a misconfiguration, so it is not an error.
                "notify": list(raw.get("notify") or []),
            })
        except Exception as e:
            errors.append((rid, str(e)))
            print(f"[alerting] skipping rule {rid}: {e}")

    seen = set()
    for r in rules:
        if r["id"] in seen:
            errors.append((r["id"], "duplicate rule id"))
            print(f"[alerting] WARNING: duplicate rule id {r['id']}")
        seen.add(r["id"])

    _rules[path], _rule_errors[path] = rules, errors
    return rules


def load_errors(path: str = RULES_PATH) -> list:
    load_rules(path)
    return _rule_errors.get(path, [])


def _fires(when: dict, det: dict) -> bool:
    """Every condition must hold (AND). Reads only what the layers below
    already established."""
    rel = det.get("relationship") or {}
    sev = det.get("severity")

    if "min_severity" in when:
        # UNRATED can never satisfy a threshold. It is the absence of a level,
        # not a low one, and treating "we could not tell" as "at least medium"
        # would fill the queue with exactly the findings we understand least.
        if sev is None or _SEVERITY_RANK[sev] < _SEVERITY_RANK[when["min_severity"]]:
            return False

    if "severity_in" in when:
        if (sev or UNRATED) not in set(when["severity_in"]):
            return False

    if "detection_rule_in" in when:
        fired = {r.get("id") for r in (det.get("rules") or [])}
        if not fired & set(when["detection_rule_in"]):
            return False

    if "link_type_in" in when:
        if rel.get("link_type") not in set(when["link_type_in"]):
            return False

    if "min_members" in when:
        if rel.get("member_count", 0) < when["min_members"]:
            return False
    if "min_distinct_sources" in when:
        if rel.get("distinct_sources", 0) < when["min_distinct_sources"]:
            return False
    if "min_distinct_scopes" in when:
        if len(rel.get("scope") or ()) < when["min_distinct_scopes"]:
            return False

    return True


def evaluate(detection: dict, path: str = RULES_PATH) -> list:
    """Which alert rules this detection clears. PURE — no writes, no sends.

    Returns every matching rule, not just the first: an alert that fires three
    rules is more explainable than one that fires one, and the reasons are
    shown to the analyst.
    """
    return [r for r in load_rules(path) if _fires(r["when"], detection)]


def alert_key(detection: dict) -> str:
    """Stable identity for a detection across recomputation.

    Everything upstream is rebuilt on every window load, so an alert keyed on
    anything generated (a row id, a hash of the rendered view, a counter) would
    produce a NEW alert every refresh and make acknowledgement meaningless.
    Each part here is derived from the data: the detection rule, the
    correlation strategy, and the strategy's own key value -- a sha1 of the
    command sequence, or "type:value", or the source address.
    """
    rel = det_rel(detection)
    rules = detection.get("rules") or []
    rid = rules[0].get("id") if rules else "none"
    return f"{rid}|{rel.get('link_type')}|{rel.get('link_value')}"


def det_rel(detection: dict) -> dict:
    return detection.get("relationship") or {}


# ── persistence ─────────────────────────────────────────────────────────────

def raise_alerts(detect_result: dict, instance: str = "default",
                 path: str = RULES_PATH, db_path: str = None) -> dict:
    """Promote qualifying detections to alerts. Writes, never sends.

    -> {"new": [alert, ...], "updated": [...], "evaluated": int}

    Only the `detections` bucket is considered. A suppressed relationship was
    deliberately kept off the analyst's screen, so promoting it to something
    that interrupts them would contradict the decision the detection layer just
    made -- while still being rated and findable, which is what the suppressed
    bucket is for.
    """
    import storage
    kw = {"path": db_path} if db_path else {}

    new, updated = [], []
    dets = (detect_result or {}).get("detections") or []
    for det in dets:
        fired = evaluate(det, path=path)
        if not fired:
            continue
        rel = det_rel(det)
        rules = det.get("rules") or []
        record = {
            "instance": instance,
            "alert_key": alert_key(det),
            "alert_rule": fired[0]["id"],
            "detection_rule": rules[0].get("id") if rules else None,
            "link_type": rel.get("link_type"),
            "link_value": rel.get("link_value"),
            "title": fired[0]["title"],
            "severity": det.get("severity"),      # None stays None
            "member_count": rel.get("member_count"),
            "distinct_sources": rel.get("distinct_sources"),
            "first_seen": rel.get("first_seen"),
            "last_seen": rel.get("last_seen"),
        }
        outcome = storage.upsert_alert(record, **kw)
        record["matched_rules"] = fired
        (new if outcome == "inserted" else updated).append(record)

    return {"new": new, "updated": updated, "evaluated": len(dets)}


def sweep(instance: str = "default", db_path: str = None,
          exclude_row=None, plugins=None) -> dict:
    """Run the analysis once and deliver whatever it raises.

    correlation -> detection -> severity -> raise_alerts -> route_alerts,
    over everything currently in storage.

    EXISTS BECAUSE NOTIFICATIONS MUST NOT DEPEND ON THE DASHBOARD. Alert
    records were only ever raised by SIEM/data.py's load_detections(), i.e. by
    someone having a browser open. That was fine while main.py also notified
    per command on FI -- there was always a live path. With that removed, a
    sensor running headless would have raised nothing and paged nobody, which
    is a worse failure than the FI behaviour it replaced.

    Deliberately NOT importing SIEM/: that package pulls in Dash, and the
    honeypot process must not depend on a web framework to send an alert.
    The cost is a few lines of pipeline wiring duplicated from
    SIEM/data.load_detections -- worth it to keep the dependency out.

    `exclude_row` is the caller's policy for what counts as real traffic, the
    same hook aggregate_overview takes.
    """
    import storage
    from threat_intel import correlation, detection, severity
    from threat_intel.ioc_extractor import build_iocs

    lo, hi = storage.time_bounds(instance=None if instance == "all" else instance)
    if not lo or not hi:
        return {"new": [], "updated": [], "evaluated": 0, "routed": None}

    rows = storage.query_range(lo, hi,
                               instance=None if instance == "all" else instance)
    if exclude_row is not None:
        rows = [r for r in rows if not exclude_row(r)]

    rels = correlation.correlate(sessions=correlation.sessions_from_rows(rows),
                                 indicators=build_iocs(rows).records())
    rated = severity.rate_detections(detection.detect(rels))

    raised = raise_alerts(rated, instance=instance, db_path=db_path)

    # Push NEW findings to the configured SIEM exporters as OCSF Detection
    # Findings. Only new ones: an alert whose counts merely refreshed is not a
    # new finding, and re-emitting it every sweep would make the same detection
    # appear repeatedly in Splunk.
    #
    # Needs the DETECTION, not just the stored alert row -- the row carries
    # counts and state, while the MITRE chain, the correlation evidence and the
    # member sessions live on the detection. Re-keyed here by alert_key, which
    # both sides derive the same way.
    if plugins is not None and raised["new"]:
        by_key = {alert_key(d): d for d in rated.get("detections", [])}
        for rec in raised["new"]:
            det = by_key.get(rec["alert_key"])
            if det is not None:
                try:
                    plugins.export_finding(det, rec)
                except Exception as e:
                    print(f"[alert] finding export failed: {e}")

    raised["routed"] = route_alerts(instance=instance, db_path=db_path)
    return raised


# ── delivery ────────────────────────────────────────────────────────────────

def load_sinks(path: str = SINKS_PATH, force: bool = False) -> dict:
    """{name: sink_config} for ENABLED sinks only.

    Disabled sinks are dropped here rather than checked at send time, so there
    is exactly one place that decides whether a sink is live.
    """
    if path in _sinks and not force:
        return _sinks[path]
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[alerting] cannot read {path}: {e}")
        _sinks[path] = {}
        return _sinks[path]
    for raw in (doc.get("sinks") or []):
        if raw.get("enabled") and raw.get("name"):
            out[raw["name"]] = raw
    _sinks[path] = out
    return out


def _send_jsonl(sink, alert) -> bool:
    """Append one JSON object per line. The default sink: local, no network,
    no credentials, and already readable by every log shipper."""
    target = sink.get("path") or "data/logs/alerts.jsonl"
    if not os.path.isabs(target):
        target = os.path.join(_ROOT, target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, default=str, ensure_ascii=False) + "\n")
    return True


def _send_webhook(sink, alert) -> bool:
    """POST one alert. urllib rather than requests: this must work in a minimal
    deployment without adding a dependency for a sink most users never enable."""
    import urllib.request
    url = sink.get("url")
    if not url:
        return False
    data = json.dumps(alert, default=str).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **(sink.get("headers") or {})})
    with urllib.request.urlopen(req, timeout=sink.get("timeout_sec", 5)) as resp:
        return 200 <= resp.status < 300


def _send_syslog(sink, alert) -> bool:
    import socket
    host, port = sink.get("host"), int(sink.get("port", 514))
    if not host:
        return False
    facility = int(sink.get("facility", 13))
    # severity 4 = warning; an alert is not an emergency by default and
    # claiming otherwise would make the priority field useless.
    pri = facility * 8 + 4
    msg = f"<{pri}>HydraPoT {json.dumps(alert, default=str)}".encode("utf-8")
    proto = (sink.get("protocol") or "udp").lower()
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as s:
        s.settimeout(5)
        if proto == "tcp":
            s.connect((host, port))
            s.sendall(msg)
        else:
            s.sendto(msg, (host, port))
    return True


def _send_channels(sink, alert) -> bool:
    """Push to the human notification channels (Slack/Discord/Telegram/email).

    A sink like any other, so WHICH findings page a human is decided in
    alert_rules.yml alongside every other routing decision -- not by a separate
    threshold in alerts.yml that could disagree with it. alert_channels.py owns
    formatting and delivery; it does not re-judge the finding.
    """
    from threat_intel.alert_channels import AlertManager
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager(sink["config"]) if sink.get("config") else AlertManager()
    results = _alert_manager.notify(alert)
    if not results:
        return False        # no channel enabled -> not delivered, so not stamped
    return all(v == "sent" for v in results.values())


_alert_manager = None       # built once; AlertManager parses alerts.yml on init

SENDERS = {"jsonl": _send_jsonl, "webhook": _send_webhook, "syslog": _send_syslog,
           "channels": _send_channels}


def route_alerts(alerts=None, instance: str = "default",
                 path: str = RULES_PATH, sinks_path: str = SINKS_PATH,
                 db_path: str = None) -> dict:
    """Deliver alerts that have never been delivered. Sends, never decides.

    -> {"sent": [(alert_key, sink), ...], "failed": [(alert_key, sink, err)],
        "skipped": [(alert_key, sink_name)]}

    `alerts` defaults to every unrouted alert in the table, so a sink that was
    down or switched off later catches up instead of losing what it missed.

    routed_at is stamped only when EVERY sink a rule named succeeded. A partial
    delivery stays unrouted and is retried -- duplicate delivery is recoverable,
    a silently dropped alert is not.
    """
    import storage
    kw = {"path": db_path} if db_path else {}

    if alerts is None:
        alerts = storage.query_alerts(unrouted_only=True, instance=instance, **kw)

    live = load_sinks(sinks_path)
    rules_by_id = {r["id"]: r for r in load_rules(path)}

    sent, failed, skipped = [], [], []
    for a in alerts:
        rule = rules_by_id.get(a.get("alert_rule"))
        targets = rule["notify"] if rule else []
        if not targets:
            continue          # recorded-only rule; nothing to deliver
        ok = True
        for name in targets:
            sink = live.get(name)
            if not sink:
                skipped.append((a["alert_key"], name))
                ok = False    # not delivered, so not marked delivered
                continue
            sender = SENDERS.get(sink.get("type"))
            if sender is None:
                skipped.append((a["alert_key"], name))
                ok = False
                continue
            try:
                if sender(sink, a):
                    sent.append((a["alert_key"], name))
                else:
                    failed.append((a["alert_key"], name, "sink reported failure"))
                    ok = False
            except Exception as e:
                # A dead collector must never take the dashboard with it.
                failed.append((a["alert_key"], name, str(e)))
                ok = False
        if ok:
            storage.mark_alert_routed(a["alert_key"],
                                      instance=a.get("instance", instance), **kw)
    return {"sent": sent, "failed": failed, "skipped": skipped}
