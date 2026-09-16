"""
threat_intel/normalize.py — ONE canonical security-event representation.

HydraPoT's interoperability layer. Before this, normalization happened in
exactly one place -- SyslogExporter._to_cef() (now threat_intel/exporters.py)
-- so Splunk and Elasticsearch
received the raw internal dict and every new exporter would have invented its
own mapping. Now there is a single canonical form and exporters translate FROM
it.

    raw HydraPoT dict  ->  normalize_*()  ->  OCSF event  ->  CEF / ECS / JSON

SCHEMA: OCSF (Open Cybersecurity Schema Framework), pinned to OCSF_VERSION.
Chosen over ECS because ECS is Elastic's schema -- normalizing internally to it
would make one vendor free and every other export a translation away from a
competitor's model. CEF is a wire format, not a data model (no nesting, no
types, six generic cs1..cs6 slots), so it cannot be canonical. STIX describes
threat-intel OBJECTS, not "this session ran this command", and the existing
IOC -> STIX path in ioc_extractor.py stays exactly as it is.

Every class id, activity id and severity value below was read from
schema.ocsf.io for the pinned version, not from memory.

ONLY THREE CLASSES, because HydraPoT only has three kinds of telemetry:

    Authentication    (3002)  login attempts        <- the auth table
    Process Activity  (1007)  commands typed        <- the sessions table
    Detection Finding (2004)  analysed findings     <- detection+severity+alerts

Detection Finding is the important one. Correlation, detection and severity
output previously reached the dashboard and stopped -- external SIEMs got raw
commands and none of the analysis that is HydraPoT's actual contribution.

TWO RULES THIS MODULE EXISTS TO ENFORCE
---------------------------------------
1. FI IS NOT SEVERITY. FI is HydraPoT's routing metric: it decides which agent
   answers a command. A loud `rm` of a file the attacker created themselves is
   FI 4 and harmless; a quiet credential read may be FI 1. It is carried in
   `unmapped.hydrapot` and NEVER touches severity_id. Raw events get
   severity_id 0 (Unknown) because nothing has assessed them yet -- that is the
   honest value, not Informational.

2. NOTHING IS FABRICATED. A typed SSH command is not an OS process: there is no
   pid, no parent, no exit code, no image path. Those fields are left ABSENT
   rather than filled with zeros that downstream tools would believe.

PURE. No database, no config, no I/O, no clock reads except converting a
timestamp the caller already had. Every function is deterministic: the same
input dict always produces the same output, which is what makes the exporters
testable.
"""
from datetime import datetime

# Pinned. Every id below was verified against https://schema.ocsf.io/1.3.0/ --
# class uids and, in particular, Detection Finding's activity ids, which were
# renumbered when Security Finding was deprecated. Bump this only alongside a
# re-read of the schema.
OCSF_VERSION = "1.3.0"

# Pinned separately from OCSF_VERSION -- different schema, different release
# cycle, and nothing keeps the two in step. Emitted as `ecs.version` on every
# ECS document because ECS requires it, and tooling that auto-detects "is this
# ECS?" looks for it before anything else.
ECS_VERSION = "8.11.0"

# class_uid -> (category_uid, category_name)
CLASS_AUTHENTICATION = 3002       # category 3, Identity & Access Management
CLASS_PROCESS_ACTIVITY = 1007     # category 1, System Activity
CLASS_DETECTION_FINDING = 2004    # category 2, Findings

CATEGORY = {CLASS_AUTHENTICATION: 3,
            CLASS_PROCESS_ACTIVITY: 1,
            CLASS_DETECTION_FINDING: 2}

# Authentication activity ids
AUTH_LOGON = 1
AUTH_UNKNOWN = 0
# Authentication status ids
STATUS_UNKNOWN, STATUS_SUCCESS, STATUS_FAILURE = 0, 1, 2

# Process Activity activity ids
PROCESS_LAUNCH = 1

# Detection Finding activity ids
FINDING_CREATE, FINDING_UPDATE, FINDING_CLOSE = 1, 2, 3

# OCSF severity_id. 6 (Fatal) and 99 (Other) exist but nothing in HydraPoT
# produces them, so they are not mapped rather than being reachable by
# accident.
SEVERITY_UNKNOWN = 0
SEVERITY_ID = {
    "info": 1,        # Informational
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

PRODUCT = {"name": "HydraPoT", "vendor_name": "HydraPoT",
           "feature": {"name": "honeypot"}}


def _epoch_ms(ts):
    """OCSF `time` is epoch MILLISECONDS.

    Returns None for anything unparseable rather than substituting now(): a
    wrong timestamp is worse than an absent one, because a SIEM will happily
    bucket it. The original string is preserved in unmapped for traceability.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return int(ts * 1000) if ts < 1e11 else int(ts)
    for parse in (datetime.fromisoformat,
                  lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M:%S")):
        try:
            return int(parse(str(ts)).timestamp() * 1000)
        except (TypeError, ValueError):
            continue
    return None


def _metadata(raw_time=None):
    md = {"version": OCSF_VERSION, "product": dict(PRODUCT)}
    if raw_time is not None:
        # Kept so an analyst can tie a normalized event back to the exact
        # string the sensor wrote, without re-deriving it from epoch ms.
        md["original_time"] = str(raw_time)
    return md


def _hydrapot(event):
    """HydraPoT's operational metrics, namespaced under OCSF's `unmapped`.

    `unmapped` is the mechanism OCSF defines for source-specific attributes, so
    this needs no invented extension and no fake standard field. Everything
    here describes how the HONEYPOT behaved, not what the attacker did:

      fi_score    which agent had to answer -- a routing metric, NOT severity
      agent       which backend served the command
      latency_ms  how long that took

    Carrying them at top level, or letting fi_score reach severity_id, is the
    single most consequential mistake this module prevents.
    """
    out = {}
    for src, dst in (("fi_score", "fi_score"), ("fi", "fi_score"),
                     ("agent", "agent"), ("latency_ms", "latency_ms"),
                     ("instance", "instance"), ("session_id", "session_id")):
        v = event.get(src)
        if v is not None and dst not in out:
            out[dst] = v
    return {"hydrapot": out} if out else {}


def _base(class_uid, activity_id, severity_id, raw_time):
    """The attributes every OCSF event carries.

    type_uid is class_uid * 100 + activity_id, per the schema -- computed, not
    written by hand, so it cannot drift from the pair it describes.
    """
    return {
        "class_uid": class_uid,
        "category_uid": CATEGORY[class_uid],
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_id,
        "time": _epoch_ms(raw_time),
        "metadata": _metadata(raw_time),
    }


def _prune(d):
    """Drop keys that carry no information, recursively.

    An absent field and an empty one mean different things to a SIEM: absent is
    "we do not know", present-but-empty is "we looked and there was nothing".
    HydraPoT frequently does not know (no pid for a typed command, no username
    on a TCP probe), so those keys are removed.

    EMPTY CONTAINERS GO TOO. Dropping only None left `"src_endpoint": {}` and
    `"unmapped": {}` behind -- an object that announces a source endpoint and
    then declines to name one, which is worse than saying nothing.

    Falsy SCALARS are kept: severity_id 0 means "Unknown", device.type_id 0
    means "Unknown device type", and status_id 0 likewise. Those are real
    enum values, not absences, and stripping them would silently delete the
    most honest answer this module gives.
    """
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            if v is None:
                continue
            pv = _prune(v)
            if isinstance(pv, (dict, list)) and not pv:
                continue
            out[k] = pv
        return out
    if isinstance(d, list):
        return [_prune(v) for v in d]
    return d


def _attacks(technique_ids=(), tactics=(), names=None):
    """OCSF `attacks[]` — an array of MITRE ATT&CK objects.

    Techniques and tactics are zipped only where both are known; a tactic with
    no technique still produces an entry, because "they reached Impact" is a
    fact worth exporting even when the specific technique is unmapped.
    """
    names = names or {}
    out = [{"technique": {"uid": tid, "name": names.get(tid)},
            "version": "v14"} for tid in (technique_ids or ())]
    for tac in (tactics or ()):
        out.append({"tactic": {"name": tac}, "version": "v14"})
    return out or None


# ── raw telemetry ───────────────────────────────────────────────────────────

def normalize_command(event: dict) -> dict:
    """One typed SSH command -> OCSF Process Activity (1007).

    `process.cmd_line` is the ONLY process field populated. A honeypot command
    has no pid, no parent process, no image file and no exit code, and OCSF
    marks none of those required on the process object -- so they are omitted.
    Emitting pid 0 would be a fabricated fact that a SIEM would correlate on.

    severity_id is 0 (Unknown): a raw command has not been assessed by
    anything. Findings carry severity; observations do not.
    """
    event = event or {}
    ts = event.get("timestamp")
    tid, tactic = event.get("technique_id"), event.get("tactic")

    out = dict(_base(CLASS_PROCESS_ACTIVITY, PROCESS_LAUNCH,
                     SEVERITY_UNKNOWN, ts))
    out.update({
        "process": {"cmd_line": event.get("cmd")},
        # `actor` is required by the class; the only actor HydraPoT can name is
        # the remote session, so it carries the session uid and nothing else.
        "actor": {"session": {"uid": event.get("session_id")}},
        "device": {"hostname": event.get("instance"), "type_id": 0},
        "src_endpoint": {"ip": event.get("src_ip")},
        "attacks": _attacks([tid] if tid else [], [tactic] if tactic else [],
                            {tid: event.get("technique")} if tid else {}),
        "message": event.get("cmd"),
        "unmapped": _hydrapot(event),
    })
    return _prune(out)


def normalize_auth(event: dict) -> dict:
    """One login attempt -> OCSF Authentication (3002).

    HydraPoT's auth rows carry auth_type ("password" / "tcp_connect") and an
    `event` string ("login.success" / "login.failed" / "connection"). Only the
    password rows are real authentication attempts; a bare TCP connect is
    reported with activity Unknown rather than being inflated into a logon that
    never happened.
    """
    event = event or {}
    ts = event.get("timestamp")
    kind = event.get("auth_type")
    ev = (event.get("event") or "").lower()

    status = STATUS_UNKNOWN
    if "success" in ev:
        status = STATUS_SUCCESS
    elif "fail" in ev:
        status = STATUS_FAILURE

    activity = AUTH_LOGON if kind == "password" else AUTH_UNKNOWN

    out = dict(_base(CLASS_AUTHENTICATION, activity, SEVERITY_UNKNOWN, ts))
    out.update({
        "user": {"name": event.get("username")},
        "src_endpoint": {"ip": event.get("src_ip"),
                         "port": event.get("src_port")},
        "device": {"hostname": event.get("instance"), "type_id": 0},
        "status_id": status,
        # The submitted password is NOT emitted. It is attacker-supplied
        # credential material; it belongs in the local IOC store, not in a
        # stream forwarded to third-party systems.
        "unmapped": _hydrapot(event),
    })
    return _prune(out)


# ── analysed findings ───────────────────────────────────────────────────────

_STATE_ACTIVITY = {"new": FINDING_CREATE,
                   "acknowledged": FINDING_UPDATE,
                   "closed": FINDING_CLOSE}


def normalize_finding(detection: dict, alert: dict = None) -> dict:
    """A detection (optionally with its alert record) -> Detection Finding (2004).

    This is the class that makes HydraPoT's analysis exportable. It carries
    what the pipeline actually concluded:

        correlation  ->  finding_info.uid + the relationship's statement
        detection    ->  which rule surfaced it, and why
        severity     ->  severity_id, from threat_intel/severity.py ONLY
        MITRE        ->  attacks[]
        alert state  ->  activity_id (Create / Update / Close)

    `detection` is a verdict from detection.detect() after severity has
    annotated it. `alert` is the row from storage.query_alerts() when one
    exists; without it the finding is reported as newly created, which is what
    it is.

    severity_id comes from the severity LAYER and nowhere else. FI is not
    consulted, and the relationship's size is not either -- a widely repeated
    low-severity behaviour stays low.
    """
    detection = detection or {}
    rel = detection.get("relationship") or {}
    ev = rel.get("evidence") or {}
    rules = detection.get("rules") or []
    alert = alert or {}

    sev = detection.get("severity") or alert.get("severity")
    severity_id = SEVERITY_ID.get(sev, SEVERITY_UNKNOWN)

    state = (alert.get("state") or "new").lower()
    activity = _STATE_ACTIVITY.get(state, FINDING_CREATE)

    rule = rules[0] if rules else {}
    title = alert.get("title") or rule.get("title") or "Correlated activity"
    # The correlation engine's own wording. It is the only sentence the engine
    # authorises a UI -- or an exporter -- to render for a relationship, so it
    # is reproduced verbatim rather than re-described here.
    statement = rel.get("statement")

    out = dict(_base(CLASS_DETECTION_FINDING, activity, severity_id,
                     alert.get("last_seen") or rel.get("last_seen")))
    out.update({
        "finding_info": _prune({
            # Stable across recomputation: rule|link_type|link_value. The whole
            # pipeline is rebuilt every window load, so a generated id would
            # make the same finding look new on every export.
            "uid": alert.get("alert_key") or _finding_uid(detection),
            "title": title,
            "desc": statement,
            "created_time": _epoch_ms(alert.get("created_at")),
            "first_seen_time": _epoch_ms(rel.get("first_seen")),
            "last_seen_time": _epoch_ms(rel.get("last_seen")),
            "analytic": _prune({
                "name": rule.get("id"),
                "desc": rule.get("reason"),
                "type_id": 1,      # Rule
            }) or None,
        }),
        "attacks": _attacks(ev.get("technique_ids"), ev.get("tactics")),
        "device": {"hostname": (rel.get("scope") or [None])[0], "type_id": 0},
        "src_endpoint": {"ip": (rel.get("src_ips") or [None])[0]},
        "message": statement,
        "evidences": _evidences(rel),
        "unmapped": {"hydrapot": _prune({
            "link_type": rel.get("link_type"),
            "detection_rule": rule.get("id"),
            "alert_rule": alert.get("alert_rule") or None,
            "alert_state": state,
            "member_count": rel.get("member_count"),
            "distinct_sources": rel.get("distinct_sources"),
            "sessions": rel.get("members"),
            "severity_rules": [r.get("id") for r in
                               (detection.get("severity_rules") or [])] or None,
        })},
    })
    return _prune(out)


def _finding_uid(detection) -> str:
    """Same identity the alert layer uses, so a finding exported before an
    alert record exists still matches the one exported after."""
    from threat_intel.alert_records import alert_key
    return alert_key(detection)


def _evidences(rel):
    """OCSF `evidences[]` — the artifacts behind the detection.

    One entry per member session, carrying only what correlation established.
    Capped: a 131-session relationship would otherwise put 131 objects into
    every syslog datagram.
    """
    members = rel.get("members") or []
    if not members:
        return None
    return [{"session": {"uid": m}} for m in members[:20]]


# ── exporter adapters ───────────────────────────────────────────────────────
# These translate FROM the canonical event. They are the only place a
# vendor-specific shape exists, and none of them re-derive a fact.

_CEF_SEVERITY = {0: None, 1: 1, 2: 3, 3: 5, 4: 7, 5: 10}


def _cef_escape(value, header=False):
    """CEF escaping. Backslash first, or it would double-escape the others."""
    s = str(value if value is not None else "")
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|") if header else s.replace("=", "\\=")
    return s.replace("\n", " ").replace("\r", " ")


def to_cef(ocsf: dict) -> str:
    """Canonical OCSF -> CEF:0 record.

    SEVERITY COMES FROM severity_id, NOT FI. The previous implementation did
    `{0:1, 1:3, 2:5, 3:7, 4:10}.get(fi)` and put HydraPoT's routing metric in
    the CEF severity column, where every downstream SIEM reads it as a security
    rating. An event OCSF rates Unknown gets CEF severity 0 -- CEF's own
    "unknown" -- rather than an invented number.
    """
    sev_id = ocsf.get("severity_id", SEVERITY_UNKNOWN)
    cef_sev = _CEF_SEVERITY.get(sev_id)
    cef_sev = 0 if cef_sev is None else cef_sev

    cls = ocsf.get("class_uid")
    name = (ocsf.get("finding_info", {}).get("title")
            or {CLASS_PROCESS_ACTIVITY: "SSH command",
                CLASS_AUTHENTICATION: "Authentication attempt"}.get(cls, "Event"))

    hp = (ocsf.get("unmapped") or {}).get("hydrapot") or {}
    ext = {
        "rt": ocsf.get("time"),
        "src": (ocsf.get("src_endpoint") or {}).get("ip"),
        "spt": (ocsf.get("src_endpoint") or {}).get("port"),
        "dvchost": (ocsf.get("device") or {}).get("hostname"),
        "duser": (ocsf.get("user") or {}).get("name"),
        "msg": ocsf.get("message"),
        "externalId": (ocsf.get("finding_info") or {}).get("uid"),
        # cs1..cs6 are CEF's only extension slots, so each one is labelled --
        # an unlabelled cs3 is meaningless at the receiving end.
        "cs1": hp.get("agent"), "cs1Label": "HydraPoTAgent",
        "cs2": hp.get("session_id") or hp.get("sessions"), "cs2Label": "SessionID",
        # FI travels as a labelled custom field, never as the severity column.
        "cs3": hp.get("fi_score"), "cs3Label": "HydraPoTFIScore",
        "cs4": ",".join(a.get("technique", {}).get("uid", "")
                        for a in (ocsf.get("attacks") or [])
                        if a.get("technique")) or None,
        "cs4Label": "MitreTechniques",
    }
    body = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items()
                    if v is not None and v != "")
    return ("CEF:0|HydraPoT|Honeypot|1.0|"
            f"{_cef_escape(ocsf.get('type_uid'), header=True)}|"
            f"{_cef_escape(name, header=True)}|{cef_sev}|{body}")


_ECS_SEVERITY = {0: None, 1: 1, 2: 21, 3: 47, 4: 73, 5: 99}
_ECS_DATASET = {CLASS_AUTHENTICATION: "auth",
                CLASS_PROCESS_ACTIVITY: "command",
                CLASS_DETECTION_FINDING: "finding"}

# ECS treats event.category and event.type as a PAIR -- category says what the
# event is about, type says what happened to it, and Elastic's own dashboards
# and rule logic filter on both. Emitting category alone (which this module did
# until now) leaves every document half-classified.
#
# Values are from the ECS allowed-value list for event.type, chosen to match
# what normalize_*() already decided rather than to look impressive:
#
#   Process Activity   a command was launched                  -> start
#   Authentication     activity_id 1 (Logon) is a session start -> start
#                      activity_id 0 (Unknown -- a bare TCP probe, which
#                      normalize_auth deliberately refuses to inflate into a
#                      logon) is not a session start            -> info
#   Detection Finding  an assessment, not a state change        -> info
_ECS_TYPE_AUTH = {AUTH_LOGON: ["start"], AUTH_UNKNOWN: ["info"]}
_ECS_TYPE = {CLASS_PROCESS_ACTIVITY: ["start"],
             CLASS_DETECTION_FINDING: ["info"]}


def to_ecs(ocsf: dict) -> dict:
    """Canonical OCSF -> Elastic Common Schema.

    Minimal by design: only fields HydraPoT actually has. HydraPoT is NOT
    internally ECS -- this mapping exists so the Elasticsearch exporter speaks
    the schema Elastic's own dashboards expect, and nothing else reads it.
    """
    cls = ocsf.get("class_uid")
    kind, category = "event", []
    if cls == CLASS_DETECTION_FINDING:
        kind, category = "alert", ["intrusion_detection"]
    elif cls == CLASS_AUTHENTICATION:
        category = ["authentication"]
    elif cls == CLASS_PROCESS_ACTIVITY:
        category = ["process"]

    # Read from activity_id for Authentication, because a logon and a bare TCP
    # connect arrive as the same class and only activity_id tells them apart.
    if cls == CLASS_AUTHENTICATION:
        etype = _ECS_TYPE_AUTH.get(ocsf.get("activity_id"))
    else:
        etype = _ECS_TYPE.get(cls)

    hp = (ocsf.get("unmapped") or {}).get("hydrapot") or {}
    ts = ocsf.get("time")
    attacks = ocsf.get("attacks") or []
    dataset = _ECS_DATASET.get(cls, "event")

    out = {
        "@timestamp": (datetime.utcfromtimestamp(ts / 1000).isoformat() + "Z"
                       if ts else None),
        "ecs": {"version": ECS_VERSION},
        "event": _prune({
            "kind": kind,
            "category": category or None,
            "type": etype,
            "module": "hydrapot",
            "dataset": f"hydrapot.{dataset}",
            # ECS event.severity is a 0-100 scale, so it is RE-SCALED from
            # OCSF's 0-5 rather than copied across as a raw number that would
            # read as "almost nothing" in Kibana.
            "severity": _ECS_SEVERITY.get(ocsf.get("severity_id")),
            "id": (ocsf.get("finding_info") or {}).get("uid"),
            "reason": ocsf.get("message"),
        }),
        "source": _prune({"ip": (ocsf.get("src_endpoint") or {}).get("ip"),
                          "port": (ocsf.get("src_endpoint") or {}).get("port")}) or None,
        "host": _prune({"name": (ocsf.get("device") or {}).get("hostname")}) or None,
        "user": _prune({"name": (ocsf.get("user") or {}).get("name")}) or None,
        "process": _prune({"command_line": (ocsf.get("process") or {}).get("cmd_line")}) or None,
        "threat": _prune({
            "framework": "MITRE ATT&CK" if attacks else None,
            "technique": _prune({
                "id": [a["technique"]["uid"] for a in attacks
                       if a.get("technique", {}).get("uid")] or None,
                "name": [a["technique"]["name"] for a in attacks
                         if a.get("technique", {}).get("name")] or None}) or None,
            "tactic": _prune({
                "name": [a["tactic"]["name"] for a in attacks
                         if a.get("tactic", {}).get("name")] or None}) or None,
        }) or None,
        # Operational metrics stay namespaced in ECS too. ECS has no field for
        # "which LLM answered this", and inventing one under a standard prefix
        # would collide the moment Elastic defines it.
        "hydrapot": hp or None,
    }
    return _prune(out)


def to_json(ocsf: dict) -> dict:
    """Canonical OCSF, unchanged.

    Exists so the exporters read the same way (`to_cef`/`to_ecs`/`to_json`)
    rather than one of them special-casing "just send it". Splunk indexes
    arbitrary JSON and OCSF is a published schema, so there is nothing to map.
    """
    return ocsf
