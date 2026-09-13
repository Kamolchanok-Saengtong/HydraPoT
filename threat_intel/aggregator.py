"""
threat_intel/aggregator.py — Event Aggregator.

Turns many individual collected events into security-relevant summaries.
Batching (see plugins/plugin_loader.py's SIEMExporter) just groups events for
network efficiency; this computes actual statistics over them.

    Collection (main.py -> storage.py) -> Aggregator (this file) -> Alert/Export/Dashboard

On-demand only: every function here queries storage.py's existing tables and
computes a summary at call time. No new tables, no writes, no change to
main.py's live session loop. Call these whenever a fresh summary is needed
(dashboard render, export tick, a future correlation pass) rather than
maintaining aggregate state continuously.

Three aggregations:

  aggregate_session(session_id)   one session's events -> one summary
  aggregate_time_windows()        ALL events, bucketed by (src_ip, time
                                   window) -> one summary per non-empty bucket
  aggregate_overview(start, end)  honeypot-wide: "what happened in this
                                   window" -> the SOC Aggregation page

The first two share a `_summarize()` core so a per-session stat can never be
computed two different ways.

THIS LAYER REPORTS FACTS ONLY.
It counts, distributes, and rolls up. It does NOT assign severity, compute a
risk score, decide whether something is malicious, or infer what is
"interesting" from whatever the current dataset happens to contain. Those are
detection decisions and belong to a separate layer that CONSUMES these facts
(threat_intel/severity.py, currently unwired). If a detection layer is later
switched on, its results are counted here like any other fact -- never
produced here.

FI stays out of the security facts. It is HydraPoT's routing/interaction
metric, not a security severity, so aggregate_overview() quarantines it (with
agent routing, latency and cost) under "operational".

Deliberately NOT here: normalization (converting events to a common schema)
and correlation (deciding whether separate events form one attack pattern).
"""
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import storage
import cost_model
from config_loader import load_config
from threat_intel.mitre_mapper import tag_all as _tag_all

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# `cmd` is read (not the stored technique_id/tactic -- see _chain below);
# `response` and `public_ip` stay excluded because the full-table scans
# (aggregate_all_sessions, aggregate_time_windows) would otherwise drag
# `response` -- the single largest column in the DB, see
# storage.SUMMARY_COLUMNS -- across every row for no reason.
AGG_COLUMNS = ("instance", "session_id", "timestamp", "src_ip", "agent",
               "fi_score", "latency_ms", "cmd")

# Command text -> full MITRE chain. Regex matching is the expensive part and
# attackers repeat the same commands constantly (one botnet family replays an
# identical script from every IP), so the cache does most of the work.
_CHAIN_CACHE = {}


def _chain(cmd: str) -> list:
    """Full MITRE technique chain for one command, via tag_all().

    Deliberately NOT the stored `technique_id`/`tactic` columns. Those are a
    point-in-time snapshot of whatever rules existed when the row was
    written, and they are wrong in two ways:

      * main.py only started tagging on 2026-08-01 -- every row older than
        that (the whole 2019 CyberLab corpus included) has NULL tags. 6903 of
        7298 taggable rows in this database are stale NULLs, so reading the
        column reported "0 downloads" for a session that pulled and ran a
        Mirai payload.
      * only the PRIMARY technique is ever stored. `wget x; chmod +x; sh x`
        is one row, but four techniques (T1105 + T1059.004 + T1222.002 +
        T1070.004) -- a rule looking for T1105 misses it entirely.

    Re-tagging at read time fixes both, applies retroactively to all history,
    and picks up rule-file edits with no migration -- the same reasoning
    SIEM/data.py's load_all() already documents for the dashboard.
    """
    if cmd not in _CHAIN_CACHE:
        _CHAIN_CACHE[cmd] = _tag_all(cmd) or []
    return _CHAIN_CACHE[cmd]


def _parse_ts(ts):
    """Parse storage.py's "YYYY-MM-DD HH:MM:SS" timestamps.

    fromisoformat, not strptime: that exact layout is valid ISO-8601 with a
    space separator, and fromisoformat is a C fast path while strptime
    re-interprets the format string on every call. Profiling a sensor switch
    showed 83,740 strptime calls costing 0.80s — one per row, for bucketing.
    Caching would not have helped (52,847 of the timestamps are distinct);
    parsing each one cheaply does. strptime stays as the fallback so any row
    written in another layout still parses exactly as before.
    """
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.strptime(ts, TS_FORMAT)
    except (TypeError, ValueError):
        return None


def _categorize(rows: list, categories: dict) -> dict:
    """{category_name: count} per config.yaml's aggregation.categories.

    Membership is decided by the command's FULL MITRE chain (see _chain) --
    still never by ad-hoc pattern matching here, so technique detection stays
    in threat_intel/rules/ where it belongs. A row counts once per category
    even if several of its techniques match that category.
    """
    counts = {name: 0 for name in categories}
    for r in rows:
        chain = _chain(r.get("cmd") or "")
        if not chain:
            continue
        tactics = {t.get("tactic") for t in chain}
        technique_ids = {t.get("technique_id") for t in chain}
        for name, rule in categories.items():
            if tactics & set(rule.get("tactics", [])) or \
               technique_ids & set(rule.get("technique_ids", [])):
                counts[name] += 1
    return counts


def _summarize(rows: list, config=None) -> dict:
    """Core stats shared by session- and window-level summaries. `rows` must
    be dicts shaped like storage.py's `sessions` table rows (query_session /
    query_all output -- both SELECT *, so both carry technique_id/tactic)."""
    if not rows:
        return {}

    cfg = config or load_config()
    fi_threshold = cfg.logging.fi_threshold
    categories = cfg.aggregation.get("categories", {})

    timestamps = [t for t in (_parse_ts(r.get("timestamp")) for r in rows) if t]
    fi_scores = [r.get("fi_score") or 0 for r in rows]

    agents = defaultdict(int)
    on_device_ms = 0.0
    cloud_count = 0
    for r in rows:
        agent = r.get("agent") or "unknown"
        agents[agent] += 1
        if agent == "on_device":
            on_device_ms += r.get("latency_ms") or 0.0
        elif agent == "cloud":
            cloud_count += 1

    latencies = [r.get("latency_ms") or 0.0 for r in rows]
    # Two currencies, kept separate rather than combined -- on-device cost is
    # electricity (THB, from Thailand's real MEA/PEA tariff), cloud cost is
    # the routed API's own billing (USD). Summing them would need an
    # exchange rate this codebase has no measured source for.
    electricity_cost_thb = cost_model.energy_thb(on_device_ms, cfg)
    cloud_cost_usd = cost_model.cloud_usd(cloud_count, cfg)

    start = min(timestamps) if timestamps else None
    end = max(timestamps) if timestamps else None
    duration_s = (end - start).total_seconds() if start and end else 0.0

    # Pacing: None rather than 0 when the session is a single instant (one
    # command, or everything inside the same second) -- a rate cannot be
    # inferred from zero elapsed time, and reporting 0 would be a fabricated
    # fact. Consumers decide what to do with None.
    commands_per_minute = (len(rows) / (duration_s / 60.0)) if duration_s > 0 else None

    # Session-wide MITRE footprint, from the full re-tagged chain (_chain).
    #
    # Insertion-ordered, NOT sorted: `rows` arrives in execution order, so this
    # preserves the order the attacker actually moved through the tactics
    # (Discovery -> Execution -> Impact). That progression is the kill chain
    # and is most of what makes the sequence readable to an analyst; sorting
    # it alphabetically would throw the only temporal information away.
    technique_ids, tactics = {}, {}
    for r in rows:
        for t in _chain(r.get("cmd") or ""):
            if t.get("technique_id"):
                technique_ids[t["technique_id"]] = None
            if t.get("tactic"):
                tactics[t["tactic"]] = None

    summary = {
        "event_count": len(rows),
        "src_ip": rows[0].get("src_ip"),
        "start_time": start.strftime(TS_FORMAT) if start else None,
        "end_time": end.strftime(TS_FORMAT) if end else None,
        "duration_s": duration_s,
        "commands_per_minute": round(commands_per_minute, 1) if commands_per_minute else None,
        "tactics": list(tactics),              # kill-chain order, see above
        "technique_ids": list(technique_ids),
        "high_risk_count": sum(1 for f in fi_scores if f >= fi_threshold),
        "max_fi_score": max(fi_scores) if fi_scores else 0,
        "avg_fi_score": sum(fi_scores) / len(fi_scores) if fi_scores else 0.0,
        "agents_used": dict(agents),
        "electricity_cost_thb": round(electricity_cost_thb, 6),
        "cloud_cost_usd": round(cloud_cost_usd, 6),
        "total_latency_ms": round(sum(latencies), 2),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
    }
    summary.update(_categorize(rows, categories))
    return summary


def aggregate_session(session_id: str, instance: str = None, config=None) -> dict:
    """One session's events -> one summary dict. {} if the session has no
    rows (e.g. bad session_id)."""
    cfg = config or load_config()
    rows = storage.query_session(session_id, instance=instance)
    summary = _summarize(rows, cfg)
    if summary:
        summary["session_id"] = session_id
    return summary


def aggregate_all_sessions(instance: str = None, config=None) -> list:
    """One summary per session_id currently in storage -- for a dashboard
    table. Heavier than aggregate_session(): reads every row once, then
    groups in Python, rather than one query per session."""
    cfg = config or load_config()  # resolved ONCE, not once per session --
    # load_config() re-parses config.yaml from disk every call (~18ms), which
    # at hundreds of sessions dominated aggregate_all_sessions()'s runtime
    # before this was hoisted out of the per-group loop.
    rows = storage.query_all(columns=AGG_COLUMNS)
    if instance and instance != "all":
        rows = [r for r in rows if r.get("instance") == instance]

    by_session = defaultdict(list)
    for r in rows:
        by_session[r.get("session_id")].append(r)

    out = []
    for session_id, session_rows in by_session.items():
        summary = _summarize(session_rows, cfg)
        summary["session_id"] = session_id
        out.append(summary)
    return sorted(out, key=lambda s: s.get("start_time") or "", reverse=True)


def aggregate_time_windows(window_minutes: int = None, since: datetime = None,
                           instance: str = None, config=None) -> list:
    """ALL events grouped by (src_ip, time window) -> one summary per
    non-empty window. window_minutes defaults to config.yaml's
    aggregation.window_minutes; `since` limits how far back to scan (None =
    every row in storage).

    Example: window_minutes=5, an attacker active 19:00-19:05 from
    10.0.0.5 -> one summary dict for that (ip, window) bucket with the same
    fields aggregate_session() returns (event_count, high_risk_count,
    max/avg fi_score, category counts, cost, latency, ...).
    """
    cfg = config or load_config()
    window_minutes = window_minutes or cfg.aggregation.get("window_minutes", 5)
    window_s = window_minutes * 60

    rows = storage.query_all(columns=AGG_COLUMNS)
    if instance and instance != "all":
        rows = [r for r in rows if r.get("instance") == instance]

    buckets = defaultdict(list)
    for r in rows:
        ts = _parse_ts(r.get("timestamp"))
        if ts is None:
            continue
        if since and ts < since:
            continue
        bucket_start = math.floor(ts.timestamp() / window_s) * window_s
        key = (r.get("src_ip"), bucket_start)
        buckets[key].append(r)

    out = []
    for (src_ip, bucket_start), bucket_rows in buckets.items():
        summary = _summarize(bucket_rows, cfg)
        summary["window_start"] = datetime.fromtimestamp(bucket_start).strftime(TS_FORMAT)
        summary["window_minutes"] = window_minutes
        out.append(summary)
    return sorted(out, key=lambda s: s.get("window_start") or "", reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# SOC OVERVIEW — "what is happening across the honeypot in this time window"
# ══════════════════════════════════════════════════════════════════════════════

# Preset name -> minutes. Presets are always measured back from the window's
# REFERENCE time, never from the wall clock: this database spans 2019 to today,
# so anchoring "last 24h" on now() renders an empty page against any historical
# capture.
PRESETS = {"15m": 15, "1h": 60, "24h": 24 * 60, "7d": 7 * 24 * 60}
# "ALL" is not a duration -- it means the whole extent of the capture. Kept as
# a preset because this database spans 2019 to today: every real duration
# preset lands on a nearly-empty window, and a dashboard that opens empty
# reads as broken rather than quiet.
ALL_PRESET = "ALL"

# Timeline bucket sizes to snap to, seconds. The raw window/target-buckets
# division lands on values like 37s or 4211s, which make unreadable axis
# labels; the smallest ladder rung at or above the raw size keeps buckets on
# human units (minute, 5-minute, hour, day) at every window length.
_BUCKET_LADDER = (60, 300, 900, 1800, 3600, 7200, 21600, 43200, 86400,
                  7 * 86400)


def _fmt(dt: datetime) -> str:
    return dt.strftime(TS_FORMAT)


def resolve_window(preset: str = None, start: str = None, end: str = None,
                   reference: str = None, instance: str = None) -> dict:
    """Work out the concrete [start, end] to aggregate over.

    Precedence: an explicit start+end wins; otherwise `preset` is measured
    back from `reference`; `reference` itself defaults to the newest event
    that actually exists (storage.time_bounds), not to now().

    -> {"start", "end", "reference", "preset"} as TS_FORMAT strings.
    """
    lo, hi = storage.time_bounds(instance=instance)

    if start and end:
        return {"start": start, "end": end, "reference": end, "preset": None}

    if (preset or "").upper() == ALL_PRESET:
        return {"start": lo or _fmt(datetime.now() - timedelta(days=1)),
                "end": hi or _fmt(datetime.now()),
                "reference": hi or _fmt(datetime.now()), "preset": ALL_PRESET}

    ref = reference or hi or _fmt(datetime.now())
    ref_dt = _parse_ts(ref) or datetime.now()

    minutes = PRESETS.get(preset or "24h", PRESETS["24h"])
    start_dt = ref_dt - timedelta(minutes=minutes)
    # Never start before the data does -- an empty leading span just squashes
    # the timeline.
    lo_dt = _parse_ts(lo) if lo else None
    if lo_dt and start_dt < lo_dt:
        start_dt = lo_dt

    return {"start": _fmt(start_dt), "end": _fmt(ref_dt),
            "reference": _fmt(ref_dt), "preset": preset or "24h"}


def _bucket_seconds(window_s: float, target: int) -> int:
    raw = max(1.0, window_s / max(target, 1))
    for rung in _BUCKET_LADDER:
        if rung >= raw:
            return rung
    return _BUCKET_LADDER[-1]


def _percentile(values: list, pct: float):
    """Nearest-rank percentile. Deliberately not numpy: this module has no
    other array dependency and a sorted list of session durations is tiny."""
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((pct / 100.0) * (len(s) - 1)))))
    return s[k]


def aggregate_overview(start: str = None, end: str = None, preset: str = None,
                       reference: str = None, instance: str = None,
                       exclude_row=None, config=None) -> dict:
    """Honeypot-wide facts for one time window — the SOC Aggregation page.

    Facts only: counts, distributions, rollups. Nothing here rates, scores or
    decides. `detections` is an empty slot reserved for a future detection
    layer's output to be COUNTED in; this function never produces it.

    Auth and session activity are reported as two parallel timelines and are
    deliberately NOT joined: the auth table carries no session_id, so any
    login->session mapping would be an invented correlation on (src_ip, time).

    `exclude_row(row) -> bool` drops rows before anything is counted. The
    dashboard passes its experiment/harness filter through here so the numbers
    on one page agree; the policy of what counts as real traffic is the
    caller's, not this module's.
    """
    cfg = config or load_config()
    agg_cfg = cfg.aggregation
    categories = agg_cfg.get("categories", {})
    inactivity_min = agg_cfg.get("session_inactivity_minutes", 15)
    target_buckets = agg_cfg.get("timeline_target_buckets", 48)

    win = resolve_window(preset=preset, start=start, end=end,
                         reference=reference, instance=instance)
    start_dt = _parse_ts(win["start"])
    end_dt = _parse_ts(win["end"])
    window_s = max((end_dt - start_dt).total_seconds(), 1.0) if start_dt and end_dt else 1.0
    bucket_s = _bucket_seconds(window_s, target_buckets)
    win["bucket_seconds"] = bucket_s

    rows = storage.query_range(win["start"], win["end"], instance=instance)
    auth_rows = storage.query_auth_range(win["start"], win["end"], instance=instance)
    if exclude_row is not None:
        rows = [r for r in rows if not exclude_row(r)]
        auth_rows = [r for r in auth_rows if not exclude_row(r)]

    # ── funnel (auth only, never joined to sessions) ─────────────────────────
    ev = Counter(r.get("event") for r in auth_rows)
    funnel = {
        "connections":      ev.get("connection", 0),
        "login_attempts":   sum(1 for r in auth_rows if r.get("auth_type") == "password"),
        "login_success":    ev.get("login.success", 0),
        "login_failed":     ev.get("login.failed", 0),
        "refused_capacity": ev.get("refused_capacity", 0),
        "distinct_auth_ips": len({r.get("src_ip") for r in auth_rows if r.get("src_ip")}),
    }

    # ── session activity ─────────────────────────────────────────────────────
    by_session = defaultdict(list)
    for r in rows:
        by_session[r.get("session_id")].append(r)

    active_cutoff = end_dt - timedelta(minutes=inactivity_min) if end_dt else None
    active = 0
    durations, cmds_per_session = [], []
    for sid, srows in by_session.items():
        ts = [t for t in (_parse_ts(r.get("timestamp")) for r in srows) if t]
        if not ts:
            continue
        cmds_per_session.append(len(srows))
        durations.append((max(ts) - min(ts)).total_seconds())
        if active_cutoff and max(ts) >= active_cutoff:
            active += 1

    activity = {
        "command_count":    len(rows),
        "session_count":    len(by_session),
        "active_sessions":  active,
        "distinct_src_ips": len({r.get("src_ip") for r in rows if r.get("src_ip")}),
    }

    # ── activity over time ───────────────────────────────────────────────────
    def _bucket(ts_str):
        t = _parse_ts(ts_str)
        if t is None:
            return None
        return math.floor(t.timestamp() / bucket_s) * bucket_s

    cmd_b, login_b = Counter(), Counter()
    sess_seen = defaultdict(set)
    for r in rows:
        b = _bucket(r.get("timestamp"))
        if b is not None:
            cmd_b[b] += 1
            sess_seen[b].add(r.get("session_id"))
    for r in auth_rows:
        b = _bucket(r.get("timestamp"))
        if b is not None and r.get("auth_type") == "password":
            login_b[b] += 1

    timeline = []
    if start_dt and end_dt:
        first = math.floor(start_dt.timestamp() / bucket_s) * bucket_s
        last = math.floor(end_dt.timestamp() / bucket_s) * bucket_s
        b = first
        while b <= last:
            timeline.append({
                "bucket_start": _fmt(datetime.fromtimestamp(b)),
                "commands": cmd_b.get(b, 0),
                "logins": login_b.get(b, 0),
                "sessions": len(sess_seen.get(b, ())),
            })
            b += bucket_s

    # ── per session (facts only; the UI ranks by ONE named column at a time) ─
    # Required by the Attention Queue: it ranks sessions by an explicit,
    # visible criterion (techniques / commands / iocs / tactics / last_seen).
    # No blended score is computed here or anywhere else -- a blend would be a
    # risk score wearing a disguise. Severity stays with the detection layer,
    # which is not wired.
    sess_rows = defaultdict(list)
    for r in rows:
        sess_rows[r.get("session_id")].append(r)

    sessions_rank = []
    for sid, srows in sess_rows.items():
        ts = [t for t in (_parse_ts(r.get("timestamp")) for r in srows) if t]
        s_tactics, s_techs = {}, {}
        for r in srows:
            for t in _chain(r.get("cmd") or ""):
                if t.get("tactic"):
                    s_tactics[t["tactic"]] = None
                if t.get("technique_id"):
                    s_techs[t["technique_id"]] = None
        sessions_rank.append({
            "session_id": sid,
            "src_ip": srows[0].get("src_ip"),
            "commands": len(srows),
            "technique_count": len(s_techs),
            "tactic_count": len(s_tactics),
            "tactics": list(s_tactics),
            "technique_ids": list(s_techs),
            "first_seen": _fmt(min(ts)) if ts else None,
            "last_seen": _fmt(max(ts)) if ts else None,
        })

    # ── per source IP (ordered by volume — a fact, not a danger ranking) ─────
    ip_cmd, ip_sess, ip_first, ip_last, ip_tac = (
        Counter(), defaultdict(set), {}, {}, defaultdict(dict))
    for r in rows:
        ip = r.get("src_ip")
        if not ip:
            continue
        ip_cmd[ip] += 1
        ip_sess[ip].add(r.get("session_id"))
        ts = r.get("timestamp")
        if ts:
            ip_first[ip] = min(ip_first.get(ip, ts), ts)
            ip_last[ip] = max(ip_last.get(ip, ts), ts)
        for t in _chain(r.get("cmd") or ""):
            if t.get("tactic"):
                ip_tac[ip][t["tactic"]] = None
    ip_logins = Counter(r.get("src_ip") for r in auth_rows
                        if r.get("auth_type") == "password" and r.get("src_ip"))

    source_ips = [{
        "src_ip": ip,
        "commands": n,
        "sessions": len(ip_sess[ip]),
        "login_attempts": ip_logins.get(ip, 0),
        "first_seen": ip_first.get(ip),
        "last_seen": ip_last.get(ip),
        "tactics": list(ip_tac.get(ip, {})),
    } for ip, n in ip_cmd.most_common()]

    # ── MITRE distribution (re-tagged; see _chain) ───────────────────────────
    tactic_counts, technique_counts, technique_names = {}, Counter(), {}
    tagged = 0
    for r in rows:
        chain = _chain(r.get("cmd") or "")
        if chain:
            tagged += 1
        for t in chain:
            tac, tid = t.get("tactic"), t.get("technique_id")
            if tac:
                tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
            if tid:
                technique_counts[tid] += 1
                technique_names.setdefault(tid, t.get("technique") or tid)

    mitre = {
        "tactics": tactic_counts,
        "techniques": [{"technique_id": tid, "name": technique_names.get(tid, tid),
                        "count": n} for tid, n in technique_counts.most_common()],
        "coverage": {"tagged": tagged, "untagged": len(rows) - tagged,
                     "total": len(rows)},
    }

    # ── IOCs ─────────────────────────────────────────────────────────────────
    # "New" is measured against the IMMEDIATELY PRECEDING window of the same
    # length, not against all history: comparing to all history would mean
    # re-extracting IOCs over the entire database on every page render (~11s
    # at this size). "New vs previous period" is the standard SOC comparison
    # and costs one extra query of the same size -- it is labelled that way in
    # the UI so the denominator is never ambiguous.
    try:
        from threat_intel.ioc_extractor import build_iocs
        store = build_iocs(rows, auth_rows)
        recs = store.records() if callable(getattr(store, "records", None)) else store.records
        values = {(r["type"], r["value"]) for r in recs}

        prev_values = set()
        if start_dt and end_dt and win.get("preset") != ALL_PRESET:
            prev_end = start_dt
            prev_start = prev_end - timedelta(seconds=window_s)
            prev_rows = storage.query_range(_fmt(prev_start), _fmt(prev_end), instance=instance)
            prev_auth = storage.query_auth_range(_fmt(prev_start), _fmt(prev_end), instance=instance)
            if exclude_row is not None:
                prev_rows = [r for r in prev_rows if not exclude_row(r)]
                prev_auth = [r for r in prev_auth if not exclude_row(r)]
            if prev_rows or prev_auth:
                pstore = build_iocs(prev_rows, prev_auth)
                precs = pstore.records() if callable(getattr(pstore, "records", None)) else pstore.records
                prev_values = {(r["type"], r["value"]) for r in precs}

        recurring = len(values & prev_values)
        iocs = {"by_type": dict(Counter(r["type"] for r in recs)),
                "distinct_total": len(recs),
                "new_vs_prev": len(values) - recurring,
                "recurring": recurring,
                "compared": bool(prev_values)}
    except Exception as e:
        iocs = {"by_type": {}, "distinct_total": 0, "new_vs_prev": 0, "recurring": 0,
                "compared": False, "error": f"{type(e).__name__}: {e}"}

    # ── operational: HydraPoT's own metrics, NOT security facts ──────────────
    agents = Counter(r.get("agent") or "unknown" for r in rows)
    latencies = [r.get("latency_ms") or 0.0 for r in rows]
    on_device_ms = sum((r.get("latency_ms") or 0.0) for r in rows
                       if r.get("agent") == "on_device")
    operational = {
        "agents_used": dict(agents),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        "fi_distribution": dict(Counter(r.get("fi_score") or 0 for r in rows)),
        "electricity_cost_thb": round(cost_model.energy_thb(on_device_ms, cfg), 6),
        "cloud_cost_usd": round(cost_model.cloud_usd(agents.get("cloud", 0), cfg), 6),
    }

    return {
        "window": win,
        "funnel": funnel,
        "activity": activity,
        "timeline": timeline,
        "source_ips": source_ips,
        "sessions": sessions_rank,
        "mitre": mitre,
        "iocs": iocs,
        "categories": _categorize(rows, categories),
        "session_stats": {
            "duration_p50_s": _percentile(durations, 50),
            "duration_p90_s": _percentile(durations, 90),
            "commands_p50": _percentile(cmds_per_session, 50),
            "commands_p90": _percentile(cmds_per_session, 90),
            # Bands rather than a raw histogram: "how many were drive-by vs
            # how many stayed" is the question, and fixed bands make that
            # readable at a glance.
            "duration_bands": {
                "0-1m": sum(1 for d in durations if d < 60),
                "1-5m": sum(1 for d in durations if 60 <= d < 300),
                "5-15m": sum(1 for d in durations if 300 <= d < 900),
                "15m+": sum(1 for d in durations if d >= 900),
            },
        },
        "operational": operational,
        # Reserved for a detection layer's output to be counted in. Aggregation
        # never populates this itself.
        "detections": {},
    }
