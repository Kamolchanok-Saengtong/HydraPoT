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

Two aggregation types, both built on the same `_summarize()` core so a stat
can never be computed two different ways:

  aggregate_session(session_id)   one session's events -> one summary
  aggregate_time_windows()        ALL events, bucketed by (src_ip, time
                                   window) -> one summary per non-empty bucket

Deliberately NOT here: normalization (converting events to a common schema)
and correlation (deciding whether separate events form one attack pattern).
Both are separate, later work — see config.yaml's `aggregation` section for
the one number/mapping this file is configured by.
"""
import math
from collections import defaultdict
from datetime import datetime

import storage
import cost_model
from config_loader import load_config

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# Everything _summarize()/_categorize() actually read -- deliberately excludes
# `cmd`, `response`, `public_ip`: the full-table scans below (aggregate_all_
# sessions, aggregate_time_windows) would otherwise drag `response` (the
# single largest column in the DB, see storage.SUMMARY_COLUMNS) across every
# row for no reason. aggregate_session() reads one session via query_session()
# instead, where the row count is small enough that this doesn't matter.
AGG_COLUMNS = ("instance", "session_id", "timestamp", "src_ip", "agent",
               "fi_score", "latency_ms", "technique_id", "tactic")


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, TS_FORMAT)
    except (TypeError, ValueError):
        return None


def _categorize(rows: list, categories: dict) -> dict:
    """{category_name: count} per config.yaml's aggregation.categories.
    Membership is decided by the row's REAL MITRE tactic/technique_id
    (already tagged per-command by mitre_mapper.py in main.py) -- never by
    re-inspecting command text, so this never drifts from the one place
    technique detection actually happens. Config-driven: adding, renaming,
    or re-scoping a category is a config.yaml edit, not a code change."""
    counts = {name: 0 for name in categories}
    for r in rows:
        tactic = r.get("tactic")
        technique_id = r.get("technique_id")
        for name, rule in categories.items():
            if tactic and tactic in rule.get("tactics", []):
                counts[name] += 1
            elif technique_id and technique_id in rule.get("technique_ids", []):
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

    summary = {
        "event_count": len(rows),
        "src_ip": rows[0].get("src_ip"),
        "start_time": start.strftime(TS_FORMAT) if start else None,
        "end_time": end.strftime(TS_FORMAT) if end else None,
        "duration_s": (end - start).total_seconds() if start and end else 0.0,
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
