"""
SIEM/data.py — dashboard-facing data-access/cache layer (Dash has no
st.cache_data, so this is a simple TTL cache).

THIN on purpose: this module only fetches and caches raw rows from
storage.py. It does not compute security summaries or costs — those live in
threat_intel/aggregator.py and SIEM/cost.py respectively, imported by the
pages that need them.
"""
import functools
import ipaddress
import time

import pandas as pd

from threat_intel.mitre_mapper import tag as _mitre_tag, tag_all as _mitre_tag_all

import storage

_cache = {"all_df": None, "all_ts": 0, "auth": None, "auth_ts": 0}
# load_raw_session_rows() re-reads every individual session JSON file from
# disk on a cache miss (~300-400ms at 3700+ files) — 1.0s was shorter than
# the time it takes a person to click something, so nearly every click paid
# that cost. 4s (just under REFRESH_MS) still keeps the live auto-refresh
# feeling live, but reuses the cache across fast clicks.
# TTL MUST be longer than REFRESH_MS or every tick is a guaranteed cold miss —
# at 4s vs a 5s tick this re-read all 3800 session files and rebuilt the 132k-row
# DataFrame every 5 seconds, which is what made the whole UI feel frozen.
# Heavy full-dataset cache: MITRE re-tagging over all history, IOC extraction,
# the aggregate rollups. Rebuilding costs ~3.2s, so a short TTL meant that
# pausing to actually READ the dashboard for 30s made the next click pay full
# price — the single biggest source of "the UI feels slow".
#
# 5 minutes is safe because nothing live depends on it: the terminal feed has
# its own 4s cache (FEED_TTL) and is pushed over the WebSocket within ~1s of a
# command landing, and the "Refresh" button clears every cache on demand.
TTL = 300.0       # heavy full-dataset cache (page renders, charts, MITRE)
FEED_ROWS = 60    # newest rows pulled for the 30-line feed. Small headroom for
                  # rows with an unparseable timestamp, which get dropped before
                  # the head(30); no reason to fetch more than that.
FEED_TTL = 4.0    # feed is cheap, so it can stay near-real-time

_feed_cache = {}   # instance key ("all" or sensor name) -> (rows, fetched_at)

# Rendered pages, keyed by everything they depend on -> (component, built_at).
# Kept to the same TTL as the data caches: a page built from a snapshot of the
# data is valid for exactly as long as that snapshot is, so this adds no
# staleness beyond what the dashboard already had.
PAGE_TTL = TTL
_page_cache = {}


def _cached_page(key, build):
    """Serve an already-rendered page instead of rebuilding it.

    Switching pages rebuilt every Plotly figure and Dash component from
    scratch — ~550ms for the Summary page — even when nothing behind it had
    changed. Profiling showed the cost is figure/component construction
    (26% plotly, 39% Dash components), not the data query, so the only real
    fix is to not rebuild at all.

    The live terminal is deliberately NOT frozen by this: it has its own 5s
    callback writing into live-feed-wrap, which replaces the feed inside
    whatever page is on screen, cached or not."""
    now = time.time()
    hit = _page_cache.get(key)
    if hit is not None and (now - hit[1]) < PAGE_TTL:
        return hit[0]
    page = build()
    _page_cache[key] = (page, now)
    return page


def load_feed_rows(instance=None, limit=None):
    """The newest rows, straight off the timestamp index.

    This used to open the 40 newest session files per sensor and parse them in
    full to render 30 lines — ~300ms of work for ~2KB of output. As one indexed
    LIMIT query it is ~2ms, which is what lets the 5s tick feel instant.

    The sensor filter is pushed into the query rather than applied after. Taking
    the newest N globally and filtering in pandas looks equivalent but is not:
    if one sensor is busy it occupies the whole window and every quieter sensor
    renders as an empty feed. Cached per instance for the same reason.

    `limit` overrides FEED_ROWS for callers that need a deeper feed than the
    Summary panel's 30 lines (the big-screen Live page). It is part of the
    cache key: a 60-row cache entry must not be served to a caller that asked
    for 120 and would silently render half a screen."""
    now = time.time()
    key = (instance or "all", limit or FEED_ROWS)
    hit = _feed_cache.get(key)
    if hit is not None and (now - hit[1]) < FEED_TTL:
        return hit[0]
    rows = storage.query_recent(limit or FEED_ROWS, instance=instance)
    _feed_cache[key] = (rows, now)
    return rows

_overview_cache = {}   # (preset, instance) -> (result, fetched_at)


def load_overview(preset="ALL", instance=None):
    """TTL-cached threat_intel.aggregator.aggregate_overview().

    The uncached call costs ~2.4s on this dataset — ~1.0s re-tagging every
    command through the MITRE rules and ~1.35s extracting IOCs across 75k auth
    rows — and the Summary page calls it on every render, which made switching
    pages or ranges feel broken. Cached on the same TTL as the other loaders:
    a page built from a snapshot is valid exactly as long as that snapshot.

    is_experiment_row is applied here so the cached numbers match load_all()'s
    view of what counts as real attacker traffic.
    """
    from threat_intel.aggregator import aggregate_overview
    now = time.time()
    key = (preset or "ALL", instance or "all")
    hit = _overview_cache.get(key)
    if hit is not None and (now - hit[1]) < TTL:
        return hit[0]
    out = aggregate_overview(preset=preset or "ALL", instance=instance,
                             exclude_row=is_experiment_row)
    _overview_cache[key] = (out, now)
    return out


_detect_cache = {}     # (preset, instance) -> (result, fetched_at)


def load_detections(preset="ALL", instance=None):
    """TTL-cached Correlation -> Detection for the dashboard.

    Runs the two layers end to end on the SAME resolved window load_overview()
    used, so the Detections panel and every count around it describe one window
    rather than two. is_experiment_row is applied here for the same reason it is
    applied in load_overview: without it the page would correlate benchmark
    traffic and report relationships between harness runs as findings.

    Cost is dominated by IOC extraction (~760ms warm) -- the same work that
    makes load_overview expensive -- so this is cached on the same TTL and
    pre-warmed by warm_caches(). Correlation and detection themselves are ~16ms
    combined once the MITRE cache is hot.

    Returns detect()'s full result, all three buckets. The panel renders the
    surfaced ones, but suppressed and unmatched stay available so the UI can
    always say what it is NOT showing and why.
    """
    from threat_intel import correlation, detection, severity, alert_records
    from threat_intel.ioc_extractor import build_iocs

    now = time.time()
    key = (preset or "ALL", instance or "all")
    hit = _detect_cache.get(key)
    if hit is not None and (now - hit[1]) < TTL:
        return hit[0]

    win = load_overview(preset=preset or "ALL", instance=instance)["window"]
    rows = [r for r in storage.query_range(win["start"], win["end"],
                                           instance=instance)
            if not is_experiment_row(r)]

    # Session rows only. The auth table is not passed: v1 correlates no auth
    # stream (shared_credential is declared but disabled), and feeding 75k auth
    # rows through the extractor to produce credential IOCs nothing reads would
    # roughly triple the cost of this call.
    indicators = build_iocs(rows).records()
    rels = correlation.correlate(
        sessions=correlation.sessions_from_rows(rows), indicators=indicators)
    # Detection -> Severity, in that order and as separate passes. detect()
    # still emits no severity of its own; rate_detections() annotates every
    # bucket afterwards, so a suppressed-but-critical finding stays findable.
    out = severity.rate_detections(detection.detect(rels))

    # Detections that clear the alerting bar become durable alert records.
    # Safe on a cached read path: upserts are idempotent, so a re-render
    # refreshes the counts of an alert that already exists rather than
    # creating a second one, and analyst state is never touched.
    #
    # RECORDING only -- no delivery. route_alerts() sends over the network,
    # and a page render is the wrong place to do that: it would fire on every
    # cache miss, from whatever thread served the request. Delivery happens
    # once per process in warm_caches().
    #
    # Wrapped because alerting must never be able to break the dashboard: a
    # locked DB or a malformed ruleset costs the alert queue, not the page.
    try:
        alert_records.raise_alerts(out, instance=instance or "default")
    except Exception as e:
        print(f"[alerts] could not record alerts: {e}")

    _detect_cache[key] = (out, now)
    return out


_session_cmd_cache = {}    # session_id -> (rows, fetched_at)


def load_session_commands(session_id, instance=None):
    """Ordered command rows for ONE session — the Command Evidence timeline.

    Correlation's `evidence.sample` is capped at 12 commands and carries no
    timestamps, because it exists to identify a shared sequence, not to be a
    transcript. The investigation view needs the real thing: every command, in
    order, with its time and its MITRE tag. That is a plain indexed lookup on
    one session, so it is fetched on demand rather than widening correlation's
    evidence with a transcript every relationship would carry and almost none
    would show.

    Cached per session: an analyst expanding, collapsing and re-expanding one
    detection should hit the DB once.
    """
    now = time.time()
    key = (session_id, instance or "all")
    hit = _session_cmd_cache.get(key)
    if hit is not None and (now - hit[1]) < TTL:
        return hit[0]
    rows = storage.query_session(session_id, instance=instance)
    _session_cmd_cache[key] = (rows, now)
    return rows


def clear_caches():
    """Drop every cached derivation. The ONE place that knows them all.

    The Refresh button used to clear four of these inline and miss
    _detect_cache and _session_cmd_cache, so a manual refresh left detections,
    severity and alerts up to five minutes stale while the rest of the page
    updated -- the two halves of the screen disagreeing is exactly what the
    button exists to prevent. Adding a cache should mean editing this function,
    not hunting for every caller.
    """
    _cache["all_ts"] = 0
    _cache["auth_ts"] = 0
    _cache["raw_rows_ts"] = 0
    _feed_cache.clear()
    _page_cache.clear()
    _overview_cache.clear()
    _detect_cache.clear()
    _session_cmd_cache.clear()
    try:
        from api.services.common import _ioc_cache
        _ioc_cache.clear()
    except Exception:
        pass        # the API package is optional for a dashboard-only install


def load_alerts(instance=None, state=None, limit=200):
    """Alert records for the dashboard.

    Deliberately NOT TTL-cached, unlike everything else in this module. Alert
    state changes the instant a person clicks Acknowledge, and serving a
    five-minute-old copy would make the button look broken. It is also the one
    cheap read here -- an indexed lookup over a handful of rows, not a scan of
    78k.
    """
    return storage.query_alerts(instance=instance or "default", state=state,
                                limit=limit)


def load_alert_counts(instance=None):
    """{state: n}, counted in SQL rather than by len()-ing a fetch."""
    return storage.alert_counts(instance=instance or "default")


def warm_caches(background=True):
    """Pre-compute the heavy caches so no CLICK ever pays for them.

    The expensive work is per (preset, sensor): re-tagging every command
    through the MITRE rules (~1.0s) and extracting IOCs (~1.3s, dominated by
    CyberLab's 75k auth rows). Those are cached, but the cache is filled
    lazily — so the FIRST click on each sensor paid ~3s while every later one
    took ~0.4s. Doing it up front on a daemon thread moves that cost off the
    interactive path entirely; nothing blocks on it and a failure just leaves
    the cache cold, exactly as before.
    """
    def _run():
        try:
            load_all()
            sensors = [None] + [s["instance"] for s in get_sensor_summary()]
            for inst in sensors:
                try:
                    load_overview(preset="ALL", instance=inst)
                    # Correlation/detection ride along: same window, same
                    # exclusion policy, and its IOC extraction is the one
                    # genuinely slow step on the interactive path.
                    load_detections(preset="ALL", instance=inst)
                except Exception:
                    pass          # a cold cache is the old behaviour, not a failure
        except Exception:
            pass
        # Delivery, once per process rather than per render. All network sinks
        # ship disabled, so by default this writes the local JSONL feed and
        # nothing leaves the host.
        try:
            from threat_intel import alert_records
            alert_records.route_alerts()
        except Exception as e:
            print(f"[alerts] routing skipped: {e}")

    if not background:
        return _run()
    import threading
    threading.Thread(target=_run, name="hp-warm-caches", daemon=True).start()


def load_raw_session_rows() -> list:
    """Raw dict rows (not the parsed load_all() DataFrame) — the shape
    threat_intel.ioc_extractor.build_iocs() expects: cmd/response/src_ip/
    session_id/fi_score/timestamp/instance per row.

    The one reader that genuinely needs `response` (IOCs are extracted from
    command output as well as the command), so this is the full-width query.
    It is only reached by the "Generate Intelligence" button, never by a page
    render — which is why load_all() gets its own narrower query instead."""
    now = time.time()
    if _cache.get("raw_rows") is not None and (now - _cache.get("raw_rows_ts", 0)) < TTL:
        return _cache["raw_rows"]

    rows = storage.query_all()
    _cache["raw_rows"] = rows
    _cache["raw_rows_ts"] = now
    return rows

# The DB holds both real honeypot traffic and the experiment-sandbox runs, which
# share the same tables. Experiment harnesses put a run label in src_ip
# ("eval_sync_on", "partc_cloud_12580") where real traffic has an IP, so the
# label prefix is what separates them. Presentation-only: the data is untouched
# on disk, and the sandbox's own scripts read it exactly as before.
EXPERIMENT_SRC_PREFIXES = (
    "eval", "parta_", "partb_", "partc_", "hrreplay_", "bench",
    "ml4net", "quickcheck", "cloudcheck", "sanity", "smoke", "replay",
)
# Harness rows whose src_ip is a bare token rather than a prefixed label
# ("t", "x", "v", "t1", "test"...). Matched by SHAPE, not by a growing list of
# literals: a real source is either a dotted IP or CyberLab's 16-char hashed
# identifier, so anything non-numeric and shorter than 6 characters is a label
# somebody typed. Well-known public resolvers are listed because they appear as
# test *targets*; none of them ever initiates an SSH connection to a honeypot.
_HARNESS_TOKEN_MAXLEN = 5
EXPERIMENT_SRC_EXACT = {"localhost", "-", "", "8.8.8.8", "8.8.4.4",
                        "1.1.1.1", "9.9.9.9"}

# NOTE: "cyberlab" is deliberately NOT a prefix any more. The CyberLab Cowrie
# capture is now imported as real sensor traffic (instance="CyberLab", src_ip =
# the dataset's hashed attacker identifier), so filtering on that string would
# hide the only genuine attacker data the dashboard has.


def drop_experiment_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Hide experiment-sandbox traffic from the dashboard.

    Without this the headline numbers are dominated by benchmark runs — 130,643
    of 132,282 rows — so "Unique Attackers" counts experiment runs rather than
    attackers."""
    if df.empty or "src_ip" not in df.columns:
        return df
    ip = df["src_ip"].astype(str)
    # str.startswith takes a tuple — one pass instead of one per prefix
    drop = ip.str.startswith(EXPERIMENT_SRC_PREFIXES, na=False)
    drop |= ip.str.lower().isin(EXPERIMENT_SRC_EXACT)
    drop |= (ip.str.len() <= _HARNESS_TOKEN_MAXLEN) & ~ip.str.contains(r"\.", na=False)
    # Loopback, private and RFC5737 documentation addresses are test targets,
    # never a real attacker. Matched by range rather than a list of literals so
    # a new test address does not need a code change to be excluded.
    drop |= ip.map(_is_non_routable)
    return df[~drop]


@functools.lru_cache(maxsize=8192)
def _is_experiment_ip(ip: str) -> bool:
    """The whole experiment/harness test, keyed on src_ip alone.

    Every rule below depends only on the address, and addresses repeat
    enormously: a sensor switch ran this 78,208 times over 766 distinct IPs,
    with ipaddress.ip_address() re-parsing each one — 0.49s of pure repeat
    work. Memoised, it is 766 real evaluations.
    """
    if ip.startswith(EXPERIMENT_SRC_PREFIXES):
        return True
    if ip.lower() in EXPERIMENT_SRC_EXACT:
        return True
    if len(ip) <= _HARNESS_TOKEN_MAXLEN and "." not in ip:
        return True
    return _is_non_routable(ip)


def is_experiment_row(row) -> bool:
    """Row-level twin of drop_experiment_rows()'s DataFrame predicate.

    Same rules, one row at a time, so callers that work in plain dicts
    (threat_intel.aggregator.aggregate_overview's exclude_row hook) apply
    exactly the same definition of "not real attacker traffic" the
    DataFrame path does -- otherwise the same page shows two different
    command counts."""
    return _is_experiment_ip(str(row.get("src_ip") or ""))


def _is_non_routable(value) -> bool:
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return False        # a hashed identifier is not an IP; keep it
    return not addr.is_global


def load_all() -> pd.DataFrame:
    now = time.time()
    if _cache["all_df"] is not None and (now - _cache["all_ts"]) < TTL:
        return _cache["all_df"]

    # Deliberately NOT load_raw_session_rows(): this runs on every page render,
    # and it never reads `response`. Skipping that column alone is ~460ms ->
    # ~145ms. Anything here that does need it should use storage.query_session().
    df = storage.query_all_df()
    df = drop_experiment_rows(df)
    if df.empty:
        df = pd.DataFrame()
    else:
        df["fi_score"]   = df.get("fi_score",   0).fillna(0).astype(int)
        df["latency_ms"] = df.get("latency_ms", 0).fillna(0).astype(float)
        df["agent"]      = df.get("agent",      "unknown").fillna("unknown")
        df["session_id"] = df.get("session_id", "default").fillna("default")
        df["src_ip"]     = df.get("src_ip",     "?").fillna("?")
        if "instance" not in df.columns:
            df["instance"] = "default"
        else:
            df["instance"] = df["instance"].fillna("default")
        # ATT&CK tags applied here rather than stored in the logs: the mapper is
        # pure pattern matching over the command text, so historical rows get
        # exactly the answer they'd have got live, and editing a rule file in
        # threat_intel/rules/ re-tags everything on the next refresh with no
        # migration. Cached per UNIQUE command (4.3k uniques for 132k rows).
        #
        # Two shapes are stored deliberately:
        #   technique_id/technique/tactic  SCALAR, the primary tag from tag().
        #       Every count on this page divides by rows, so these must stay
        #       one-per-row or coverage %, per-IP totals and tactic counts all
        #       inflate.
        #   technique_ids                  LIST, the full chain from tag_all().
        #       Used only by the technique bar chart, which explodes it. A
        #       dropper line like `wget …; chmod +x …; sh …; rm …` carries five
        #       techniques; the primary tag alone would show one.
        _cmds  = df["cmd"].astype(str)
        _uniq  = _cmds.unique()
        _lut     = {c: _mitre_tag(c)     for c in _uniq}
        _lut_all = {c: _mitre_tag_all(c) for c in _uniq}
        df["technique_id"] = _cmds.map(lambda c: (_lut.get(c) or {}).get("technique_id"))
        df["technique"]    = _cmds.map(lambda c: (_lut.get(c) or {}).get("technique"))
        df["tactic"]       = _cmds.map(lambda c: (_lut.get(c) or {}).get("tactic"))
        df["technique_ids"] = _cmds.map(
            lambda c: [x["technique_id"] for x in (_lut_all.get(c) or [])])
        df["timestamp"]  = pd.to_datetime(df.get("timestamp", ""), errors="coerce")

    _cache["all_df"] = df
    _cache["all_ts"] = now
    return df

def load_auth_log() -> list:
    now = time.time()
    if _cache["auth"] is not None and (now - _cache["auth_ts"]) < TTL:
        return _cache["auth"]

    data = storage.query_auth()
    _cache["auth"] = data
    _cache["auth_ts"] = now
    return data

def get_sensor_summary() -> list:
    """One row per HydraPoT instance actually present in the data (not per
    directory) — {'instance', 'commands', 'sessions', 'src_ips'}, sorted by
    command volume."""
    df = load_all()
    if df.empty or "instance" not in df.columns:
        return []
    out = []
    for instance, g in df.groupby("instance"):
        out.append({
            "instance": instance,
            "commands": len(g),
            "sessions": g["session_id"].nunique(),
            "src_ips":  g["src_ip"].nunique(),
        })
    return sorted(out, key=lambda r: r["commands"], reverse=True)


_health_cache = {"v": None, "ts": 0}


def agent_health():
    """Real component checks for the sidebar status panel.

    Every row is an actual probe, never a hardcoded "Online" — a status light
    that is always green tells an operator nothing. Cheap enough to run behind
    a short TTL: the only network call is one non-blocking TCP connect.

    Returns [(name, ok, detail)]."""
    now = time.time()
    if _health_cache["v"] is not None and now - _health_cache["ts"] < 15:
        return _health_cache["v"]

    import glob
    import os
    import socket
    from config_loader import load_config as _load_config

    rows = []

    try:
        cfg = _load_config()
    except Exception:
        cfg = None

    # Honeypot — is the SSH front door actually accepting connections? This is
    # the row that answers "is HydraPoT running at all", so it comes first.
    # Without it the panel could read all-green while nothing was listening.
    try:
        hp_host = cfg.honeypot.host
        hp_port = int(cfg.honeypot.port)
        with socket.socket() as s:
            s.settimeout(0.35)
            up = s.connect_ex((hp_host, hp_port)) == 0
        rows.append(("Honeypot", up, f"{hp_host}:{hp_port}"))
    except Exception:
        rows.append(("Honeypot", False, "not listening"))

    # Router — config parses and a routing table exists
    try:
        n = len(getattr(cfg.routing, "fi_routing", {}) or {})
        rows.append(("Router", n > 0, f"{n} FI bands"))
    except Exception:
        rows.append(("Router", False, "config error"))

    # Cowrie — is the backend actually accepting connections?
    try:
        host = cfg.agents.cowrie.host, cfg.agents.cowrie.port
        with socket.socket() as s:
            s.settimeout(0.35)
            ok = s.connect_ex((host[0], int(host[1]))) == 0
        rows.append(("Cowrie Agent", ok, f"{host[0]}:{host[1]}"))
    except Exception:
        rows.append(("Cowrie Agent", False, "unreachable"))

    # Local LLM — enabled AND the weights are actually on disk
    try:
        od = cfg.agents.on_device
        gguf = getattr(od, "gguf_file", "") or ""
        found = bool(gguf) and any(
            os.path.basename(p) == os.path.basename(gguf)
            for p in glob.glob(os.path.expanduser("~/.cache/huggingface/**/*.gguf"), recursive=True)
        )
        rows.append(("Local LLM", bool(getattr(od, "enabled", False)) and found,
                     os.path.basename(gguf) or "no model"))
    except Exception:
        rows.append(("Local LLM", False, "unavailable"))

    # Cloud LLM — enabled AND the API key is present in the environment
    try:
        cl = cfg.agents.cloud
        keyed = bool(os.environ.get(getattr(cl, "api_key_env", "") or "", ""))
        rows.append(("Cloud LLM", bool(getattr(cl, "enabled", False)) and keyed,
                     getattr(cl, "model", "") if keyed else "no API key"))
    except Exception:
        rows.append(("Cloud LLM", False, "unavailable"))

    # SIEM — an export plugin is configured and switched on
    try:
        import yaml
        _root = os.path.dirname(os.path.abspath(storage.__file__))
        ok, detail = False, "not configured"
        for fp in glob.glob(os.path.join(_root, "plugins", "export", "*.yml")):
            y = yaml.safe_load(open(fp)) or {}
            if y.get("enabled"):
                ok, detail = True, os.path.basename(fp).replace(".yml", "")
                break
            detail = "disabled"
        rows.append(("SIEM Export", ok, detail))
    except Exception:
        rows.append(("SIEM Export", False, "unavailable"))

    _health_cache.update(v=rows, ts=now)
    return rows
