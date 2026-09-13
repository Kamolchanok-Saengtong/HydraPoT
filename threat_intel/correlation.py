"""
threat_intel/correlation.py — the correlation engine.

    Aggregation  ->  Correlation  ->  relationships  ->  (later) Detection

Establishes that separate observations are RELATED, and states on what basis.
It does not decide whether a relationship matters, how dangerous it is, or what
it implies about an attacker -- those are detection decisions and analyst
judgements. The engine's only claim is:

    these N observations share an identical value for key K

Everything past that ("same script", "same operator", "same campaign") is
interpretation. A correlation layer that bakes interpretation into its output
produces relationships nobody can audit, and they go stale the moment the
threat landscape shifts. So each relationship carries a `statement` describing
what was OBSERVED, and that is the only wording a UI may render.

Design constraints this file keeps:

  * PURE. No database access, no re-derivation of facts. Callers pass in the
    records they already loaded; the engine groups them. That keeps it cheap
    (one pass over data the dashboard has in hand) and trivially testable.
  * NO DATASET TUNING. There are no thresholds, no minimum cluster sizes, no
    privileged strategy. The capture that happened to be on disk while this
    was written proved the mechanisms CAN fire; it does not define what they
    should look for. A window with no relationships is a correct result.
  * THE STREAMS ARE NEVER JOINED. storage.py's `auth` table carries no
    session_id, so any session<->login link would be an invented (src_ip,
    time) guess. Each strategy declares its stream and stays inside it.
  * NO PRIVILEGED KEY. Relative importance of one relationship over another is
    a detection concern, so relationships come back in a stable, explainable
    order (most members first), not a ranked one.

Strategies live in threat_intel/rules/correlation_strategies.yml. Adding one is
a config edit; the engine itself knows nothing about what any key means.
"""
import hashlib
import os

import yaml

STRATEGIES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "rules", "correlation_strategies.yml")

# Only `exact` is implemented. Normalised matching would require deciding what
# counts as "the same" command (fold whitespace? argument order? paths?), which
# is a judgement rather than an observation -- and judgements do not belong in
# this layer.
_SUPPORTED_MATCH = {"exact"}

# Keyed BY PATH, not a single slot. With one global slot the `path` argument
# was silently ignored the moment any ruleset had been loaded: the second
# caller got the first caller's strategies back and nothing said so. That is
# invisible in production (one ruleset) and quietly fatal in a test, where it
# makes a case asserting on a custom ruleset actually assert on the shipped
# one -- passing for the wrong reason.
_strategies = {}        # path -> [strategy, ...]
_load_errors = {}       # path -> [(id, message), ...]


# ── key extractors ───────────────────────────────────────────────────────────
# Each returns the grouping key for one record, or None to exclude it. They are
# deliberately dumb: extract a value, do not interpret it.

def _key_command_sequence(session):
    """Byte-identical ordered command text, hashed for a compact key.

    Hashed rather than stored whole so a relationship row stays small; the
    hash is an identifier for the sequence, not a claim about it.
    """
    cmds = session.get("commands_ordered")
    if not cmds:
        return None
    joined = "\n".join(c or "" for c in cmds)
    return hashlib.sha1(joined.encode("utf-8", "replace")).hexdigest()


def _key_src_ip(session):
    return session.get("src_ip") or None


def _key_indicator_value(indicator):
    t, v = indicator.get("type"), indicator.get("value")
    return f"{t}:{v}" if t and v else None


def _key_credential_pair(auth_row):
    u, p = auth_row.get("username"), auth_row.get("password")
    return f"{u}:{p}" if u is not None and p is not None else None


KEY_EXTRACTORS = {
    "command_sequence": _key_command_sequence,
    "src_ip": _key_src_ip,
    "indicator_value": _key_indicator_value,
    "credential_pair": _key_credential_pair,
}


# ── evidence builders ────────────────────────────────────────────────────────
# What IS the shared thing? The grouping key answers that for a machine (a
# sha1, an IP), not for an analyst or for a downstream rule. An evidence
# builder describes the shared value in factual terms.
#
# Keyed by strategy key, NOT applied to every relationship, and that
# distinction is load-bearing: in a `command_sequence` group every member has
# the same sequence by construction, so one member describes them all. In a
# `src_ip` group members have DIFFERENT sequences, so publishing one member's
# commands as the group's evidence would be simply false. A key with no builder
# gets no evidence, which is the honest result.
#
# These are still observations. "This sequence contains T1105" is a fact
# produced by the MITRE layer below; whether that makes the relationship
# interesting is a detection decision, made elsewhere.

def _evidence_command_sequence(session):
    from threat_intel.mitre_mapper import tag_all   # lazy: keeps import cost
    cmds = session.get("commands_ordered") or []    # off callers that never
    techs, tactics = {}, {}                         # correlate sequences
    for c in cmds:
        for t in tag_all(c or ""):
            if t.get("technique_id"):
                techs[t["technique_id"]] = None
            if t.get("tactic"):
                tactics[t["tactic"]] = None
    return {
        "sequence_length": len(cmds),
        "distinct_commands": len(set(cmds)),
        "technique_ids": list(techs),     # insertion order = execution order
        "tactics": list(tactics),
        "sample": cmds[:12],              # for the UI; never a matching input
    }


EVIDENCE_BUILDERS = {
    "command_sequence": _evidence_command_sequence,
}


# ── strategy loading ─────────────────────────────────────────────────────────

def load_strategies(path: str = STRATEGIES_PATH, force: bool = False) -> list:
    """Parse and validate correlation_strategies.yml. Cached after first call.

    A malformed strategy is skipped with a warning rather than breaking the
    caller, and the reason is kept in load_errors() -- the same philosophy as
    mitre_mapper.load_rules() and severity.load_rules(). A strategy naming a
    key the engine cannot extract is skipped LOUDLY: silently producing no
    relationships would look identical to "there was nothing to correlate".
    """
    if path in _strategies and not force:
        return _strategies[path]

    out, errors = [], []
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[correlation] cannot read {path}: {e}")
        _strategies[path] = []
        _load_errors[path] = [(os.path.basename(path), str(e))]
        return _strategies[path]

    for raw in (doc.get("strategies") or []):
        sid = raw.get("id", "<no id>")
        try:
            if not raw.get("enabled", False):
                continue
            key = raw.get("key")
            if key not in KEY_EXTRACTORS:
                raise ValueError(f"unknown key {key!r}; "
                                 f"known: {sorted(KEY_EXTRACTORS)}")
            match = raw.get("match", "exact")
            if match not in _SUPPORTED_MATCH:
                raise ValueError(f"unsupported match {match!r}; "
                                 f"only {sorted(_SUPPORTED_MATCH)} implemented")
            statement = (raw.get("statement") or "").strip()
            if not statement:
                raise ValueError("strategy has no `statement`")
            stream = raw.get("stream")
            if not stream:
                raise ValueError("strategy has no `stream`")
            out.append({"id": sid, "stream": stream, "key": key,
                        "match": match, "statement": statement})
        except Exception as e:
            errors.append((sid, str(e)))
            print(f"[correlation] skipping strategy {sid}: {e}")

    seen = set()
    for s in out:
        if s["id"] in seen:
            errors.append((s["id"], "duplicate strategy id"))
            print(f"[correlation] WARNING: duplicate strategy id {s['id']}")
        seen.add(s["id"])

    _strategies[path], _load_errors[path] = out, errors
    return out


def load_errors(path: str = STRATEGIES_PATH) -> list:
    """[(strategy_id, message)] from the last load of `path` — for the rule
    validator, and for telling "nothing correlated" apart from "the ruleset
    failed to load"."""
    load_strategies(path)
    return _load_errors.get(path, [])


# ── input adapter ────────────────────────────────────────────────────────────

def sessions_from_rows(rows) -> list:
    """Turn raw event rows the caller ALREADY HAS into engine input.

    Aggregation's per-session records carry counts, not the ordered command
    text, and aggregation is closed -- so rather than reach back into the
    database (which would break this layer's purity) or widen a finished layer,
    correlation adapts the rows the dashboard has already loaded for its own
    charts. One pass, no I/O.

    Row order is preserved as execution order, exactly as _summarize() and the
    kill-chain view already assume; `command_sequence` is therefore an ordered
    key, and sorting here would silently destroy that.
    """
    out = {}
    for r in rows:
        sid = r.get("session_id")
        if sid is None:
            continue
        s = out.get(sid)
        if s is None:
            s = out[sid] = {"session_id": sid, "src_ip": r.get("src_ip"),
                            "instance": r.get("instance"), "commands_ordered": [],
                            "first_seen": None, "last_seen": None}
        cmd = r.get("cmd")
        if cmd:
            s["commands_ordered"].append(cmd)
        ts = r.get("timestamp")
        if ts:
            if s["first_seen"] is None or ts < s["first_seen"]:
                s["first_seen"] = ts
            if s["last_seen"] is None or ts > s["last_seen"]:
                s["last_seen"] = ts
    return list(out.values())


# ── the engine ───────────────────────────────────────────────────────────────

def _relationship(strategy, key_value, members, sessions_by_id, evidence=None):
    """One relationship record. `distinct_sources` is reported as a FACT, not
    a verdict: whether more than one source address is significant is the
    analyst's call, not this layer's."""
    srcs, firsts, lasts, scopes = set(), [], [], set()
    for sid in members:
        s = sessions_by_id.get(sid) or {}
        if s.get("src_ip"):
            srcs.add(s["src_ip"])
        if s.get("first_seen"):
            firsts.append(s["first_seen"])
        if s.get("last_seen"):
            lasts.append(s["last_seen"])
        if s.get("instance"):
            scopes.add(s["instance"])
    return {
        "link_type": strategy["id"],
        "link_value": key_value,
        "statement": strategy["statement"],
        "members": sorted(members),
        "member_count": len(members),
        "distinct_sources": len(srcs),
        "src_ips": sorted(srcs),
        "first_seen": min(firsts) if firsts else None,
        "last_seen": max(lasts) if lasts else None,
        "scope": sorted(scopes),
        # Absent (None) when the strategy's key has no evidence builder -- see
        # EVIDENCE_BUILDERS. Downstream MUST treat absent as "unknown", never
        # as zero, or a rule written for sequences will silently pass judgement
        # on indicator and address links it knows nothing about.
        "evidence": evidence,
    }


def correlate(sessions=None, indicators=None, auth_rows=None,
              path: str = STRATEGIES_PATH) -> list:
    """Group observations by each enabled strategy's key.

    sessions   : [{session_id, src_ip, instance, first_seen, last_seen,
                   commands_ordered: [...]}, ...]   -- caller-supplied, the
                 engine never queries for them.
    indicators : IOCStore.records() output; each carries a `sessions` set.
    auth_rows  : auth-stream records (only read by auth-stream strategies).

    -> [relationship, ...] for every key shared by MORE THAN ONE member. A key
    held by a single member is not a relationship; it is just a value.

    Ordered by member_count then link_type/link_value so output is stable and
    explainable. That ordering is NOT a ranking of importance -- no strategy is
    privileged over another here.
    """
    sessions = sessions or []
    indicators = indicators or []
    auth_rows = auth_rows or []
    sessions_by_id = {s.get("session_id"): s for s in sessions}

    out = []
    for strat in load_strategies(path):
        extract = KEY_EXTRACTORS[strat["key"]]
        groups = {}

        if strat["stream"] == "sessions":
            for s in sessions:
                k = extract(s)
                if k is None:
                    continue
                groups.setdefault(k, set()).add(s.get("session_id"))

        elif strat["stream"] == "indicators":
            # An indicator already carries the sessions it was seen in, so the
            # grouping is the indicator itself.
            for ind in indicators:
                k = extract(ind)
                if k is None:
                    continue
                members = ind.get("sessions") or set()
                if members:
                    groups.setdefault(k, set()).update(members)

        elif strat["stream"] == "auth":
            # Kept in its own stream and never joined to sessions: the auth
            # table has no session_id. Members are auth row ids, so these
            # relationships are about login attempts, not sessions.
            for a in auth_rows:
                k = extract(a)
                if k is None:
                    continue
                rid = a.get("id")
                if rid is not None:
                    groups.setdefault(k, set()).add(rid)
        else:
            continue        # unknown stream -- load_strategies already warned

        build_evidence = EVIDENCE_BUILDERS.get(strat["key"])
        for key_value, members in groups.items():
            if len(members) <= 1:
                continue
            evidence = None
            if build_evidence:
                # Any member describes the group: they were grouped BY this
                # value, so it is identical across all of them.
                rep = sessions_by_id.get(sorted(members)[0])
                if rep:
                    evidence = build_evidence(rep)
            out.append(_relationship(strat, key_value, members,
                                     sessions_by_id, evidence))

    out.sort(key=lambda r: (-r["member_count"], r["link_type"], str(r["link_value"])))
    return out
