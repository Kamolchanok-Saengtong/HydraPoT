"""
experiment_data/PartB/run_partB.py — Part B: Context Preservation & SRi Overhead
─────────────────────────────────────────────────────────────────────
B1  Context Preservation — 7 forced agent-pair combinations
    Forces routing via handle(..., force_agent=X) — an eval-only
    parameter added to main.py's handle(). Production calls never
    pass force_agent so production behavior is 100% unchanged.

B2  Context-Synchronization Overhead (session-level)
    Runs the FULL benchmark (all pairs) as ONE continuous session,
    under natural routing, twice per trial:
      - sync_on : PromptManager injects Hi + SRi context into prompts
      - sync_off: same routing, same tracking, but context is NOT
                  injected into the prompt (sync_state=False)
    Measures the TOTAL session latency difference. Routing and state
    tracking are identical in both conditions — only prompt content
    differs — so the delta isolates the cost of context injection.

Output:
  experiment_data/results/partB/<creator>_<reader>/context_preservation.jsonl
  experiment_data/results/partB/summary.json

Usage:
    python experiment_data/PartB/run_partB.py --trials 3
    python experiment_data/PartB/run_partB.py --b1-only
    python experiment_data/PartB/run_partB.py --b2-only
"""

import argparse
import glob
import json
import os
import re
import sys
import time
import statistics
from datetime import datetime

# PartB/, not this sub-folder: paths below are relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
for p in (_ROOT, _NSC, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

sys.path.insert(0, os.path.join(_NSC, "PartA"))
from overhead import _FakeChannel

# Route each arm's log to its own Part folder (see _paths.py).
from _paths import session_dir_for



BENCHMARK_DEFAULT = os.path.join(
    _ROOT, "dataset", "stateful_benchmark_ml4net_deduped.json"
)
RESULTS_DIR = os.path.join(_NSC, "results", "partB")

AGENT_PAIRS = [
    ("cowrie",    "cowrie"),
    ("cowrie",    "on_device"),
    ("cowrie",    "cloud"),
    ("on_device", "on_device"),
    ("on_device", "cloud"),
    ("cloud",     "on_device"),
    ("cloud",     "cloud"),
    # LLM-creates → Cowrie-reads pairs. Architecturally Cowrie reads its own
    # container filesystem, so it cannot see state an LLM only tracked in
    # HydraPoT's in-memory SYSTEM_STATE — expected to score ~0%. Kept available
    # (opt-in via --pairs) to *document* that limitation, which is exactly why
    # production routing never creates-on-LLM then reads-on-Cowrie.
    ("on_device", "cowrie"),
    ("cloud",     "cowrie"),
]

def pair_label(creator, reader):
    return f"{creator}→{reader}"


# ─── benchmark loader ─────────────────────────────────────────────────────────

def _normalize_record(r):
    """
    Flatten a benchmark record to the shape run_pair()/_is_skippable() expect:
    id, category, fi, source, setup, creator, reader, ground_truth, ok.

    partB_stateful_benchmark.json is already flat and passes through as-is.
    stateful_benchmark_ml4net*.json nests the pair under "pair":
      {setup_cmd, test_cmd, fi_setup, fi_test, ground_truth, blocked} —
    setup_cmd IS the creator action (no separate prep step in this dataset),
    test_cmd is the reader.
    """
    p = r.get("pair")
    if p is None:
        return r

    ground_truth = p.get("ground_truth") or ""
    return {
        "id":           r.get("session_id"),
        "category":     f"ml4net_fi{p.get('fi_setup')}_fi{p.get('fi_test')}",
        "fi":           p.get("fi_setup"),
        "source":       r.get("source", "ml4net"),
        "setup":        None,
        "creator":      p.get("setup_cmd"),
        "reader":       p.get("test_cmd"),
        "ground_truth": ground_truth,
        # empty ground_truth is a VALID target for silent-success commands
        # (chmod, cd, mkdir, ...) — only a real Docker "blocked" verdict
        # makes a pair unusable, not the mere absence of stdout.
        "ok":           not p.get("blocked", False),
    }


# ── Scoring scope: which pairs actually measure cross-agent STATE ────────────
#
# Three kinds of pair can never be scored fairly here, for reasons unrelated to
# whether state synchronization worked. They are identified purely from the
# BENCHMARK DEFINITION (command text + recorded ground truth) — never from
# whether a run passed or failed — so the scope is fixed before any result
# exists and cannot be tuned to flatter the numbers.
_TRANSFORM_TOOLS_RE = re.compile(
    r"\b(gzip|gunzip|base64|md5sum|sha1sum|sha256sum|sha512sum|tar|zip|"
    r"compress|xxd|od|openssl|cksum|b2sum)\b"
)
# Kernel-managed pseudo-filesystems. A real Linux refuses to create files here,
# so `cat` prints "No such file or directory" — but the recorded ground truth is
# '' because collection captured stdout only at the time (stderr merging was
# added later and these were never re-collected). That ground truth therefore
# matches neither a correct honeypot nor a real system.
_PSEUDO_FS_PATHS = ("/proc", "/sys", "/dev/pts", "/lib/init/rw")


def _has_binary(text):
    return any(ord(c) < 9 or (13 < ord(c) < 32) or ord(c) == 127 for c in (text or ""))


def exclusion_reason(rec):
    """Reason this pair cannot measure state preservation, or None if it can."""
    gt      = rec.get("ground_truth") or ""
    creator = rec.get("creator") or ""
    reader  = rec.get("reader") or ""
    if _has_binary(gt):
        return "binary ground truth (no LLM can reproduce raw bytes)"
    if _TRANSFORM_TOOLS_RE.search(reader):
        return "reader runs a deterministic transform (LLM cannot compute it)"
    if not gt.strip() and any(p in creator or p in reader for p in _PSEUDO_FS_PATHS):
        return "kernel-refused write (recorded ground truth is invalid)"
    return None


def load_benchmark(path):
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    records = [_normalize_record(r) for r in raw]
    valid = [r for r in records if r.get("ok")]
    n_silent = sum(1 for r in valid if not r.get("ground_truth", "").strip())

    for r in valid:
        r["excluded_reason"] = exclusion_reason(r)
    excluded = [r for r in valid if r["excluded_reason"]]
    scored   = len(valid) - len(excluded)

    print(f"[benchmark] loaded {len(valid)}/{len(records)} valid pairs from {path} "
          f"({n_silent} silent-success, i.e. empty ground truth)")
    print(f"[benchmark] scoring scope: {scored} state-preservation pairs "
          f"({len(excluded)} excluded, listed below)")
    for r in excluded:
        print(f"    excluded: {(r.get('reader') or '')[:44]:<44} — {r['excluded_reason']}")

    return valid


# ─── output matching ──────────────────────────────────────────────────────────

def normalize(text):
    if text is None:
        return ""
    return " ".join(text.strip().lower().split())


def is_match(agent_output, ground_truth):
    ao = normalize(agent_output)
    gt = normalize(ground_truth)
    if not gt:
        # real command produced no stdout (chmod, cd, mkdir, ...) — correct
        # agent behavior is to ALSO produce no stdout.
        return (ao == ""), ("silent_success" if ao == "" else "silent_success_mismatch")
    if ao == gt:
        return True, "exact"
    if gt in ao:
        return True, "substring"
    return False, "no_match"


# ─── state propagation ────────────────────────────────────────────────────────
# B1's question is whether the creator's state REACHED the reader, which is a
# property of the pipeline, not of the model. Output matching cannot answer it:
# a lost file and a badly formatted answer both read as a mismatch. So check the
# state store and the reader's own prompt instead.

_REDIR_RE  = re.compile(r">>?\s*([^\s;|&<>\"']+)")
_QUOTED_RE = re.compile(r"""'[^']*'|\"[^\"]*\"""")


def _operands(cmd: str):
    """File operands a command names, relative forms included.

    Not an absolute-path regex: most of this benchmark writes to bare names
    (`echo ... > usb_ver`, `chmod 777 usb_ver`), which such a regex misses
    entirely — it matched 7 of 29 pairs.
    """
    cmd = cmd or ""
    out = set(_REDIR_RE.findall(cmd))          # redirect target is unambiguous
    body = _QUOTED_RE.sub(" ", cmd)            # drop payloads: they are data
    for tok in body.replace(">", " ").replace("|", " ").split()[1:]:
        tok = tok.strip("'\"`")
        if not tok or tok.startswith("-") or tok.isdigit():
            continue
        if tok in ("&&", "||", ";", "<", "sudo"):
            continue
        out.add(tok)
    return out


def target_paths(pair_rec):
    """Operands named by BOTH commands — what the creator makes and the reader needs.

    Intersection, not union: the creator may touch scratch paths the reader never
    looks at, and requiring those would fail a pair whose state did arrive.
    """
    shared = _operands(pair_rec.get("creator")) & _operands(pair_rec.get("reader"))
    return sorted(shared) or sorted(_REDIR_RE.findall(pair_rec.get("creator") or ""))


def state_in_prompt(prompt: str, targets, cwd: str) -> bool:
    """Is the creator's state in the reader's STATE BLOCK — not merely anywhere
    in the prompt?

    `path in prompt` is not a valid test: the reader's own command sits inside
    the prompt, so `cat f` satisfies it by naming `f` itself. That version
    scored 100% even under sync_state=False, where no state is injected at all
    -- it was measuring the echo of the command, not context transfer.

    PromptManager renders each tracked file as `file '<path>' EXISTS` (see
    prompt_manager.py's sync_state block), and that phrase appears ONLY there.
    """
    if not targets:
        return False
    return all(
        any(f"file '{c}' EXISTS" in prompt for c in _candidates(t, cwd))
        for t in targets
    )


def _candidates(token: str, cwd: str):
    """Every spelling of one operand the state or prompt might carry.

    The resolved form is what the state stores, the literal form is what the
    attacker typed, and the single-slash form matters because POSIX normpath
    KEEPS exactly two leading slashes -- `//f` never matches a stored `/f`.
    """
    cwd = cwd or "/root"
    forms = {token, os.path.normpath(os.path.join(cwd, token))}
    forms |= {re.sub(r"^/+", "/", f) for f in list(forms)}
    return forms


class PromptSpy:
    """Captures the prompt an agent is actually sent.

    Wraps send/send_with_usage rather than rebuilding the prompt, so the check
    sees what the model received and cannot drift from it.
    """

    def __init__(self, *agent_objs):
        self.agents = [a for a in agent_objs if a is not None]
        self.prompt = ""
        self._orig = []

    def _wrap(self, fn):
        def inner(system_prompt, user_prompt, *a, **k):
            self.prompt = f"{system_prompt}\n{user_prompt}"
            return fn(system_prompt, user_prompt, *a, **k)
        return inner

    def __enter__(self):
        for a in self.agents:
            for name in ("send", "send_with_usage"):
                fn = getattr(a, name, None)
                if fn is None:
                    continue
                self._orig.append((a, name, fn))
                setattr(a, name, self._wrap(fn))
        return self

    def __exit__(self, *exc):
        for a, name, fn in self._orig:
            setattr(a, name, fn)
        return False


# ─── handle() wrapper ─────────────────────────────────────────────────────────

def _run_handle(agents, cmd, force_agent=None):
    ch = _FakeChannel()
    t0 = time.perf_counter()
    try:
        if force_agent is not None:
            ret = agents.handle(cmd, ch.write, ch.read, force_agent=force_agent)
        else:
            ret = agents.handle(cmd, ch.write, ch.read)
        ok = True
    except Exception:
        ret = ("", "")
        ok  = False
    latency_ms   = round((time.perf_counter() - t0) * 1000, 2)
    output       = (ret[0] if isinstance(ret, tuple) else None) or ch.text()
    actual_agent = getattr(agents.handle, "last_agent", "unknown")
    cost_info    = getattr(agents.handle, "last_usage", None)
    return output.strip(), latency_ms, actual_agent, ok, cost_info


# ─── single pair execution ────────────────────────────────────────────────────

def run_pair(agents, pair_rec, creator_agent=None, reader_agent=None):
    """
    Run one benchmark pair (setup → creator → reader) inside the given
    agents session. When creator_agent/reader_agent are None, routing is
    natural (used by B2). When provided, routing is forced (used by B1).
    """
    setup_cmd = pair_rec.get("setup")

    result = {
        "id":           pair_rec["id"],
        "fi":           pair_rec.get("fi"),
        "source":       pair_rec.get("source", "unknown"),
        "category":     pair_rec["category"],
        "pair":         pair_label(creator_agent, reader_agent)
                        if creator_agent else "natural",
        "setup_cmd":    setup_cmd,
        "creator_cmd":  pair_rec["creator"],
        "reader_cmd":   pair_rec["reader"],
        "ground_truth": pair_rec["ground_truth"],
        "excluded_reason": pair_rec.get("excluded_reason"),
        "ok":           False,
    }

    try:
        if setup_cmd:
            _, setup_lat, _, s_ok, setup_cost = _run_handle(agents, setup_cmd)
            result["setup_latency_ms"] = setup_lat
            if setup_cost is not None:
                result["setup_cost_info"] = setup_cost
            if not s_ok:
                result["error"] = "setup failed"
                return result

        creator_out, creator_lat, creator_actual, _, creator_cost = _run_handle(
            agents, pair_rec["creator"], force_agent=creator_agent
        )
        result["creator_output"]        = creator_out
        result["creator_latency_ms"]    = creator_lat
        result["creator_actual_agent"]  = creator_actual
        if creator_cost is not None:
            result["creator_cost_info"] = creator_cost

        # Did the creator's change land in the shared state at all?
        targets = target_paths(pair_rec)
        snap    = getattr(agents.handle, "state_snapshot", None) or {}
        files   = snap.get("files") or {}
        cwd     = snap.get("cwd") or "/root"
        in_state = [p for p in targets
                    if _candidates(p, cwd) & set(files)]
        result["target_paths"]  = targets
        result["state_updated"] = bool(targets) and len(in_state) == len(targets)
        result["state_missing"] = [p for p in targets if p not in in_state]

        with PromptSpy(getattr(agents, "ondevice", None),
                       getattr(agents, "cloud", None)) as spy:
            reader_out, reader_lat, reader_actual, _, reader_cost = _run_handle(
                agents, pair_rec["reader"], force_agent=reader_agent
            )
        result["reader_prompt_chars"] = len(spy.prompt)

        if reader_agent == "cowrie" or reader_actual == "cowrie":
            # Cowrie gets no prompt: state reaches it by replay into the real
            # container, so prompt inspection does not apply to these pairs.
            result["state_delivered"] = None
            result["propagation"]     = "replay"
        else:
            delivered = state_in_prompt(spy.prompt, targets, cwd)
            result["state_delivered"] = delivered
            result["propagation"]     = "delivered" if delivered else "missing"
        result["propagated"] = bool(result["state_updated"]) and \
            result["state_delivered"] is not False
        result["reader_output"]         = reader_out
        result["reader_latency_ms"]     = reader_lat
        result["reader_actual_agent"]   = reader_actual
        if reader_cost is not None:
            result["reader_cost_info"] = reader_cost

        matched, match_type = is_match(reader_out, pair_rec["ground_truth"])
        result["matched"]    = matched
        result["match_type"] = match_type
        result["ok"]         = True

    except Exception as e:
        result["error"] = str(e)

    return result


# ─── B1: context preservation ────────────────────────────────────────────────

def run_b1(agents_factory, benchmark, trials, writer, sync_label="on", pairs=None):
    """
    All benchmark pairs run sequentially within ONE session per
    (agent pair, trial), so SRi/Hi accumulate realistically across many
    commands, matching a real attacker session. Routing is forced per pair.

    sync_label tags every record ("on"/"off") so B1 can be run once with
    agents_factory (sync_state=True, SRi/Hi injected) and once with
    agents_sync_off_factory (sync_state=False, SRi/Hi withheld) — comparing
    success rate between the two isolates whether SRi/Hi actually helps
    context preservation, rather than just assuming it does.
    """
    print(f"\n{'─'*60}")
    print(f"  B1  Context Preservation (combined session) — sync_{sync_label}")
    print(f"  {len(benchmark)} pairs × {len(AGENT_PAIRS)} combos × {trials} trials")
    print(f"{'─'*60}")

    all_results = []

    for creator_agent, reader_agent in (pairs or AGENT_PAIRS):
        pair = pair_label(creator_agent, reader_agent)
        print(f"\n[B1:{sync_label}] {pair}")

        pair_results = []
        for t in range(trials):
            agents = agents_factory()   # fresh session per trial
            for pair_rec in benchmark:
                rec = run_pair(agents, pair_rec, creator_agent, reader_agent)
                rec["trial"]      = t
                rec["experiment"] = "B1_context_preservation"
                rec["sync"]       = sync_label
                writer(rec)
                pair_results.append(rec)

        ok      = [r for r in pair_results if r["ok"]]
        scored  = [r for r in ok if not r.get("excluded_reason")]
        matched = [r for r in scored if r["matched"]]
        rate    = len(matched) / len(scored) * 100 if scored else 0
        n_excl  = len(ok) - len(scored)
        raw_m   = sum(1 for r in ok if r["matched"])
        prop_n  = [r for r in scored if r.get("propagated") is not None]
        prop_ok = [r for r in prop_n if r.get("propagated")]
        prop    = len(prop_ok) / len(prop_n) * 100 if prop_n else 0
        print(f"  propagation: {len(prop_ok)}/{len(prop_n)} = {prop:.1f}%"
              f"   (state reached the reader)")
        print(f"  output match: {len(matched)}/{len(scored)} = {rate:.1f}%"
              + (f"   [raw incl. {n_excl} unscoreable: {raw_m}/{len(ok)}]" if n_excl else ""))
        all_results.extend(pair_results)

    return all_results


# ─── B2: context-synchronization overhead (session-level) ─────────────────────

def run_b2(agents_sync_on_factory, agents_sync_off_factory,
           benchmark, trials, writer):
    """
    Session-level overhead: run the ENTIRE benchmark as one continuous
    session, natural routing, under two conditions:
      - sync_on : PromptManager injects Hi + SRi into prompts
      - sync_off: same routing + tracking, but context NOT injected
    Measure total session latency for each, report the delta.

    Alternates which condition runs first each trial to cancel out
    time-block drift (network load, GPU warmup, etc.).
    """
    print(f"\n{'─'*60}")
    print(f"  B2  Context-Sync Overhead (session-level, natural routing)")
    print(f"  {len(benchmark)} pairs per session × {trials} trials × 2 conditions")
    print(f"{'─'*60}")

    all_results = []

    for t in range(trials):
        conditions = [
            ("sync_on",  agents_sync_on_factory),
            ("sync_off", agents_sync_off_factory),
        ]
        if t % 2 == 1:
            conditions.reverse()   # cancel time-block drift

        trial_latency = {}
        trial_cost    = {}

        for label, factory in conditions:
            agents = factory()     # ONE fresh session for the whole benchmark
            t0 = time.perf_counter()
            session_cost = 0.0
            cost_seen    = False
            for pair_rec in benchmark:
                pair_result = run_pair(agents, pair_rec)   # natural routing, no force_agent
                for key in ("setup_cost_info", "creator_cost_info", "reader_cost_info"):
                    ci = pair_result.get(key)
                    if ci and ci.get("cost") is not None:
                        session_cost += ci["cost"]
                        cost_seen = True
            session_ms = (time.perf_counter() - t0) * 1000
            trial_latency[label] = session_ms
            trial_cost[label]    = round(session_cost, 6) if cost_seen else None
            print(f"  trial {t}  [{label:8}] session latency: {session_ms:9.1f} ms")

        on_ms  = trial_latency["sync_on"]
        off_ms = trial_latency["sync_off"]
        rec = {
            "trial":               t,
            "experiment":          "B2_sync_overhead",
            "session_sync_on_ms":  round(on_ms, 2),
            "session_sync_off_ms": round(off_ms, 2),
            "overhead_ms":         round(on_ms - off_ms, 2),
            "overhead_pct":        round((on_ms - off_ms) / off_ms * 100, 2)
                                   if off_ms > 0 else None,
            "session_sync_on_cost":  trial_cost["sync_on"],
            "session_sync_off_cost": trial_cost["sync_off"],
            "ok":                  True,
        }
        writer(rec)
        all_results.append(rec)

    return all_results


# ─── summary ──────────────────────────────────────────────────────────────────

def _read_pair_file(path):
    """Parse one per-pair file: blank-line-separated pretty-printed JSON objects."""
    recs = []
    try:
        txt = open(path, encoding="utf-8").read()
    except OSError:
        return recs
    dec, i, n = json.JSONDecoder(), 0, len(txt)
    while i < n:
        while i < n and txt[i] in " \n\r\t":
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(txt, i)
        except json.JSONDecodeError:
            break
        recs.append(obj)
    return recs


def collect_results_from_disk():
    """Rebuild (b1_results, b2_results) from EVERY per-pair file on disk.

    This is what lets a subset rerun (`--pairs on_device>cowrie`) overwrite just
    those pairs' files yet still produce a summary covering all pairs, each with
    its freshest data. B2 records are the ones in the b2_overhead folder (session
    latencies); everything else is B1.
    """
    b1, b2 = [], []
    for path in sorted(glob.glob(os.path.join(RESULTS_DIR, "*", "context_preservation.jsonl"))):
        for r in _read_pair_file(path):
            if r.get("experiment", "").startswith("B2") or "session_sync_on_ms" in r:
                b2.append(r)
            else:
                b1.append(r)
    return b1, b2


def compute_summary(b1_results, b2_results):
    from collections import defaultdict
    summary = {"B1_context_preservation": {}, "B2_sync_overhead": {}}

    # ── B1 — per-(sync, pair) success rate ──
    b1_by_sync_pair = defaultdict(list)
    for r in b1_results:
        if r.get("ok") and not r.get("excluded_reason"):
            b1_by_sync_pair[(r.get("sync", "on"), r["pair"])].append(r)

    for (sync_label, pair), recs in sorted(b1_by_sync_pair.items()):
        matched = sum(1 for r in recs if r.get("matched"))
        by_fi   = defaultdict(lambda: {"matched": 0, "total": 0})
        by_trial = defaultdict(lambda: {"matched": 0, "total": 0})
        for r in recs:
            fi = str(r.get("fi", "?"))
            by_fi[fi]["total"] += 1
            if r.get("matched"):
                by_fi[fi]["matched"] += 1
            t = str(r.get("trial", "?"))
            by_trial[t]["total"] += 1
            if r.get("matched"):
                by_trial[t]["matched"] += 1
        summary["B1_context_preservation"].setdefault(f"sync_{sync_label}", {})[pair] = {
            "propagation_rate_pct": (
                round(sum(1 for r in recs if r.get("propagated")) /
                      len(recs) * 100, 2)),
            "propagated": sum(1 for r in recs if r.get("propagated")),
            "output_match_rate_pct": round(matched / len(recs) * 100, 2),
            "success_rate_pct": round(matched / len(recs) * 100, 2),
            "matched": matched,
            "total":   len(recs),
            "trials":  len(by_trial),
            "by_trial": {
                t: {
                    "success_rate_pct": round(v["matched"] / v["total"] * 100, 2),
                    "matched": v["matched"],
                    "total":   v["total"],
                }
                for t, v in sorted(by_trial.items())
            },
            "by_fi": {
                fi: {
                    "success_rate_pct": round(v["matched"] / v["total"] * 100, 2),
                    "matched": v["matched"],
                    "total":   v["total"],
                }
                for fi, v in sorted(by_fi.items())
            },
        }

    # ── B1 — sync_on vs sync_off comparison per pair ──
    on_map  = summary["B1_context_preservation"].get("sync_on", {})
    off_map = summary["B1_context_preservation"].get("sync_off", {})
    if on_map or off_map:
        comparison = {}
        for pair in sorted(set(on_map) | set(off_map)):
            on_pct  = on_map.get(pair, {}).get("success_rate_pct")
            off_pct = off_map.get(pair, {}).get("success_rate_pct")
            comparison[pair] = {
                "sync_on_pct":  on_pct,
                "sync_off_pct": off_pct,
                "delta_pct":    round(on_pct - off_pct, 2)
                                if on_pct is not None and off_pct is not None else None,
            }
        summary["B1_context_preservation"]["comparison"] = comparison

    # ── B2 — session-level overhead aggregated across trials ──
    on_lats   = [r["session_sync_on_ms"]  for r in b2_results if r.get("ok")]
    off_lats  = [r["session_sync_off_ms"] for r in b2_results if r.get("ok")]
    overheads = [r["overhead_ms"]         for r in b2_results if r.get("ok")]
    pcts      = [r["overhead_pct"]        for r in b2_results
                 if r.get("ok") and r.get("overhead_pct") is not None]

    if overheads:
        summary["B2_sync_overhead"] = {
            "trials":                 len(overheads),
            "mean_session_sync_on_ms":  round(statistics.mean(on_lats), 2),
            "mean_session_sync_off_ms": round(statistics.mean(off_lats), 2),
            "mean_overhead_ms":       round(statistics.mean(overheads), 2),
            "mean_overhead_pct":      round(statistics.mean(pcts), 2) if pcts else None,
            "stdev_overhead_ms":      round(statistics.stdev(overheads), 2)
                                      if len(overheads) > 1 else 0.0,
            "min_overhead_ms":        round(min(overheads), 2),
            "max_overhead_ms":        round(max(overheads), 2),
            "per_trial_overhead_ms":  [round(o, 2) for o in overheads],
        }

    return summary


def print_summary(summary):
    W = 72

    b1 = summary.get("B1_context_preservation", {})
    for sync_label in ("sync_on", "sync_off"):
        pair_stats = b1.get(sync_label, {})
        print(f"\n{'═'*W}")
        print(f"  B1  CONTEXT PRESERVATION — SUCCESS RATE BY AGENT PAIR [{sync_label}]")
        print(f"{'═'*W}")
        print(f"  {'pair':<25} {'success %':>10}  {'matched':>8}  {'total':>6}  {'trials':>6}")
        print(f"  {'─'*68}")
        for pair, s in pair_stats.items():
            print(f"  {pair:<25} {s['success_rate_pct']:>9.1f}%  "
                  f"{s['matched']:>8}  {s['total']:>6}  {s.get('trials', '?'):>6}")
            by_trial = s.get("by_trial", {})
            if len(by_trial) > 1:
                per = "  ".join(f"t{t} {v['success_rate_pct']:.1f}% "
                                f"({v['matched']}/{v['total']})"
                                for t, v in by_trial.items())
                print(f"  {'':<25} └ {per}")
        if not pair_stats:
            print(f"  (no B1 {sync_label} data)")

    comparison = b1.get("comparison", {})
    if comparison:
        print(f"\n{'═'*W}")
        print("  B1  SRi/Hi IMPACT — sync_on vs sync_off SUCCESS RATE")
        print(f"{'═'*W}")
        print(f"  {'pair':<25} {'sync_on %':>10}  {'sync_off %':>11}  {'delta':>8}")
        print(f"  {'─'*68}")
        for pair, c in comparison.items():
            on_pct  = c['sync_on_pct']
            off_pct = c['sync_off_pct']
            delta   = c['delta_pct']
            on_s  = f"{on_pct:.1f}%"  if on_pct  is not None else "n/a"
            off_s = f"{off_pct:.1f}%" if off_pct is not None else "n/a"
            delta_s = f"{delta:+.1f}%" if delta is not None else "n/a"
            print(f"  {pair:<25} {on_s:>10}  {off_s:>11}  {delta_s:>8}")

    print(f"\n{'═'*W}")
    print("  B2  CONTEXT-SYNC OVERHEAD — SESSION LATENCY (ms)")
    print(f"{'═'*W}")
    b2 = summary.get("B2_sync_overhead", {})
    if b2:
        print(f"  trials                : {b2['trials']}")
        print(f"  mean session sync_on  : {b2['mean_session_sync_on_ms']:.1f} ms")
        print(f"  mean session sync_off : {b2['mean_session_sync_off_ms']:.1f} ms")
        print(f"  ─────────────────────────────────────────────")
        print(f"  mean overhead         : {b2['mean_overhead_ms']:+.1f} ms "
              f"({b2['mean_overhead_pct']:+.1f}%)" if b2['mean_overhead_pct'] is not None
              else f"  mean overhead         : {b2['mean_overhead_ms']:+.1f} ms")
        print(f"  stdev overhead        : {b2['stdev_overhead_ms']:.1f} ms")
        print(f"  range                 : {b2['min_overhead_ms']:+.1f} .. "
              f"{b2['max_overhead_ms']:+.1f} ms")
        print(f"  per-trial overhead    : {b2['per_trial_overhead_ms']}")
    else:
        print("  (no B2 data)")
    print(f"{'═'*W}\n")


# ─── writer — clean minimal JSON ──────────────────────────────────────────────

KEEP = [
    # B1 fields
    "id", "trial", "experiment", "pair", "sync", "fi", "source", "category",
    "setup_cmd", "creator_cmd", "reader_cmd", "ground_truth",
    "creator_output", "reader_output",
    "creator_actual_agent", "reader_actual_agent",
    "matched", "match_type", "excluded_reason",
    # state propagation — the question B1 is actually asking
    "target_paths", "state_updated", "state_missing", "state_delivered",
    "propagated", "propagation", "reader_prompt_chars",
    "creator_latency_ms", "reader_latency_ms", "setup_latency_ms",
    "creator_cost_info", "reader_cost_info", "setup_cost_info",
    "ok", "error",
    # B2 session-level fields
    "session_sync_on_ms", "session_sync_off_ms",
    "overhead_ms", "overhead_pct",
    "session_sync_on_cost", "session_sync_off_cost",
]


def _pair_folder(rec):
    """Subfolder name for a record: '<creator>_<reader>', or 'b2_overhead'."""
    pair = rec.get("pair")
    if not pair or pair == "natural":
        return "b2_overhead"
    return pair.replace("→", "_").replace(">", "_").replace(" ", "_").replace("/", "_")


def make_writer():
    base = RESULTS_DIR
    os.makedirs(base, exist_ok=True)
    handles = {}

    def _fh(rec):
        name = _pair_folder(rec)
        if name not in handles:
            d = os.path.join(base, name)
            os.makedirs(d, exist_ok=True)
            handles[name] = open(os.path.join(d, "context_preservation.jsonl"),
                                 "w", encoding="utf-8")
        return handles[name]

    def write(rec):
        clean = {k: rec[k] for k in KEEP if k in rec and rec[k] is not None}
        fh = _fh(rec)
        fh.write(json.dumps(clean, indent=2, ensure_ascii=False) + "\n\n")
        fh.flush()

    def close():
        for fh in handles.values():
            fh.close()
        return base

    return write, close


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmark", default=BENCHMARK_DEFAULT)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--filter", default=None,
                    help="regex — keep only benchmark pairs whose creator or "
                         "reader command matches. Lets you re-run just the "
                         "pairs you're debugging instead of all 35 "
                         "(e.g. --filter 'nippon|mkdir').")
    ap.add_argument("--b1-only", action="store_true")
    ap.add_argument("--b2-only", action="store_true")
    ap.add_argument("--pairs", default=None,
                    help="run only these B1 pairs, comma-separated as "
                         "'creator>reader' (e.g. 'on_device>cowrie'). "
                         "Default: all AGENT_PAIRS.")
    args = ap.parse_args()

    selected_pairs = None
    if args.pairs:
        selected_pairs = []
        for p in args.pairs.split(","):
            c, r = p.replace("→", ">").split(">")
            selected_pairs.append((c.strip(), r.strip()))
        print(f"[run_partB] B1 pairs filtered to: {selected_pairs}")

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"[run_partB] run_id={run_id}  trials={args.trials}")

    if not os.path.exists(args.benchmark):
        print(f"[error] benchmark not found: {args.benchmark}")
        sys.exit(1)

    benchmark = load_benchmark(args.benchmark)

    if args.filter:
        rx = re.compile(args.filter)
        before = len(benchmark)
        benchmark = [r for r in benchmark
                     if rx.search(r.get("creator") or "") or rx.search(r.get("reader") or "")]
        print(f"[benchmark] --filter {args.filter!r}: {len(benchmark)}/{before} pairs kept")
        for r in benchmark:
            print(f"    {r['creator'][:55]:<55} -> {r['reader'][:45]}")
        if not benchmark:
            print("[benchmark] filter matched nothing — aborting")
            sys.exit(1)

    from agents import build_agents, Agents
    import main as hydrapot_main

    _base = build_agents()

    def _make_agents(sync_state=True, src_ip="eval"):
        """
        Build an agents session. sync_state controls whether PromptManager
        injects Hi + SRi context into LLM prompts. Routing and state
        tracking are IDENTICAL regardless of sync_state — only prompt
        content differs — so B2's two conditions isolate context-injection
        overhead cleanly.
        """
        handle = hydrapot_main.make_command_handler(
            _base.cowrie,
            src_ip=src_ip, public_ip=src_ip,
            plugins=None,
            sri_max_events=20,
            sync_state=sync_state,
            store="json", store_dir=session_dir_for(src_ip, __file__),
            capture_cost=True,
        )
        return Agents(
            config=_base.config, cowrie=_base.cowrie,
            ondevice=_base.ondevice, cloud=_base.cloud,
            handle=handle, pm=_base.pm,
            scorer=_base.scorer, cowrie_ok=_base.cowrie_ok,
        )

    # B1 always runs with full context (sync on)
    def agents_factory():
        return _make_agents(sync_state=True, src_ip="eval_sync_on")

    # B2 sync_off condition: context NOT injected into prompt
    def agents_sync_off_factory():
        try:
            return _make_agents(sync_state=False, src_ip="eval_sync_off")
        except TypeError:
            print("[run_partB] ERROR: make_command_handler() does not accept "
                  "sync_state yet — add it to main.py and thread it into "
                  "PromptManager(...). Falling back to sync_on (B2 invalid).")
            return _make_agents(sync_state=True, src_ip="eval_sync_off")

    write, close = make_writer()
    b1_results, b2_results = [], []

    try:
        if not args.b2_only:
            b1_results  = run_b1(agents_factory, benchmark, args.trials, write,
                                 sync_label="on", pairs=selected_pairs)
            b1_results += run_b1(agents_sync_off_factory, benchmark, args.trials, write,
                                 sync_label="off", pairs=selected_pairs)
        if not args.b1_only:
            b2_results = run_b2(agents_factory, agents_sync_off_factory,
                                benchmark, args.trials, write)
    finally:
        jsonl_path = close()

    # Build from EVERY pair file on disk, not just this run's results, so a
    # subset rerun (--pairs) refreshes those pairs and keeps all the others.
    summary = compute_summary(*collect_results_from_disk())
    print_summary(summary)

    summary_path = os.path.join(jsonl_path, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[run_partB] results → {jsonl_path}/")
    print(f"[run_partB] summary → {summary_path}")


if __name__ == "__main__":
    main()