"""
experiment_data/PartC/select_stateful_sessions.py
─────────────────────────────────────────────────────────────────
Selects real, stateful attacker SESSIONS (not individual commands, and not
setup/test PAIRS like Part B) from ml4net (233k sessions) for Part C's
Docker ground-truth collection — cyberlab (~338 sessions) intentionally
excluded here, ml4net-only per explicit request. Unlike Part B, no
read-after-write pairing is required — a session qualifies just by having
>=1 stateful (FI>=1) command, same loose definition build_partB_benchmark.py
originally used.

Reuses the raw session loader already built for Part B (no duplicated
dataset-parsing logic): filter_stateful_ml4net.load_ml4net_raw_sessions()

Per-command, not per-session, safety: excluding a WHOLE session for containing
one wget/rm would throw away almost every real attacker session (most download
and run something at some point) — that's not necessary. partC.md's own
established convention already handles this at the individual-command level:
a blocked command gets ground_truth=null/blocked=true but the session still
gets replayed around it. Same rule applied here:
  - partC.md's own BLOCKED set (rm, mkfs, dd, shutdown, reboot, halt,
    poweroff, kill, pkill, killall) — would hang/kill the container or the
    docker exec shell itself if actually run
  - wget/curl — would need to fetch real (often dead or malicious) URLs
  - direct execution of a local file (./something) — would run unknown/
    reconstructed code, same guard Part B already applies
A session is INCLUDED as long as it's stateful; individual commands within
it are annotated safe/blocked for the ground-truth collector to honor.

Non-cloud sessions are then picked GREEDILY to BALANCE FI0-FI4 coverage:
target = the scarcest band's own SAFE-unique-command ceiling across the
WHOLE stateful pool (unsafe commands never count toward the target, since
they get ground_truth=null and can't be scored). This is why sessions
aren't excluded for containing one unsafe command elsewhere — most real
FI2/FI3/FI4 activity co-occurs with a wget/rm in the same session, and
throwing away the whole session would throw away most of the real signal
for exactly the bands we're trying to balance.

Output: dataset/partC_stateful_sessions.json
{
  "total_sessions": N,
  "total_commands": N,
  "blocked_commands": N,
  "breakdown": {"cyberlab_2019-05-13.json": N, "cyberlab_2019-08-05.json": N, "ml4net_full.json": N},
  "sessions": [
    {"session_id": "...", "source": "...", "full_entry": ...,
     "commands": [{"cmd": "...", "blocked": bool}, ...]}
  ]
}

Usage:
    python experiment_data/PartC/select_stateful_sessions.py
─────────────────────────────────────────────────────────────────
"""

import os
import re
import sys
import json

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_PARTB = os.path.join(_NSC, "PartB")
for p in (_ROOT, _NSC, _PARTB):
    if p not in sys.path:
        sys.path.insert(0, p)

from filter_stateful_cyberlab import _expand_commands   # reused split helper, not the cyberlab loader
from filter_stateful_ml4net import load_ml4net_raw_sessions as load_ml4net_raw
from prompt.fi_manager import FIScorer
from core.router import _is_cloud   # the REAL obfuscation-detection logic, not a reimplementation

DATASET_DIR = os.path.join(_ROOT, "dataset")
OUTPUT_PATH = os.path.join(DATASET_DIR, "partC_stateful_sessions.json")

# partC.md's own BLOCKED set — would hang/kill the container or the docker
# exec shell itself, breaking the rest of that session's replay
BLOCKED = {
    "rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff",
    "kill", "pkill", "killall",
}


def _is_safe_for_docker(cmd: str) -> bool:
    """True if `cmd` can be actually executed in a throwaway Docker
    container without needing network fetches, running unknown binaries,
    or risking the container/shell itself."""
    for part in cmd.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        base = toks[0].lstrip("./") if toks else ""
        if base in BLOCKED:
            return False
        if "wget" in toks or "curl" in toks:
            return False
        if re.match(r"^\./\S+", part):
            return False
    return True


def _is_stateful(commands: list[str], scorer: FIScorer) -> bool:
    """Loose definition (same as build_partB_benchmark.py originally used):
    at least one command in the session has FI >= 1."""
    return any(scorer.score(c)[0] >= 1 for c in commands)


def _is_cloud_routed(commands: list[str]) -> bool:
    """At least one command in the session would actually route to cloud in
    production — real obfuscation/semantic-reconstruction detection from
    router.py, not a separate reimplementation."""
    return any(_is_cloud(c) for c in commands)


def _annotate_commands(cmds: list[str], scorer: FIScorer) -> list[dict]:
    return [{"cmd": c, "blocked": not _is_safe_for_docker(c), "fi": scorer.score(c)[0]}
            for c in cmds]


def select_sessions():
    scorer = FIScorer()

    # ml4net only (233k sessions) — not cyberlab (~338), per explicit request
    pools = {
        "ml4net": load_ml4net_raw(),
    }
    # ml4net stores an entire session as ONE ';'-joined string — split it so
    # per-command safety/statefulness below operates on real individual
    # steps, not one giant blob per session.
    for name, pool in pools.items():
        for s in pool:
            s["commands"] = _expand_commands(s["commands"])
        print(f"[select] {name}: {len(pool)} raw sessions with commands")

    # scan the FULL pool for two separate categories — sessions are NOT
    # excluded for containing an unsafe command (wget/rm/etc. elsewhere in
    # the same session); only that individual command gets marked blocked
    # at annotation time. Most real FI2/FI3/FI4 activity co-occurs with a
    # download step in the same session, so requiring the WHOLE session be
    # safe would throw away most of the signal for exactly the bands this
    # file exists to balance. cloud-routed sessions are pulled out and
    # harvested FIRST, since real obfuscated commands are much rarer than
    # plain stateful ones — without this, they'd get crowded out entirely
    # by the balancing pass below and Part C would never exercise the
    # cloud/honeyrouter arms.
    cloud_pool    = {name: [] for name in pools}
    stateful_pool = {name: [] for name in pools}
    for name, pool in pools.items():
        for s in pool:
            cmds = s["commands"]
            if not cmds:
                continue
            if _is_cloud_routed(cmds):
                cloud_pool[name].append(s)
            elif _is_stateful(cmds, scorer):
                stateful_pool[name].append(s)
        n_cloud = len(cloud_pool[name])
        n_stateful = len(stateful_pool[name])
        print(f"[select] {name}: {n_cloud} qualifying cloud-routed sessions, "
              f"{n_stateful} qualifying stateful sessions (unsafe commands allowed, "
              f"marked blocked individually)")

    selected = []
    total_commands = 0
    blocked_commands = 0
    breakdown = {}

    def _take(s, reason):
        nonlocal total_commands, blocked_commands
        annotated = _annotate_commands(s["commands"], scorer)
        selected.append({**s, "commands": annotated, "selected_because": reason})
        total_commands   += len(annotated)
        blocked_commands += sum(1 for c in annotated if c["blocked"])
        breakdown[s["source"]] = breakdown.get(s["source"], 0) + len(annotated)

    # compute the shared balance TARGET up front (before either harvesting
    # step): the scarcest FI band's own SAFE-unique-command ceiling across
    # the whole stateful pool. This same number caps BOTH the cloud harvest
    # and the FI0-FI4 balance below, so "cloud" is treated as its own
    # category balanced to the same scale as everything else, not a
    # special-cased "take everything" bucket.
    all_stateful = [s for pool in stateful_pool.values() for s in pool]
    avail_by_fi = {fi: set() for fi in range(5)}
    for s in all_stateful:
        for c in set(s["commands"]):
            if _is_safe_for_docker(c):
                avail_by_fi[scorer.score(c)[0]].add(c)
    target = min(len(v) for v in avail_by_fi.values())
    print(f"[select] shared balance target={target} unique SAFE commands per category "
          f"(bottleneck FI band size, across the full stateful pool)")

    # 1) harvest cloud-routed sessions GREEDILY by new-unique-command
    #    coverage, capped at `target` — NOT every qualifying session
    #    unconditionally. Once unsafe commands are allowed to stay
    #    in-session (instead of excluding the whole session), the
    #    qualifying cloud-routed pool turns out to be huge (90k+ of 233k
    #    sessions all contain SOME obfuscation-triggering command
    #    somewhere) — taking all of them, or even just "until nothing new
    #    appears," produces a multi-million-command dataset nowhere near
    #    collectible via Docker. Capping the loop at `target` bounds both
    #    the dataset size AND the runtime (at most `target` argmax passes
    #    over the pool, not one per remaining session).
    cloud_candidates = [s for pool in cloud_pool.values() for s in pool]
    cloud_seen = set()
    while cloud_candidates and len(cloud_seen) < target:
        best_idx, best_gain = None, -1
        for i, s in enumerate(cloud_candidates):
            gain = len(set(s["commands"]) - cloud_seen)
            if gain > best_gain:
                best_idx, best_gain = i, gain
        if best_gain <= 0:
            break
        s = cloud_candidates.pop(best_idx)
        cloud_seen.update(s["commands"])
        _take(s, "cloud")
    print(f"[select] harvested {len(selected)} cloud-routed sessions "
          f"({total_commands} commands) before filling the rest with stateful ones")

    # 2) fill the remainder with stateful-only sessions, picked GREEDILY to
    #    BALANCE FI0-FI4 coverage to the same `target` — not just maximize
    #    raw diversity. ml4net is FI0-heavy (basic recon) with FI2/FI4
    #    being genuinely scarce (real "modify"/"impact" commands mostly
    #    show up bundled inside sessions that also contain a wget/rm). Each
    #    pick is scored by how many NEW commands it adds to bands still
    #    below target, not by total new-command count. Unsafe commands
    #    never count toward the target — they'll be marked blocked
    #    (ground_truth=null) and can't be scored, so "coverage" only means
    #    SAFE commands actually collectible in Docker.
    seen_by_fi = {fi: set() for fi in range(5)}
    for s in selected:
        # sessions already in `selected` (from step 1) are annotated —
        # commands are {"cmd": ..., "blocked": ..., "fi": ...} dicts, not
        # plain strings
        for c in s["commands"]:
            if not c["blocked"]:
                seen_by_fi[c["fi"]].add(c["cmd"])

    # Restrict the greedy scan to sessions carrying at least one SAFE
    # command in a currently-scarce band (2/3/4) — FI0/FI1 are so abundant
    # that virtually every session already has them, so they don't need
    # active searching (they ride along for free, as the last run showed).
    # Scanning all ~233k sessions per pick otherwise would be far too slow.
    SCARCE = {2, 3, 4}
    remaining = [
        s for s in all_stateful
        if any(_is_safe_for_docker(c) and scorer.score(c)[0] in SCARCE
               for c in set(s["commands"]))
    ]
    print(f"[select] {len(remaining)} sessions carry a safe FI2/FI3/FI4 command "
          f"(candidate pool for balancing)")

    def _under_target():
        return {fi for fi in range(5) if len(seen_by_fi[fi]) < target}

    while remaining and _under_target():
        best_idx, best_gain = None, -1
        needed = _under_target()
        for i, s in enumerate(remaining):
            gain = 0
            for c in set(s["commands"]):
                if not _is_safe_for_docker(c):
                    continue
                fi = scorer.score(c)[0]
                if fi in needed and c not in seen_by_fi[fi]:
                    gain += 1
            if gain > best_gain:
                best_idx, best_gain = i, gain
        if best_gain <= 0:
            break   # no remaining session helps any still-under-target band
        s = remaining.pop(best_idx)
        for c in set(s["commands"]):
            if not _is_safe_for_docker(c):
                continue
            fi = scorer.score(c)[0]
            if fi in needed:
                seen_by_fi[fi].add(c)
        _take(s, "stateful")

    return selected, total_commands, blocked_commands, breakdown


def main():
    selected, total_commands, blocked_commands, breakdown = select_sessions()

    n_cloud    = sum(1 for s in selected if s["selected_because"] == "cloud")
    n_stateful = sum(1 for s in selected if s["selected_because"] == "stateful")
    cloud_commands = sum(len(s["commands"]) for s in selected if s["selected_because"] == "cloud")

    print(f"\n[select] selected {len(selected)} sessions, {total_commands} total commands "
          f"({blocked_commands} blocked, {total_commands - blocked_commands} runnable)")
    print(f"[select]   {n_cloud} sessions selected for cloud/obfuscated coverage ({cloud_commands} commands)")
    print(f"[select]   {n_stateful} sessions selected for plain stateful coverage")
    print(f"[select] breakdown by source file:")
    for src, n in sorted(breakdown.items()):
        print(f"  {src:<30} {n:5d} commands")

    out = {
        "total_sessions":   len(selected),
        "total_commands":   total_commands,
        "blocked_commands": blocked_commands,
        "cloud_sessions":   n_cloud,
        "breakdown":        breakdown,
        "sessions":         selected,
    }
    os.makedirs(DATASET_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[select] wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
