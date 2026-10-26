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
A session is INCLUDED as long as it's stateful; the unrunnable commands
within it are DROPPED, so every command written out is one Docker can
really execute. Session text is otherwise exactly as ml4net recorded it —
nothing is decoded, rewritten or reordered.

Sessions are then picked GREEDILY to BALANCE FI0-FI4 coverage, scored by
how many new unique commands each adds to bands still below target. This is
why sessions aren't excluded for containing one unsafe command elsewhere —
most real FI2/FI3/FI4 activity co-occurs with a wget/rm in the same
session, and throwing away the whole session would throw away most of the
real signal for exactly the bands we're trying to balance.

With --target-commands N the balance pass only steers the ORDER of picks; a
top-up pass then keeps going until N runnable commands are collected, since
FI0/FI2/FI4 saturate after a few hundred commands and would otherwise cut
the dataset short (that is what held the first run to 2179).

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
import heapq
import argparse

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
from core.router import _deobfuscate   # the REAL unwrapping logic, not a reimplementation

DATASET_DIR = os.path.join(_ROOT, "dataset")
OUTPUT_PATH = os.path.join(DATASET_DIR, "partC_stateful_sessions.json")

# partC.md's own BLOCKED set — would hang/kill the container or the docker
# exec shell itself, breaking the rest of that session's replay
BLOCKED = {
    "rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff",
    "kill", "pkill", "killall",
}


# commands whose argument is itself a command — the real verb is the next
# token, so `sudo rm -rf /` must not read as `sudo`
_WRAPPERS = {"sudo", "doas", "busybox", "env", "nohup", "time", "command",
             "exec", "timeout", "nice", "ionice", "setsid", "xargs"}
# every separator that begins a new command. Splitting on ';' alone missed
# `echo hi && rm -rf /` and `cat x | rm` entirely.
_SEPARATORS = re.compile(r"(?:\|\||&&|[;|&\n])")


def _verb(part: str) -> str:
    """The command actually being invoked: basename, past any VAR=val prefix
    and command wrapper. `/bin/rm` -> rm, `sudo rm` -> rm, `LC_ALL=C ls` -> ls.

    basename, NOT lstrip("./") — lstrip takes a character SET, so
    "/bin/rm".lstrip("./") is "bin/rm", which matched nothing in BLOCKED and
    let every absolute path through."""
    for tok in part.split():
        if "=" in tok.split("/")[0]:          # VAR=value prefix
            continue
        base = os.path.basename(tok)
        if base in _WRAPPERS:
            continue
        return base
    return ""


def _is_safe_for_docker(cmd: str) -> bool:
    """True if `cmd` can be actually executed in a throwaway Docker
    container without needing network fetches, running unknown binaries,
    or risking the container/shell itself.

    This decides whether a command is DROPPED from the dataset (see
    _annotate_commands), so a miss means a destructive command reaches the
    ground-truth collector and runs.

    The command is judged exactly as ml4net recorded it. Judging the
    router's decoded form as well was tried and removed: it caught none of
    `$(echo cm0=|base64 -d) -rf /`, `echo cm0=|base64 -d|sh` (the regex
    needs 8+ base64 chars, and $(echo ...) is unwrapped without decoding
    its argument), while it did drop `echo a2lsbA==|base64 -d`, which only
    prints "kill" to stdout and runs nothing. Zero threats caught, real
    commands lost. A disguised `rm` therefore still reaches Docker — a known
    limitation of a static filter, not something decoding here fixes."""
    for part in _SEPARATORS.split(cmd):
        part = part.strip()
        if not part:
            continue
        if re.match(r"^\./\S+", part):
            return False
        if _verb(part) in BLOCKED:
            return False
        if any(os.path.basename(t) in ("wget", "curl") for t in part.split()):
            return False
    return True


def _is_stateful(commands: list[str], scorer: FIScorer) -> bool:
    """Loose definition (same as build_partB_benchmark.py originally used):
    at least one command in the session has FI >= 1.

    Restricted to SAFE commands, since the unsafe ones are dropped from the
    session — a session stateful only by virtue of an `rm` or a `wget` has no
    stateful command left once those are removed."""
    return any(scorer.score(c)[0] >= 1 for c in commands if _is_safe_for_docker(c))


def _annotate_commands(cmds: list[str], scorer: FIScorer) -> list[dict]:
    """Annotate a session's commands, DROPPING the unrunnable ones.

    Ground truth is collected by really executing the session in Docker, and
    the collector skips anything _is_safe_for_docker rejects — so the
    container state never reflects those commands. Keeping them in the
    session would hand the agent a history Docker never had (a `wget` whose
    payload does not exist, an `rm` that never ran) and then score it against
    that container, marking the agent wrong for believing its own transcript.
    They are removed so the session the agent replays is the session Docker
    actually executed."""
    return [{"cmd": c, "blocked": False, "fi": scorer.score(c)[0]}
            for c in cmds if _is_safe_for_docker(c)]


def select_sessions(target_commands: int = 0):
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

    # ONE bucket: a session qualifies if it has at least one stateful (FI>=1)
    # safe command. Sessions are NOT excluded for containing an unsafe command
    # elsewhere — that command alone is dropped by _annotate_commands, and most
    # real FI2/FI3/FI4 activity co-occurs with a download step in the same
    # session, so excluding whole sessions would throw away the signal for
    # exactly the bands this file exists to balance.
    #
    # There used to be a second bucket that harvested "cloud-routed"
    # (obfuscated) sessions first, back when router._is_cloud() sent anything
    # obfuscated straight to cloud. The router no longer works that way — it
    # decodes the disguise and routes on the DECODED FI band — so an
    # obfuscated command is already represented by whichever band it decodes
    # into, and the FI balance below covers the cloud arm on its own. The
    # bucket is gone: session text is kept exactly as ml4net recorded it, with
    # the unrunnable commands removed and nothing else changed.
    stateful_pool = {name: [] for name in pools}
    for name, pool in pools.items():
        for s in pool:
            cmds = s["commands"]
            if not cmds:
                continue
            if _is_stateful(cmds, scorer):
                stateful_pool[name].append(s)
        print(f"[select] {name}: {len(stateful_pool[name])} qualifying stateful "
              f"sessions (unrunnable commands dropped individually)")

    selected = []
    total_commands = 0
    blocked_commands = 0
    dropped_empty = 0
    breakdown = {}

    # the two pools overlap, so a session can be a candidate in both passes
    taken_ids = set()

    def _already_taken(s):
        return (s["source"], s["session_id"]) in taken_ids

    def _runnable():
        """Commands that will actually execute in Docker -- the budget's unit.
        A blocked command is written with ground_truth=null and can never be
        scored, so counting it toward a requested size would overstate the
        dataset."""
        return total_commands - blocked_commands

    def _take(s, reason):
        """Record a session. Returns False if nothing runnable survived the
        unsafe-command drop, in which case the session is not selected."""
        nonlocal total_commands, blocked_commands, dropped_empty
        annotated = _annotate_commands(s["commands"], scorer)
        if not annotated:
            dropped_empty += 1
            return False
        selected.append({**s, "commands": annotated, "selected_because": reason})
        taken_ids.add((s["source"], s["session_id"]))
        total_commands   += len(annotated)
        blocked_commands += sum(1 for c in annotated if c["blocked"])
        breakdown[s["source"]] = breakdown.get(s["source"], 0) + len(annotated)
        return True

    # compute the shared balance TARGET up front (before either harvesting
    # step): the scarcest FI band's own SAFE-unique-command ceiling across
    # the whole stateful pool — the headroom each band actually has, which
    # the per-band targets below are clamped to.
    all_stateful = [s for pool in stateful_pool.values() for s in pool]
    avail_by_fi = {fi: set() for fi in range(5)}
    for s in all_stateful:
        for c in set(s["commands"]):
            if _is_safe_for_docker(c):
                avail_by_fi[scorer.score(c)[0]].add(c)
    ceiling = {fi: len(avail_by_fi[fi]) for fi in range(5)}
    print("[select] unique SAFE commands available per FI band:")
    for fi in range(5):
        print(f"[select]   FI{fi}: {ceiling[fi]}")

    # --target-commands is a budget on the RUNNABLE commands written to the
    # dataset -- the ones Part C can actually replay and score. It is NOT a
    # per-band unique-command count. The two differ a lot: sessions are taken
    # whole, so each pick contributes all ~23 of its commands (duplicates and
    # FI0 filler included), while FI0/FI2/FI4 hold only a few hundred unique
    # safe commands each, so band coverage saturates long before the budget.
    #
    # Band balance therefore steers the ORDER of picks (scarce bands first)
    # while the budget decides when to stop. Without the budget, selection
    # halts the moment no session adds new scarce-band coverage -- which is
    # what held the original run to 2179.
    budget = target_commands if target_commands > 0 else None
    if budget:
        quota = budget // 5
        target_by_fi = {fi: min(quota, ceiling[fi]) for fi in range(5)}
        print(f"[select] budget {budget} RUNNABLE commands; band coverage steers "
              f"pick order ({', '.join(f'FI{fi}={target_by_fi[fi]}' for fi in range(5))} "
              f"unique SAFE before top-up)")
        capped = [f"FI{fi}" for fi in range(5) if ceiling[fi] < quota]
        if capped:
            print(f"[select] note: {', '.join(capped)} saturate below the "
                  f"{quota}/band share -- the top-up pass covers the shortfall")
    else:
        bottleneck = min(ceiling.values())
        target_by_fi = {fi: bottleneck for fi in range(5)}
        print(f"[select] shared balance target={bottleneck} unique SAFE commands "
              f"per category (bottleneck FI band size, across the full stateful pool)")

    # 1) pick sessions GREEDILY to BALANCE FI0-FI4 coverage — not just to
    #    maximize raw diversity. ml4net is FI1-heavy (basic recon) with
    #    FI0/FI2/FI4 genuinely scarce (real "modify"/"impact" commands mostly
    #    show up bundled inside sessions that also contain a wget/rm). Each
    #    pick is scored by how many NEW commands it adds to bands still below
    #    target, not by total new-command count. Unrunnable commands never
    #    count -- they are dropped from the session, so "coverage" only means
    #    commands actually collectible in Docker.
    seen_by_fi = {fi: set() for fi in range(5)}

    # Restrict the greedy scan to sessions carrying at least one SAFE
    # command in a currently-scarce band (2/3/4) — FI0/FI1 are so abundant
    # that virtually every session already has them, so they don't need
    # active searching (they ride along for free, as the last run showed).
    # Scanning all ~233k sessions per pick otherwise would be far too slow.
    SCARCE = {2, 3, 4}
    remaining = [
        s for s in all_stateful
        if not _already_taken(s)
        and any(_is_safe_for_docker(c) and scorer.score(c)[0] in SCARCE
                for c in set(s["commands"]))
    ]
    print(f"[select] {len(remaining)} sessions carry a safe FI2/FI3/FI4 command "
          f"(candidate pool for balancing)")

    def _under_target():
        return {fi for fi in range(5) if len(seen_by_fi[fi]) < target_by_fi[fi]}

    # Each pick below re-read every candidate session's commands and
    # re-scored FI on all of them. At the old bottleneck target that was
    # tolerable; at a 2000-per-band quota it is ~2000 passes over ~100k
    # sessions, i.e. billions of regex scores, and never finishes. Band
    # membership never changes during the loop, so it is computed once here
    # and the loop does set arithmetic instead.
    bands_of = [
        {fi: {c for c in set(s["commands"])
              if _is_safe_for_docker(c) and scorer.score(c)[0] == fi}
         for fi in range(5)}
        for s in remaining
    ]

    # Greedy max-coverage, LAZILY evaluated. A session's marginal gain can
    # only shrink as seen_by_fi grows, so a cached gain is always an upper
    # bound: pop the best bound, recompute just that one session, and if it
    # still beats the next bound it IS the true argmax. Identical picks to a
    # full scan, but a handful of evaluations per pick instead of ~230k --
    # the full scan needs billions of set operations at a 50k budget and does
    # not finish. (Lazy greedy / CELF; valid because coverage is submodular.)
    def _greedy(pool, bands_list, needed_fn, done_fn, reason):
        heap = [(-sum(len(b[fi]) for fi in needed_fn()), i)
                for i, b in enumerate(bands_list)]
        heapq.heapify(heap)
        alive = dict(enumerate(bands_list))
        while heap and not done_fn():
            needed = needed_fn()
            if not needed:
                break
            neg, i = heapq.heappop(heap)
            bands = alive.get(i)
            if bands is None:
                continue
            gain = sum(len(bands[fi] - seen_by_fi[fi]) for fi in needed)
            if gain <= 0:
                del alive[i]        # contributes nothing, and `needed` only
                continue            # shrinks, so it never will
            if heap and gain < -heap[0][0]:
                heapq.heappush(heap, (-gain, i))   # stale bound, re-queue
                continue
            del alive[i]
            for fi in needed:
                seen_by_fi[fi] |= bands[fi]
            _take(pool[i], reason)
        kept = sorted(alive)       # keep the two lists index-aligned
        return [pool[i] for i in kept], [alive[i] for i in kept]

    remaining, bands_of = _greedy(
        remaining, bands_of, _under_target,
        lambda: not _under_target(), "stateful")

    print(f"[select] band coverage pass done: {_runnable()} runnable commands "
          f"({', '.join(f'FI{fi}={len(seen_by_fi[fi])}' for fi in range(5))} unique SAFE)")

    # 3) top up to the requested RUNNABLE budget. The pass above stops as
    #    soon as no session adds new coverage in a needy band -- with
    #    FI0/FI2/FI4 only a few hundred commands deep, that happens early and
    #    is exactly what capped the original run. Carry on taking the session
    #    that adds the most new unique safe commands in ANY band until the
    #    budget is met, so a requested size is actually delivered instead of
    #    being silently cut short by the scarcest band.
    if budget:
        _greedy(remaining, bands_of, lambda: set(range(5)),
                lambda: _runnable() >= budget, "topup")
        if _runnable() < budget:
            print(f"[select] WARNING: pool exhausted at {_runnable()} runnable "
                  f"commands, short of the {budget} requested")

    if dropped_empty:
        print(f"[select] {dropped_empty} sessions skipped — every command in them "
              f"was unrunnable, nothing left after the drop")
    return selected, total_commands, blocked_commands, breakdown


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target-commands", type=int, default=0, metavar="N",
                    help="minimum RUNNABLE commands wanted in the dataset -- "
                         "commands that actually execute in Docker, i.e. total "
                         "minus the wget/curl/rm/./x ones marked blocked. FI band "
                         "coverage still steers which sessions are picked first; "
                         "once the scarce bands saturate, a top-up pass keeps "
                         "taking sessions until the budget is met. "
                         "0 (default) keeps the original behaviour: every band "
                         "pinned to the scarcest band's size.")
    args = ap.parse_args()

    selected, total_commands, blocked_commands, breakdown = select_sessions(
        target_commands=args.target_commands)

    n_balance = sum(1 for s in selected if s["selected_because"] == "stateful")
    n_topup   = sum(1 for s in selected if s["selected_because"] == "topup")

    print(f"\n[select] selected {len(selected)} sessions, {total_commands} commands "
          f"(all runnable — the unrunnable ones were dropped)")
    print(f"[select]   {n_balance} sessions picked for FI band balance")
    print(f"[select]   {n_topup} sessions picked to reach the requested budget")
    print(f"[select] breakdown by source file:")
    for src, n in sorted(breakdown.items()):
        print(f"  {src:<30} {n:6d} commands")

    out = {
        "total_sessions":   len(selected),
        "total_commands":   total_commands,
        "blocked_commands": blocked_commands,   # 0 — kept for schema compatibility
        "breakdown":        breakdown,
        "sessions":         selected,
    }
    os.makedirs(DATASET_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[select] wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
