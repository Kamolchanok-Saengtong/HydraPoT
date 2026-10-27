"""
experiment_data/PartC/collect_ground_truth_sessions.py
─────────────────────────────────────────────────────────────────
Runs every session in the dataset named by --dataset for real in a
throwaway Ubuntu 22.04 Docker container. Commands within ONE session run
in order inside the SAME container — so state accumulates realistically
(e.g. 'mkdir foo' then 'cd foo' actually sees that directory). The
container is reset to a fresh state only BETWEEN different sessions, never
between commands within the same session.

Reuses build_partB_benchmark.py's Docker helpers (start_container/
reset_container/exec_cmd/stop_container) — same image, same lifecycle,
nothing reinvented.

Writes ground_truth back into that dataset (or --out) in
place, adding a "ground_truth" field to every command dict. Checkpoints
every 10 sessions (and on exit) so progress isn't lost if interrupted —
this can be a long run (2000+ docker exec calls plus ~270 container resets).

Every session in this file was already filtered to have ZERO blocked
commands (see select_stateful_sessions.py), so "blocked" should never
actually trigger here — handled anyway for safety/robustness.

Requires working Docker access (your user in the `docker` group, or a
shell where `sudo docker` doesn't prompt for a password) — this script
does not attempt to escalate or bypass that itself.

Usage:
    python experiment_data/PartC/collect_ground_truth_sessions.py
─────────────────────────────────────────────────────────────────
"""

import os
import re
import sys
import json
import uuid
import yaml
import argparse
import shlex
import subprocess

# PartC/, not this sub-folder: _NSC and _ROOT are derived from it.
_HERE  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSC   = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT  = os.path.abspath(os.path.join(_HERE, "..", ".."))
_PARTB = os.path.join(_NSC, "PartB")
# build_partB_benchmark.py sits in PartB/build/, not PartB/ — without this the
# import below raises ModuleNotFoundError and the collector cannot start.
_PARTB_BUILD = os.path.join(_PARTB, "build")
for p in (_ROOT, _NSC, _PARTB, _PARTB_BUILD):
    if p not in sys.path:
        sys.path.insert(0, p)

from build_partB_benchmark import (start_container, reset_container, exec_cmd,
                                   stop_container, DOCKER, CONTAINER, TIMEOUT)

# No default dataset path on purpose. This used to point at
# dataset/partC_stateful_sessions.json, so running the collector with no
# arguments silently reopened a months-old selection that already carried
# ground truth from a 22.04 container -- the source of every "why is this
# mixed" surprise. The dataset to fill is now always named explicitly.

# Programs that never exit on their own -- read from config.yaml's
# static_commands, the list HydraPoT already maintains for exactly this
# property (it answers them without consulting an agent at all). Each one
# otherwise burns the full 10s timeout: `top` alone is 4.2% of ml4net, so on
# a 50k-command run that is ~2000 commands x 10s = 5.8 hours of waiting for
# output that is identical after 2 seconds. The ones in the list that DO
# terminate (tail on a file, a short ping) finish in milliseconds and are
# unaffected by the shorter ceiling.
HANG_TIMEOUT = 2

# Builtins that end the shell they run in. Every command shares one shell now,
# so these are run in a subshell instead of taking the session with them.
SHELL_EXIT = {"exit", "logout"}

_BUILTINS = None


def _builtins():
    """The container's own list of shell builtins, from `compgen -b`.

    Asked rather than listed here, so it is whatever that bash really
    supports instead of a copy that can drift. Cached: one exec per run."""
    global _BUILTINS
    if _BUILTINS is None:
        r = subprocess.run(f"{DOCKER} exec {CONTAINER} bash -c 'compgen -b'",
                           shell=True, capture_output=True, timeout=60)
        _BUILTINS = set(r.stdout.decode().split())
    return _BUILTINS

with open(os.path.join(_ROOT, "config.yaml"), encoding="utf-8") as _fh:
    HANGS = set(yaml.safe_load(_fh).get("static_commands") or [])


def _timeout_for(cmd):
    """Short ceiling for a command whose program will not exit by itself."""
    toks = cmd.split()
    if toks and os.path.basename(toks[0]) in HANGS:
        return HANG_TIMEOUT
    return None            # None -> exec_cmd's own default


def _build_oneline(cmds, marker):
    """A session as ONE bash command line: every command in the SAME shell.

    Two properties matter, and both come from the shape of this string.

    `cd` works. One `docker exec` per command gave each command a brand-new
    shell at the image's working directory, so `cd /tmp` had no effect on the
    next command and `cd /tmp ; ls -a` recorded the listing of `/`. 73 of the
    109 sessions in the old 2179-command dataset were collected that way.

    Diagnostics read as they do on a real box. bash adds a "line N: " to its
    messages when its input spans several lines, and omits it when the input
    is a single line -- however many commands that line holds:
        bash -c $'echo a\\n/nope'  -> bash: line 1: /nope: No such file ...
        bash -c 'echo a; /nope'    -> bash: /nope: No such file ...
    An interactive SSH session shows the second form, so everything is
    joined with "; " onto one line and nothing has to be rewritten afterwards.

    Each command goes through `eval` so that it still runs in this shell
    (`cd`, `export` and the rest keep working) while "; " can follow it even
    when it ends in `&`, which is a syntax error otherwise. Commands reach
    eval shell-quoted, so an attacker string needs no escaping of its own.
    Verbs in HANGS are additionally wrapped in `timeout`; every one of them
    is an external binary, so wrapping cannot break a builtin.
    """
    # __run asks the container, per command, whether the verb is a shell
    # builtin. A builtin is eval'd so it still affects THIS shell (`cd`,
    # `export`); anything else goes through `timeout`, which can only wrap an
    # external binary. Every external command therefore gets a ceiling, which
    # the HANGS list alone could not provide: `screen` is not in config.yaml's
    # static_commands, and one bare `screen` under a PTY hung a whole
    # 41-command session for the full budget.
    parts = ["exec 2>&1",                      # merge stderr once, for all
             "__hp() { printf '\\n%s%s__\\n' '" + marker + "' \"$1\"; }"]
    builtins = _builtins()
    for i, cmd in enumerate(cmds):
        parts.append(f"__hp {i}")
        verb = os.path.basename(cmd.split()[0]) if cmd.split() else ""
        if verb in builtins:
            # Bare, not through a helper. Dispatching builtins via
            # `__run() { ... eval "$1" ... }` made bash attribute their
            # failures to the function -- "environment: line 0: cd: ..."
            # instead of "bash: line 0: cd: ..." -- a prefix no real shell
            # ever prints. `timeout` cannot wrap a builtin anyway, so there
            # is nothing to gain by routing it through one.
            run = cmd
        else:
            # -k: SIGTERM, then SIGKILL 2s later. Plain `timeout` sends only
            # SIGTERM, and su / sudo / passwd ignore it while sitting at a
            # password prompt -- which they reach by opening /dev/tty
            # directly, so `</dev/null` does not stop them and `docker exec
            # -t` hands them a terminal to find. One such command held its
            # whole session until the overall budget expired: 35% of sessions
            # hung this way, at up to 29 minutes each. SIGKILL cannot be
            # ignored.
            run = (f"timeout -k 2 {_timeout_for(cmd) or TIMEOUT} "
                   f"bash -c {shlex.quote(cmd)}")
        # `exit` ends the shell it runs in, so every later command and marker
        # would be lost -- ml4net has 17,612 of them, and the old
        # one-exec-per-command collector never hit this. A subshell keeps it
        # local.
        parts.append(f"( {run} )" if verb in SHELL_EXIT else run)
    parts.append(f"__hp {len(cmds)}")          # closes the last command
    return "; ".join(parts)


def _split_output(text, marker, n):
    """Marker-delimited stdout -> one string per command, verbatim."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    chunks = re.split(re.escape(marker) + r"(\d+)__\n?", text)
    out = {}
    for j in range(1, len(chunks) - 1, 2):
        out[int(chunks[j])] = chunks[j + 1]
    return [out.get(i, "").strip() for i in range(n)]


def exec_session(cmds):
    """Run a whole session in one shell, in ONE docker exec. Returns a list
    of outputs aligned with `cmds`."""
    marker = "__HPGT_" + uuid.uuid4().hex + "_"
    oneline = _build_oneline(cmds, marker)

    # Worst case is every command hitting its own ceiling; normal commands
    # finish in milliseconds, so this bound is only reached if the session
    # really does hang throughout.
    budget = sum(_timeout_for(c) or TIMEOUT for c in cmds) + 60
    try:
        r = subprocess.run(
            f"{DOCKER} exec -t {CONTAINER} bash -c {shlex.quote(oneline)}",
            shell=True, capture_output=True, timeout=budget,
            stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or b"").decode("utf-8", errors="replace")
        return _split_output(partial, marker, len(cmds))
    return _split_output(r.stdout.decode("utf-8", errors="replace"),
                         marker, len(cmds))


def _checkpoint(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True, metavar="PATH",
                    help="the selected-sessions JSON to fill in place. "
                         "select_stateful_sessions.py names its output after "
                         "the command count, so pass that "
                         "dataset_groundtruth_<N>.json here. Required: there "
                         "is deliberately no default, so no run can reach for "
                         "an older dataset on its own.")
    ap.add_argument("--per-command", action="store_true",
                    help="run one docker exec per command, the old way. Each "
                         "command then gets a FRESH shell, so `cd` does not "
                         "carry over and `cd /tmp ; ls` records the listing of "
                         "/ -- kept only for comparing against datasets "
                         "collected before the one-shell-per-session fix.")
    ap.add_argument("--session-id", default=None, metavar="ID",
                    help="collect only this one session — use it to check a "
                         "session you know contains a `cd` before trusting a "
                         "full run.")
    ap.add_argument("--limit", type=int, default=0, metavar="N",
                    help="collect only the first N sessions.")
    ap.add_argument("--out", default=None, metavar="PATH",
                    help="write to PATH instead of rewriting --dataset in "
                         "place. Use it for a trial run so the real dataset "
                         "and whatever ground truth it already holds are left "
                         "untouched.")
    ap.add_argument("--resume", action="store_true",
                    help="keep the ground truth already in the file and only "
                         "collect the sessions that have none. Without this "
                         "the file is cleared first, which is right for a "
                         "fresh run but throws away a partial one.")
    ap.add_argument("--redo-hung", action="store_true",
                    help="with --resume, also re-collect sessions whose output "
                         "stops partway -- the signature of a command that "
                         "outlived the old SIGTERM-only timeout (su, sudo su, "
                         "passwd). Their stored output is empty-by-timeout, "
                         "not genuinely empty.")
    args = ap.parse_args()
    path, per_command = args.dataset, args.per_command
    out_path = args.out or path

    data     = json.load(open(path, encoding="utf-8"))
    sessions = data["sessions"]

    if args.session_id is not None:
        sessions = [s for s in sessions
                    if str(s["session_id"]) == str(args.session_id)]
        if not sessions:
            raise SystemExit(f"[ground-truth] no session with id "
                             f"{args.session_id} in {path}")
    if args.limit:
        sessions = sessions[:args.limit]

    def _incomplete(s):
        return any(c.get("ground_truth") is None for c in s["commands"])

    def _hung(s):
        """A session whose output stops partway and never resumes.

        Before `timeout -k`, a command that ignored SIGTERM (su, sudo su,
        passwd -- they read the password from /dev/tty, so </dev/null does
        not stop them) held the shell until the whole session's budget
        expired. Everything after it was recorded as "" by the marker split.
        A trailing run of empties with real output before it is that
        signature; a session that is empty throughout is usually legitimate
        (mkdir/cd/touch produce nothing)."""
        cs = s["commands"]
        if any(c.get("ground_truth") is None for c in cs):
            return False
        trail = 0
        for c in reversed(cs):
            if c["ground_truth"] == "":
                trail += 1
            else:
                break
        return 0 < trail < len(cs)

    if args.resume:
        # Keep what is already in the file and only run what is missing.
        # `data["sessions"]` stays whole so finished work survives the
        # checkpoint; only the to-run list is filtered.
        todo = [s for s in sessions if _incomplete(s)]
        hung = [s for s in sessions if _hung(s)]
        if args.redo_hung:
            ids = {id(s) for s in todo}
            for s in hung:
                if id(s) not in ids:
                    for c in s["commands"]:
                        c.pop("ground_truth", None)
                        c.pop("error", None)
                    todo.append(s)
        print(f"[resume] {len(sessions) - len(todo)} sessions already done, "
              f"{len(todo)} to collect")
        print(f"[resume] {len(hung)} sessions look truncated by the old "
              f"SIGTERM-only timeout"
              + (" -- re-collecting them" if args.redo_hung else
                 " -- kept as-is; pass --redo-hung to redo them"))
        sessions = todo
    else:
        # Write out ONLY the sessions this run collects, and drop any
        # ground_truth already sitting on them.
        #
        # Both halves matter. `data` held all 109 sessions while `sessions`
        # was filtered to the one being collected, and the checkpoint wrote
        # `data`, so the other 108 went to the output file carrying ground
        # truth from an earlier run -- a file that silently mixed a 22.04
        # container's output (apt 2.4.11, `ls` always listing /) with a fresh
        # 20.04 one. Nothing in it could be trusted and nothing said so.
        # Clearing first means an interrupted run leaves nulls, which are
        # obviously missing, instead of stale values that look collected.
        data["sessions"] = sessions
        for s in sessions:
            for c in s["commands"]:
                c.pop("ground_truth", None)
                c.pop("error", None)

    total_sessions = len(sessions)
    total_commands = sum(len(s["commands"]) for s in sessions)
    n_hang = sum(1 for s in sessions for c in s["commands"]
                 if _timeout_for(c["cmd"]) is not None)
    print(f"[ground-truth] {path}")
    print(f"[ground-truth] {total_sessions} sessions, {total_commands} commands to run")
    print(f"[ground-truth] {n_hang} of them are non-terminating programs "
          f"(capped at {HANG_TIMEOUT}s instead of the default)")

    start_container()

    n_ok = n_empty = n_blocked = n_error = done_commands = 0

    try:
        for i, s in enumerate(sessions, 1):
            if i > 1:
                reset_container()   # fresh container PER SESSION, not per command

            live = [c for c in s["commands"] if not c.get("blocked")]
            for c in s["commands"]:
                if c.get("blocked"):
                    c["ground_truth"] = None
                    n_blocked += 1

            if per_command:
                outs = []
                for c in live:
                    # a single command failing (timeout, decode issue, docker
                    # hiccup) must not kill a run collecting thousands
                    try:
                        gt, _rc = exec_cmd(c["cmd"], timeout=_timeout_for(c["cmd"]))
                        outs.append(gt)
                    except Exception as e:
                        c["error"] = str(e)
                        outs.append(None)
            else:
                outs = exec_session([c["cmd"] for c in live])
                if outs is None:
                    outs = [None] * len(live)
                    for c in live:
                        c["error"] = "could not plant session script in container"

            for c, gt in zip(live, outs):
                done_commands += 1
                if gt is None:
                    c["ground_truth"] = None
                    n_error += 1
                    continue
                c["ground_truth"] = gt
                if gt.strip():
                    n_ok += 1
                else:
                    n_empty += 1

            if i % 10 == 0 or i == total_sessions:
                print(f"[ground-truth] {i}/{total_sessions} sessions, "
                      f"{done_commands}/{total_commands} commands "
                      f"({n_ok} ok, {n_empty} empty, {n_blocked} blocked, {n_error} error)")
                _checkpoint(data, out_path)   # don't lose progress if interrupted

    finally:
        stop_container()
        _checkpoint(data, out_path)

    runnable = n_ok + n_empty
    print(f"\n[ground-truth] done -> {out_path}")
    print(f"[ground-truth] {n_ok}/{total_commands} succeeded (non-empty ground truth)")
    print(f"[ground-truth] {n_empty}/{total_commands} ran but produced empty output")
    print(f"[ground-truth] {n_blocked}/{total_commands} blocked (skipped for safety)")
    print(f"[ground-truth] {n_error}/{total_commands} errored (see each record's \"error\" field)")
    if runnable:
        print(f"[ground-truth] success rate of runnable commands: "
              f"{n_ok}/{runnable} = {100*n_ok/runnable:.1f}%")


if __name__ == "__main__":
    main()
