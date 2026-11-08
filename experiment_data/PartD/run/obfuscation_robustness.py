"""
experiment_data/PartD/run/obfuscation_robustness.py — how many commands that
SHOULD stay on Cowrie (real FI==0, real classify()==cowrie) get escalated to
Cloud/on_device once obfuscated with Bashfuscator.

Router code is NOT modified here. core/router.py's _deobfuscate() only
unwraps 3 narrow disguises (base64-pipe, \\xNN hex runs, $(echo ...)); it has
no idea about Bashfuscator's rot13/xor/case-swap/reverse/glob/token tricks,
so those are left as garbled text and the FI scorer can't match any pattern
against it -> falls through to a higher band -> Cloud. This measures that
gap as it exists today.

Input commands: experiment_data/results/partC/fidelity/cowrie.jsonl -- the
same real 2179-command attacker-session dataset every other Part C result
uses (not a separate synthetic corpus), filtered to fi_score==0 AND
core.router.classify()=="cowrie" (the real baseline -- a few FI0 commands
already escalate on their own via COWRIE_UNIMPLEMENTED, unrelated to
obfuscation).

Usage:
    python experiment_data/PartD/run/obfuscation_robustness.py [--variants 5] [--layers 2]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from types import SimpleNamespace

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, _ROOT)
# experiment_data/ itself, so agents.py's `from _paths import ...` resolves --
# the Part C scripts run with that directory on the path.
sys.path.insert(0, os.path.join(_ROOT, "experiment_data"))
sys.path.insert(0, os.path.join(_ROOT, "third_party", "Bashfuscator"))

from core.router import classify                # noqa: E402

OUT_DIR = os.path.join(_ROOT, "experiment_data", "results", "partD", "obfuscation_robustness")
FIDELITY_COWRIE = os.path.join(_ROOT, "experiment_data", "results", "partC", "fidelity", "cowrie.jsonl")


def load_cowrie_baseline() -> list[str]:
    """Real fi_score==0, real classify()==cowrie commands from the Part C
    fidelity dataset -- same 2179-command real attacker-session corpus every
    other Part C result is built from."""
    rows = [json.loads(l) for l in open(FIDELITY_COWRIE, encoding="utf-8")]

    seen, out = set(), []
    for r in rows:
        if r.get("fi_score") != 0:
            continue
        cmd = r["cmd"].strip()
        if cmd in seen:
            continue
        seen.add(cmd)
        if classify(cmd, []) == "cowrie":
            out.append(cmd)
    return out


def make_obfuscation_handler(layers: int):
    """Bashfuscator's ObfuscationHandler, called as a library -- bypasses the
    CLI script's `stty size` call, which has no terminal to query here.

    payload_size=1 (small): a real attacker pastes a one-liner, not megabytes
    of escape soup -- payload_size=2/3 inflate output into the hundreds of KB
    to MB range (see experiment notes), well past what any LLM API would
    accept as a single command."""
    from bashfuscator.core.engine.obfuscation_handler import ObfuscationHandler

    args = SimpleNamespace(
        layers=layers, payload_size=1, execution_time=2, binaryPref=None,
        no_file_write=True, write_dir="/tmp/", full_ascii_strings=False,
        debug=False, clip=False, command=None,
        choose_mutators=None, choose_all=None,
        no_mangling=None, no_binary_mangling=None, binary_mangle_percent=None,
        no_random_whitespace=None, random_whitespace_range=None,
        no_insert_chars=None, insert_chars_range=None,
        no_misleading_commands=None, misleading_commands_range=None,
        no_integer_mangling=None, no_integer_expansion=None,
        no_integer_base_randomization=None, integer_expansion_depth=None,
        no_terminator_randomization=None,
    )
    return ObfuscationHandler(args=args)


def obfuscate(cmd: str, handler, n: int) -> list[str]:
    out = []
    for _ in range(n):
        handler.originalCmd = cmd
        handler.mutatorList = []
        handler.prevCmdOb = None
        try:
            out.append(handler.generatePayload())
        except Exception as e:
            print(f"  [skip] {cmd!r}: {e}")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Experiment 2: does obfuscation break COWRIE ITSELF?
#
# Experiment 1 above asks where an obfuscated command ROUTES. This asks a
# different question: send the obfuscated command straight to Cowrie and see
# whether Cowrie's emulated shell still answers it the same way it answered the
# plain command. Real bash would `eval` the payload back to the original;
# Cowrie emulates a shell rather than being one, so it may not -- and a failure
# here is a fingerprinting signal (the honeypot behaves differently from a real
# host under obfuscation).
#
# These commands are EXECUTED in the Cowrie container. That is safe by design:
# Cowrie is a sandbox, its wget/curl are faked, and nothing reaches a real
# host. The corpus is the ml4net ground-truth attacker dataset, sent as-is
# (downloaders included) so the measurement reflects real traffic.
# ──────────────────────────────────────────────────────────────────────────

ML4NET = os.path.join(_ROOT, "dataset", "dataset_groundtruth_ml4net_50006.json")
COWRIE_OUT = os.path.join(OUT_DIR, "cowrie_success.json")


def load_sessions(n: int) -> list[dict]:
    """First `n` sessions, each as {session_id, commands:[{cmd, ground_truth,
    fi}]}.

    Session is the sampling unit because the ground truth was produced per
    session with state carried across its commands (a `cd` or a variable set
    early changes what a later command prints). Reading sessions whole, in
    order, is what lets the replay match the conditions the ground truth was
    recorded under.
    """
    data = json.load(open(ML4NET, encoding="utf-8"))
    out = []
    for sess in data["sessions"][:n]:
        cmds = [{"cmd": (e.get("cmd") or "").strip(),
                 "ground_truth": e.get("ground_truth") or "",
                 "fi": e.get("fi")}
                for e in sess.get("commands", []) if (e.get("cmd") or "").strip()]
        if cmds:
            out.append({"session_id": sess.get("session_id"), "commands": cmds})
    return out


def _norm(text: str) -> str:
    """Compare outputs ignoring only trailing whitespace per line.

    An exact match after this means Cowrie produced the same bytes for the
    OBFUSCATED command as the dataset recorded for the plain one -- i.e. Cowrie
    decoded the obfuscation and answered as if it had seen the original.
    """
    return "\n".join(line.rstrip() for line in (text or "").splitlines()).strip()


def _is_error(text: str) -> bool:
    """A response that is empty or a shell complaint, not a real answer.

    Applied to the dataset's ground truth, to split 'Cowrie should have
    produced a real answer' from 'the plain command already errors' -- the
    latter is not an obfuscation failure.
    """
    t = _norm(text).lower()
    if not t:
        return True
    markers = ("command not found", "syntax error", "unexpected",
               "no such file", "not found", "bad substitution")
    return any(m in t for m in markers)


class _Channel:
    """Captures what the pipeline streams out, for commands that write via the
    streaming path instead of returning a string."""
    def __init__(self):
        self._buf = []
    def write(self, s):
        self._buf.append(s)
    def read(self, *_a, **_k):
        return ""
    def text(self):
        return "".join(self._buf)


def _recover(cowrie):
    """Abort any half-parsed payload and drain to a clean prompt.

    A Bashfuscator payload with an unbalanced quote or heredoc leaves Cowrie's
    shell at a continuation prompt, and the next command's output then bleeds
    into this one's -- so row N could record row N-1's bytes. Ctrl-C aborts the
    pending line; the drain clears the buffer. Run after every command so the
    next one starts from a clean prompt. State (cwd, files) is untouched, so it
    still accumulates within a session.
    """
    import time
    sh = getattr(cowrie, "shell", None)
    if sh is None:
        return
    try:
        sh.send("\x03")          # Ctrl-C: drop any pending continuation line
        sh.send("\n")            # ask for a fresh prompt
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if sh.recv_ready():
                sh.recv(9999)
                deadline = time.time() + 0.3   # keep draining until quiet
            else:
                time.sleep(0.02)
    except Exception:
        cowrie.available = False


def cowrie_success_rate():
    """Obfuscate each command from N sessions, send it THROUGH HydraPoT forced
    to Cowrie, and compare Cowrie's response against the dataset's ground truth.

    "Through HydraPoT", not the raw agent: the obfuscated command runs the real
    make_command_handler pipeline -- FI scoring, state sync, the Cowrie proxy --
    with the agent pinned to cowrie and the other two disabled. So this measures
    Cowrie as it actually sits inside the system, not a bare SSH call.

    One pass only: the dataset's ground truth IS the plain-command baseline, so
    there is nothing to send twice. A match means Cowrie saw through the
    obfuscation.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=50,
                    help="how many ml4net sessions to replay")
    ap.add_argument("--layers", type=int, default=1,
                    help="Bashfuscator --layers (the task asks for level 1)")
    ap.add_argument("--progress-every", type=int, default=10,
                    help="print progress every N sessions")
    args = ap.parse_args()

    import tempfile
    from experiment_data.agents import build_agents
    import main as hydrapot_main
    from core import router

    sessions = load_sessions(args.sessions)
    n_cmds = sum(len(s["commands"]) for s in sessions)
    print(f"{len(sessions)} sessions, {n_cmds} commands, level-{args.layers} "
          f"obfuscation\n")

    base = build_agents(connect_cowrie=True, load_on_device=False)
    if not base.cowrie_ok:
        raise SystemExit("Cowrie is not reachable -- start the container "
                         "(hp --run, or docker start honeypot_cowrie_1) first.")

    # Disable the other two agents, so even a fallback inside the pipeline
    # cannot reach the paid cloud or load the GPU -- force_agent already pins
    # cowrie, this is the belt to its braces.
    saved_enabled = dict(router._AGENTS_ENABLED)
    router._AGENTS_ENABLED = {"cowrie": True, "on_device": False, "cloud": False}

    handler = make_obfuscation_handler(args.layers)
    # store="json" to a tempdir, never the sqlite default: that would write
    # these replayed commands into the real capture DB. The logs are a
    # by-product we do not keep (same reason guardrail/DES.py does this).
    log_dir = tempfile.mkdtemp(prefix="partd_obf_")

    rows = []
    stats = Counter()
    try:
        for si, sess in enumerate(sessions):
            # Fresh handle per session -> fresh SYSTEM_STATE, so one session's
            # `cd` or variables do not leak into the next. This matches how the
            # ground truth was collected (reset between sessions).
            # Fresh shell per session too: reconnect gives a clean /root with no
            # files or variables, matching how the ground truth was collected
            # (reset between sessions). CowrieLink rebuilds state from the fresh
            # handle on its first command.
            base.cowrie._connect()
            handle = hydrapot_main.make_command_handler(
                base.cowrie,
                src_ip=f"partd_obf_{sess['session_id']}",
                public_ip=f"partd_obf_{sess['session_id']}",
                plugins=None, store="json",
                store_dir=os.path.join(log_dir, str(sess["session_id"])),
            )
            for entry in sess["commands"]:
                cmd, gt = entry["cmd"], entry["ground_truth"]
                variants = obfuscate(cmd, handler, 1)
                if not variants:
                    stats["obfuscation_failed"] += 1
                    continue
                obf = variants[0]

                ch = _Channel()
                try:
                    ret = handle(obf, ch.write, ch.read, force_agent="cowrie")
                    out = ret[0] if isinstance(ret, tuple) else ret
                    obf_out = out if out else ch.text()
                except Exception as e:
                    obf_out = ""
                    print(f"  [err] {cmd!r}: {type(e).__name__}: {e}")
                finally:
                    # Resync before the next command, so a payload that left the
                    # shell mid-parse cannot bleed into the next row.
                    _recover(base.cowrie)

                match = _norm(obf_out) == _norm(gt)
                gt_clean = not _is_error(gt)
                stats["total"] += 1
                stats["match"] += int(match)
                stats["gt_clean"] += int(gt_clean)
                if gt_clean:
                    stats["match_given_gt_clean"] += int(match)

                rows.append({
                    "session_id": sess["session_id"],
                    "command": cmd,
                    "obfuscated": obf,
                    "ground_truth": gt,
                    "cowrie_output": obf_out,
                    "routed_to": getattr(handle, "last_agent", None),
                    "fi": entry["fi"],
                    "match": match,
                })
            if (si + 1) % args.progress_every == 0:
                t = stats["total"] or 1
                print(f"  {si + 1}/{len(sessions)} sessions  "
                      f"match {stats['match']}/{stats['total']} "
                      f"({100 * stats['match'] / t:.1f}%)")
    finally:
        router._AGENTS_ENABLED = saved_enabled
        base.cowrie.disconnect()

    total = stats["total"] or 1
    clean = stats["gt_clean"] or 1
    print("\n" + "=" * 64)
    print(f"  obfuscated commands sent to Cowrie: {stats['total']}")
    print(f"  matched ground truth:               {stats['match']} "
          f"({100 * stats['match'] / total:.1f}%)   <- Cowrie handled it")
    print(f"  ...of those whose plain answer is a real response (not an error):")
    print(f"       {stats['match_given_gt_clean']}/{stats['gt_clean']} "
          f"({100 * stats['match_given_gt_clean'] / clean:.1f}%)")
    if stats["obfuscation_failed"]:
        print(f"  Bashfuscator could not obfuscate:   {stats['obfuscation_failed']}")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(COWRIE_OUT, "w", encoding="utf-8") as fh:
        json.dump({
            "dataset": os.path.relpath(ML4NET, _ROOT),
            "sessions": len(sessions),
            "layers": args.layers,
            "sent": stats["total"],
            "match": stats["match"],
            "gt_clean": stats["gt_clean"],
            "match_given_gt_clean": stats["match_given_gt_clean"],
            "obfuscation_failed": stats["obfuscation_failed"],
            "rows": rows,
        }, fh, indent=2)
    print(f"\nwrote {COWRIE_OUT}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variants", type=int, default=5, help="obfuscated variants per command")
    ap.add_argument("--layers", type=int, default=2, help="Bashfuscator --layers")
    args = ap.parse_args()

    baseline = load_cowrie_baseline()
    print(f"baseline: {len(baseline)} real FI0/cowrie-routed commands\n")

    handler = make_obfuscation_handler(args.layers)

    rows = []
    route_counts = Counter()
    for i, cmd in enumerate(baseline):
        variants = obfuscate(cmd, handler, args.variants)
        for v in variants:
            route = classify(v, [])
            route_counts[route] += 1
            rows.append({"original": cmd, "obfuscated": v, "routed_to": route})
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(baseline)} commands done")

    total = sum(route_counts.values())
    escalated = total - route_counts.get("cowrie", 0)
    to_cloud = route_counts.get("cloud", 0)

    print("\n" + "=" * 60)
    print(f"  {total} obfuscated variants from {len(baseline)} Cowrie-bound commands")
    for route, n in route_counts.most_common():
        print(f"  -> {route:<12}{n:>6}  ({100 * n / total:.1f}%)")
    print(f"\n  escalated off Cowrie entirely: {escalated}/{total} ({100 * escalated / total:.1f}%)")
    print(f"  escalated to Cloud specifically: {to_cloud}/{total} ({100 * to_cloud / total:.1f}%)")

    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, "results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({
            "baseline_n": len(baseline),
            "variants_per_command": args.variants,
            "layers": args.layers,
            "route_counts": dict(route_counts),
            "total_variants": total,
            "escalated_off_cowrie": escalated,
            "escalated_to_cloud": to_cloud,
            "rows": rows,
        }, fh, indent=2)
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    # Two experiments in one file. Default stays `main` (the routing-gap one,
    # experiment 1) so nothing that called this script before changes; the new
    # Cowrie-robustness one is reached by name as the first argument.
    if len(sys.argv) > 1 and sys.argv[1] == "cowrie":
        sys.argv.pop(1)
        cowrie_success_rate()
    else:
        main()
