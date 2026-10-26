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
    main()
