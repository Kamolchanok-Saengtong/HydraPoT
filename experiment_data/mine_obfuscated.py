"""
experiment_data/mine_obfuscated.py — extract REAL obfuscated commands from ML4Net.
─────────────────────────────────────────────────────────────────
Reads ML4Net's raw parquet (233K real attacker sessions), splits sessions
into single commands, and keeps those that trip the project's REAL _is_cloud
detector via one of its genuine obfuscation rules (eval, pipe-to-shell,
subshell, base64 -d, hex-escape, var-split, bash -c, /dev/tcp) — NOT the
entropy/operator-count fallback, so the set is cleanly "obfuscated".

Each kept command is tagged with which mechanism it triggered, so the eval
can report mechanism coverage + routing accuracy.

Output: dataset/obfuscated_commands.json
    [{"command": ..., "mechanism": ..., "source": "ML4Net",
      "expected_route": "cloud"}, ...]

Run once (needs the ML4Net parquet locally; download from
github.com/ML4Net/SSH-Shell-Attacks, data/raw/ssh_attacks.parquet):

    python mine_obfuscated.py /path/to/ssh_attacks.parquet --per-mechanism 6
"""

import os
import re
import sys
import json
import argparse

# import the REAL detector so mined commands provably route to cloud
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
sys.path.insert(0, _ROOT)
from core.router import _is_cloud   # noqa: E402

OUT_PATH = os.environ.get(
    "NSC_OBFUSCATED_FILE",
    os.path.join(_ROOT, "dataset", "obfuscated_commands.json"),
)


def which_mechanism(cmd: str) -> str | None:
    """
    Return which genuine obfuscation rule fires (mirrors _is_cloud rules 1-8),
    or None if only the entropy/operator-count fallback would catch it.
    Keeps the curated set to *real* obfuscation, not benign multi-operator lines.
    """
    if re.search(r'\beval\b', cmd):                                   return "eval"
    if re.search(r'\|\s*(bash|sh|python3?|perl|ruby)\b', cmd):        return "pipe-to-shell"
    if re.search(r'\$\(.*\)', cmd) or re.search(r'`[^`]+`', cmd):     return "subshell"
    if re.search(r'base64\s+-d', cmd):                               return "base64"
    if re.search(r'(\\x[0-9a-fA-F]{2}){3,}', cmd):                   return "hex-escape"
    if re.search(r'\$[a-zA-Z]\$[a-zA-Z]', cmd):                      return "var-split"
    if re.search(r'bash\s+-c\b', cmd):                              return "bash-c"
    if re.search(r'/dev/tcp/', cmd):                                return "dev-tcp"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("parquet", help="path to ML4Net ssh_attacks.parquet (raw)")
    ap.add_argument("--per-mechanism", type=int, default=6,
                    help="max commands to keep per obfuscation mechanism")
    ap.add_argument("--max-len", type=int, default=160,
                    help="skip commands longer than this (keep examples readable)")
    args = ap.parse_args()

    try:
        import pandas as pd
    except ImportError:
        print("[!] need pandas+pyarrow: pip install pandas pyarrow")
        sys.exit(1)

    df = pd.read_parquet(args.parquet)
    col = "full_session" if "full_session" in df.columns else df.columns[0]

    buckets: dict[str, list[str]] = {}
    seen: set[str] = set()
    for sess in df[col].astype(str):
        for cmd in sess.split(";"):
            cmd = cmd.strip()
            if not cmd or cmd in seen or len(cmd) > args.max_len:
                continue
            mech = which_mechanism(cmd)
            if mech is None:
                continue
            # double-check it actually trips the real detector
            if not _is_cloud(cmd):
                continue
            seen.add(cmd)
            buckets.setdefault(mech, [])
            if len(buckets[mech]) < args.per_mechanism:
                buckets[mech].append(cmd)

    out = []
    for mech, cmds in buckets.items():
        for c in cmds:
            out.append({"command": c, "mechanism": mech,
                        "source": "ML4Net", "expected_route": "cloud"})

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    json.dump(out, open(OUT_PATH, "w"), indent=2, ensure_ascii=False)

    print(f"[mine] mechanisms found: "
          f"{ {m: len(c) for m, c in buckets.items()} }")
    print(f"[mine] saved {len(out)} obfuscated commands -> {OUT_PATH}")


if __name__ == "__main__":
    main()