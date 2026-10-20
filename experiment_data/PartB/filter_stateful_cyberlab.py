"""
experiment_data/PartB/filter_stateful_cyberlab.py
─────────────────────────────────────────────────────────────────
Filter stateful commands from cyberlab sessions for HydraPoT evaluation.

A command is STATEFUL if its correct response depends on a previous command
in the SAME session — read-after-write only. A later command only counts as
a read if it references the SAME resource (filename/dir/package/user/service/
var name) a specific prior command created — not just "any read command
appears later" (that would flag whoami/uname/ps/id etc. as stateful, which
they never are).

Mechanisms (see _match_write / _is_read):
  echo/touch              -> file   read: cat/ls/chmod file, or ./file
  mkdir dir               -> dir    read: cd dir, ls dir
  apt/apt-get install pkg -> pkg    read: pkg <args>, which pkg
  useradd/adduser user    -> user   read: id user, su user
  systemctl start svc     -> svc    read: systemctl status svc
  export VAR=val          -> var    read: any cmd containing $VAR

wget/curl are deliberately NOT treated as a write mechanism — evaluating a
pair derived from them would mean actually downloading the (often malicious)
payload URL during eval. Excluded outright, not just skipped downstream.

No Docker execution, no ground truth collection here — just extraction and
formatting. Ground truth for a session gets collected later by replaying
the WHOLE session (not just the two flagged commands) up through test_cmd.

Sessions are scanned directly from the raw dataset/cyberlab_*.json files
(every file matching that glob, not just one hardcoded filename) so the
full, unmodified raw event list for each flagged session can be attached to
the output — independently verifiable against the source file, nothing
synthesized.

Output: dataset/stateful_benchmark.json, one record per SESSION that has
>=1 stateful pair (real session_id exactly as it appears in the source
file, plus the untouched raw event list for that session):
{
  "session_id":  "<real session_id from the dataset file>",
  "source":      "cyberlab_2019-08-05.json",
  "full_entry":  [ ...raw events for this session, verbatim... ],
  "pairs": [
    {"setup_cmd": "...", "test_cmd": "...", "fi_setup": int, "fi_test": int}
  ]
}

Usage:
    python experiment_data/PartB/filter_stateful_cyberlab.py
─────────────────────────────────────────────────────────────────
"""

import os
import re
import sys
import json
import glob

_HERE = os.path.dirname(os.path.abspath(__file__))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _NSC):
    if p not in sys.path:
        sys.path.insert(0, p)

from workloads import _COMMAND_EVENT_PREFIXES
from prompt.fi_manager import FIScorer

DATASET_DIR = os.path.join(_ROOT, "dataset")
OUTPUT_PATH = os.path.join(DATASET_DIR, "stateful_benchmark.json")


def _strip_sudo(cmd: str) -> str:
    """Strip leading sudo so match patterns work regardless of privilege prefix."""
    cmd = cmd.strip()
    if cmd.startswith("sudo "):
        cmd = cmd[5:].strip()
    return cmd


def _match_write(cmd: str):
    """Returns (write_type, resource) if `cmd` creates a named resource, else None."""
    # FIX 1: strip sudo before matching so 'sudo touch file' is caught
    cmd = _strip_sudo(cmd)

    m = re.match(r"^echo\s+.*>>?\s*(\S+)$", cmd)
    if m:
        return "file", m.group(1)

    m = re.match(r"^touch\s+(\S+)$", cmd)
    if m:
        return "file", m.group(1)

    # `cp SRC DEST` creates DEST — search (not ^-anchored) because ml4net
    # commonly logs this as one alternative in a "||" chain kept in the same
    # fragment, e.g. 'cat .s || cp /bin/echo .s' (classic IoT-botnet
    # architecture-fingerprint loader: copy /bin/echo locally, then read its
    # ELF header bytes back to guess CPU arch).
    m = re.search(r"\bcp\s+(?:-\S+\s+)*(\S+)\s+(\S+)", cmd)
    if m:
        return "file", m.group(2)

    # NOTE: wget/curl intentionally excluded — see module docstring.

    # FIX 4: handle any flags (e.g. mkdir -m 755 dir), not just -p
    m = re.match(r"^mkdir\s+(?:-\S+\s+)*(\S+)$", cmd)
    if m:
        return "dir", m.group(1)

    m = re.search(r"\b(?:apt|apt-get)\s+install\s+(?:-\S+\s+)*(\S+)", cmd)
    if m:
        return "pkg", m.group(1)

    # FIX 2: handle both useradd and adduser
    m = re.match(r"^(?:useradd|adduser)\s+(?:-\S+\s+)*(\S+)$", cmd)
    if m:
        return "user", m.group(1)

    m = re.match(r"^systemctl\s+start\s+(\S+)$", cmd)
    if m:
        return "svc", m.group(1)

    m = re.match(r"^export\s+([A-Za-z_][A-Za-z0-9_]*)=", cmd)
    if m:
        return "var", m.group(1)

    return None


def _is_read(write_type: str, resource: str, current: str) -> bool:
    """Does `current` reference the SAME resource created earlier?"""
    # FIX 1: strip sudo from current command too
    current = _strip_sudo(current)
    esc  = re.escape(resource)
    base = os.path.basename(resource.rstrip("/")) or resource

    if write_type == "file":
        # exact-token match, not substring — "/var/tmp/.x" must never match
        # resource "/tmp/.x" just because it ends with that text
        toks = current.split()
        if toks and toks[0] in ("cat", "ls", "chmod") and resource in toks[1:]:
            return True
        if current.startswith(f"./{base}"):
            return True
        # dd if=<resource> — same architecture-fingerprint loader reads the
        # file back via dd, not cat, most of the time.
        m = re.search(r"\bif=(\S+)", current)
        if m and m.group(1) == resource:
            return True
        # input redirection: `while read i; do ... ; done < resource`
        m = re.search(r"<(?!<)\s*(\S+)", current)
        if m and m.group(1) == resource:
            return True
        return False

    if write_type == "dir":
        toks = current.split()
        if toks and toks[0] == "cd" and len(toks) > 1 and toks[1] == resource:
            return True
        if toks and toks[0] == "ls" and resource in toks[1:]:
            return True
        return False

    if write_type == "pkg":
        first = current.split()[0] if current.split() else ""
        if first == resource:
            return True
        if re.match(rf"^which\s+{esc}$", current):
            return True
        return False

    if write_type == "user":
        # FIX 3: removed 'cat /etc/passwd' — that file exists on every system
        # regardless of whether this specific user was created, so it's a
        # false stateful pair. Only id/su prove the user was created.
        if re.match(rf"^id\s+{esc}$", current):
            return True
        if re.match(rf"^su\s+{esc}\b", current):
            return True
        return False

    if write_type == "svc":
        return bool(re.match(rf"^systemctl\s+status\s+{esc}$", current))

    if write_type == "var":
        return f"${resource}" in current

    return False


_BLOCK_OPEN  = {"while", "until", "for", "if", "case"}
_BLOCK_CLOSE = {"done", "fi", "esac"}


def _split_on_top_level_semicolons(cmd: str) -> list[str]:
    """Split on ';' but never inside single/double-quoted strings, and never
    inside a while/for/if/case ... done/fi/esac block — e.g.
    awk '{print $1;}' has a real ';' that's part of the quoted script, and
    'while read i ; do echo $i ; done < .s' has two real ';' that are
    internal to one compound command, not command separators. Splitting
    either would tear one valid command into invalid fragments."""
    parts = []
    buf = []
    word = []
    in_single = in_double = False
    depth = 0

    def flush_word():
        nonlocal depth
        w = "".join(word)
        word.clear()
        if w in _BLOCK_OPEN:
            depth += 1
        elif w in _BLOCK_CLOSE and depth > 0:
            depth -= 1

    for ch in cmd:
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch); word.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch); word.append(ch)
        elif ch == ";" and not in_single and not in_double:
            flush_word()
            if depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        elif ch.isspace() and not in_single and not in_double:
            flush_word()
            buf.append(ch)
        else:
            buf.append(ch); word.append(ch)
    flush_word()
    parts.append("".join(buf))
    return parts


def _expand_commands(cmds: list[str]) -> list[str]:
    """Split semicolon-chained commands into individual commands.
    Cowrie logs 'echo X > f; cat f; rm f' as one entry — split it first."""
    expanded = []
    for cmd in cmds:
        parts = [p.strip() for p in _split_on_top_level_semicolons(cmd) if p.strip()]
        expanded.extend(parts)
    return expanded


def _touches_network_fetch(cmd: str) -> bool:
    """True if wget/curl appears anywhere in the command. wget/curl are
    excluded from _match_write entirely, but they can still slip in on the
    READ side via another mechanism (e.g. 'apt-get install curl -y' -> pkg
    read 'curl <args>' where the args are a real download+pipe-to-bash).
    Any pair touching wget/curl on EITHER side is rejected here, regardless
    of which mechanism produced it — running it for ground truth would mean
    actually fetching a (often malicious) remote payload."""
    toks = cmd.split()
    return any(t in ("wget", "curl") for t in toks)


def find_stateful_pairs(commands: list[str]) -> list[tuple[str, str]]:
    """(setup_cmd, test_cmd) pairs found in this session, in command order."""
    cmds  = _expand_commands(commands)
    pairs = []
    for i, prior in enumerate(cmds):
        match = _match_write(prior)
        if not match:
            continue
        write_type, resource = match
        for current in cmds[i + 1:]:
            if _is_read(write_type, resource, current):
                if _touches_network_fetch(prior) or _touches_network_fetch(current):
                    continue
                pairs.append((prior, current))
    return pairs


def _extract_commands(events: list[dict]) -> list[str]:
    """Pull command strings out of a session's raw event list — same
    dual-eventid logic as workloads.load_cyberlab_sessions(), duplicated
    narrowly here because we need the raw `events` kept alongside, which
    that shared loader discards."""
    cmds = []
    for e in events:
        prefix = _COMMAND_EVENT_PREFIXES.get(e.get("eventid"))
        if prefix is None:
            continue
        msg = e.get("message", "")
        cmd = msg.split(prefix, 1)[-1].strip() if prefix in msg else msg.strip()
        if cmd:
            cmds.append(cmd)
    return cmds


def load_raw_sessions():
    """
    Scan every dataset/cyberlab_*.json file directly (not through
    workloads.load_cyberlab_sessions()) so the full, untouched raw event
    list for each session can be kept and later attached to the output —
    independently verifiable against the source file.
    Returns [{"session_id": <real id>, "source": <filename>,
              "full_entry": <raw events, verbatim>, "commands": [...]}, ...]
    """
    sessions = []
    for path in sorted(glob.glob(os.path.join(DATASET_DIR, "cyberlab_*.json"))):
        fname = os.path.basename(path)
        data  = json.load(open(path, encoding="utf-8"))
        for entry in data:
            for sid, events in entry.items():
                cmds = _extract_commands(events)
                if cmds:
                    sessions.append({
                        "session_id": sid,
                        "source":     fname,
                        "full_entry": events,
                        "commands":   cmds,
                    })
    return sessions


def main():
    scorer   = FIScorer()
    sessions = load_raw_sessions()
    print(f"[filter] {len(sessions)} cyberlab sessions with commands "
          f"(scanned {len(sorted(glob.glob(os.path.join(DATASET_DIR, 'cyberlab_*.json'))))} source files)")

    records = []
    for s in sessions:
        pairs = find_stateful_pairs(s["commands"])
        if not pairs:
            continue
        records.append({
            "session_id": s["session_id"],
            "source":     s["source"],
            "full_entry": s["full_entry"],
            "pairs": [
                {
                    "setup_cmd": setup_cmd,
                    "test_cmd":  test_cmd,
                    "fi_setup":  scorer.score(setup_cmd)[0],
                    "fi_test":   scorer.score(test_cmd)[0],
                }
                for setup_cmd, test_cmd in pairs
            ],
        })

    total_pairs = sum(len(r["pairs"]) for r in records)
    print(f"[filter] {len(records)}/{len(sessions)} sessions have >=1 stateful pair")
    print(f"[filter] {total_pairs} total stateful pairs extracted")

    os.makedirs(DATASET_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"[filter] wrote {OUTPUT_PATH}")

    for r in records:
        print(f"  [{r['session_id']}] ({r['source']}) {len(r['pairs'])} pair(s)")
        for p in r["pairs"]:
            print(f"      FI{p['fi_setup']}: {p['setup_cmd']!r}  ->  FI{p['fi_test']}: {p['test_cmd']!r}")


if __name__ == "__main__":
    main()