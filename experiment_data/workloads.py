"""
experiment_data/workloads.py
─────────────────────────────────────────────────────────────────
Workload loaders for the NSC evaluation. Single source of truth for
"what commands do we run", so every part of the eval draws from the
same place and nothing is hardcoded inline.

Part A (architecture overhead):
    load_mrheinen()  -> flat list of single commands
    load_ml4net()    -> flat list from real attacker sessions
    load_mixed()     -> proportional mix of mrheinen+ML4Net+cyberlab
    stratify_by_fi() -> bucket by FI band

Part C (cost-effectiveness, later):
    load_cyberlab_sessions() -> ordered per-session command lists
─────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import random

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from prompt.fi_manager import FIScorer


# ─── Paths ────────────────────────────────────────────────────────────────────

CYBERLAB_FILE = os.environ.get(
    "NSC_CYBERLAB_FILE",
    os.path.join(_ROOT, "dataset", "cyberlab_2019-05-13.json"),
)
MRHEINEN_FILE = os.environ.get(
    "NSC_MRHEINEN_FILE",
    os.path.join(_ROOT, "dataset", "mrheinen_linux_commands.json"),
)
OBFUSCATED_FILE = os.environ.get(
    "NSC_OBFUSCATED_FILE",
    os.path.join(_ROOT, "dataset", "obfuscated_commands.json"),
)
ML4NET_FILE = os.environ.get(
    "NSC_ML4NET_FILE",
    os.path.join(_ROOT, "dataset", "ml4net_full.json"),
)


# ─── Loaders ──────────────────────────────────────────────────────────────────

def load_mrheinen(path: str = MRHEINEN_FILE) -> list[str]:
    """
    Load the mrheinen/linux-commands set as a flat list of command strings.
    Accepts JSON list of strings, list of objects with a "command"/"cmd"
    field, or JSONL. Deduplicates while preserving order.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"mrheinen workload not found at {path}. "
            f"Export it once from HuggingFace or set NSC_MRHEINEN_FILE."
        )
    text = open(path, encoding="utf-8").read().strip()
    try:
        records = json.loads(text)
    except json.JSONDecodeError:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]

    commands: list[str] = []
    for r in records:
        if isinstance(r, str):
            raw = r
        elif isinstance(r, dict):
            raw = r.get("command") or r.get("cmd") or r.get("input") or ""
        else:
            raw = ""
        for part in raw.split(";"):
            cmd = part.strip()
            if cmd:
                commands.append(cmd)

    seen = set()
    unique = []
    for c in commands:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def load_mrheinen_raw(path: str = MRHEINEN_FILE) -> list[str]:
    """
    Load the mrheinen/linux-commands set as the raw, un-split, un-deduped
    "input" field of every record — exactly as it sits on disk (481 rows).
    Unlike load_mrheinen(), this does NOT split on ";" or dedupe: a row like
    "arp -an; tempfile --directory=/var/tmp --prefix=myapp_" is kept as ONE
    command line, same as a real terminal would receive it. Use this for
    full-coverage runs (Part A) where every dataset row should be measured
    once, as written. load_mrheinen() stays split+deduped for the sampling
    pool consumers (stratify_by_fi/balanced_sample, load_mixed()).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"mrheinen workload not found at {path}. "
            f"Export it once from HuggingFace or set NSC_MRHEINEN_FILE."
        )
    records = json.loads(open(path, encoding="utf-8").read())
    commands = []
    for r in records:
        raw = r if isinstance(r, str) else r.get("input") or r.get("command") or r.get("cmd") or ""
        raw = raw.strip()
        if raw:
            commands.append(raw)
    return commands


def load_mrheinen_instruction(path: str = MRHEINEN_FILE) -> str:
    """
    Returns the mrheinen dataset's own "instruction" field — the generic
    "you are a computer terminal" prompt the dataset author used, identical
    across every record. This is the vanilla, non-HydraPoT prompt for the
    pure on_device/cloud arms in Part A (source of truth is the dataset
    itself, not a prompt we write ourselves).
    """
    records = json.loads(open(path, encoding="utf-8").read())
    for r in records:
        if isinstance(r, dict) and r.get("instruction"):
            return r["instruction"].strip()
    return ""


def load_obfuscated(path: str = OBFUSCATED_FILE) -> list[str]:
    """
    Load the obfuscated benchmark commands (built by build_obfuscated_benchmark.py).
    All commands trip _is_cloud() so they exercise the cloud route in Part A.
    Returns [] if file doesn't exist.
    """
    if not os.path.exists(path):
        print(f"[workloads] no obfuscated set at {path}; skipping")
        return []
    records = json.load(open(path, encoding="utf-8"))
    cmds = []
    for r in records:
        c = (r.get("command") if isinstance(r, dict) else r) or ""
        c = c.strip()
        if c:
            cmds.append(c)
    return cmds


def load_ml4net(
    max_sessions: int = 10000,
    path: str = ML4NET_FILE,
) -> list[str]:
    """
    Load commands from ml4net_full.json (233k real attacker sessions).
    Splits each session's semicolon-joined command string into individual
    commands, deduplicates, and returns a flat list.
    max_sessions caps how many sessions to read (default 10000).
    """
    if not os.path.exists(path):
        print(f"[workloads] ML4Net not found at {path}; skipping")
        return []
    data = json.load(open(path, encoding="utf-8"))
    cmds = []
    for entry in data[:max_sessions]:
        raw = entry.get("commands", "")
        for part in raw.split(";"):
            c = part.strip()
            if c:
                cmds.append(c)
    seen = set()
    unique = []
    for c in cmds:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def load_mixed(
    total: int = 3000,
    seed: int = 42,
    ml4net_sessions: int = 10000,
) -> tuple[list[str], dict[str, int]]:
    """
    Returns (commands, breakdown) where:
      - commands is a flat shuffled list of `total` commands sampled
        proportionally from mrheinen + ML4Net + cyberlab
      - breakdown is {"mrheinen": N, "ml4net": N, "cyberlab": N}
        showing exactly how many came from each source

    Proportions are derived from each dataset's actual pool size so the
    mix reflects real-world attacker command frequency.
    The caller (run_partX.py) controls total, seed, ml4net_sessions —
    this function only loads and samples, never decides what to measure.
    """
    random.seed(seed)

    sources: dict[str, list[str]] = {}
    if os.path.exists(MRHEINEN_FILE):
        sources["mrheinen"] = load_mrheinen()
    if os.path.exists(ML4NET_FILE):
        sources["ml4net"]   = load_ml4net(max_sessions=ml4net_sessions)
    if os.path.exists(CYBERLAB_FILE):
        sessions            = load_cyberlab_sessions()
        sources["cyberlab"] = [c for s in sessions for c in s["commands"]]

    if not sources:
        raise FileNotFoundError("No datasets found for load_mixed()")

    # proportional allocation based on pool size
    pool_sizes  = {k: len(v) for k, v in sources.items()}
    total_pool  = sum(pool_sizes.values())
    allocations = {
        k: max(1, round(total * n / total_pool))
        for k, n in pool_sizes.items()
    }
    # fix rounding drift so we hit exactly `total`
    diff = total - sum(allocations.values())
    largest = max(allocations, key=allocations.get)
    allocations[largest] += diff

    mixed = []
    breakdown: dict[str, int] = {}
    for src, n in allocations.items():
        pool   = sources[src]
        sample = random.sample(pool, min(n, len(pool)))
        mixed.extend(sample)
        breakdown[src] = len(sample)

    # global dedup
    seen: set[str] = set()
    unique = []
    for c in mixed:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    # adjust breakdown if dedup reduced count
    breakdown["_total_after_dedup"] = len(unique)

    random.shuffle(unique)
    return unique, breakdown


# ─── FI helpers ───────────────────────────────────────────────────────────────

def stratify_by_fi(commands: list[str]) -> dict[int, list[str]]:
    """
    Bucket commands by FI band (0-4) using the project's own FIScorer.
    Returns {0: [...], 1: [...], ..., 4: [...]}.
    """
    scorer = FIScorer()
    buckets: dict[int, list[str]] = {fi: [] for fi in range(5)}
    for cmd in commands:
        fi, _ = scorer.score(cmd)
        buckets.setdefault(fi, []).append(cmd)
    return buckets


def balanced_sample(buckets: dict[int, list[str]], per_band: int) -> list[tuple[int, str]]:
    """
    Take up to `per_band` commands from each FI band, returning (fi, cmd) pairs.
    Deterministic (first N of each band) for reproducibility.
    """
    out: list[tuple[int, str]] = []
    for fi in range(5):
        for cmd in buckets.get(fi, [])[:per_band]:
            out.append((fi, cmd))
    return out


# ─── Part C: cyberlab session loader ──────────────────────────────────────────

# Cowrie logs a typed command under different eventids/message prefixes
# depending on version/config — both are standard Cowrie events for
# "a command ran in this session", not dataset-specific quirks:
#   cowrie.command.success -> "Command found: <cmd>"  (e.g. cyberlab_2019-05-13)
#   cowrie.command.input   -> "CMD: <cmd>"             (e.g. cyberlab_2019-08-05)
_COMMAND_EVENT_PREFIXES = {
    "cowrie.command.success": "Command found:",
    "cowrie.command.input":   "CMD:",
}


def load_cyberlab_sessions(max_sessions: int | None = None) -> list[dict]:
    """
    Parse cyberlab into ordered per-session command lists.
    Returns [{"session_id": sid, "commands": [cmd, ...]}, ...].
    """
    if not os.path.exists(CYBERLAB_FILE):
        raise FileNotFoundError(f"cyberlab file not found: {CYBERLAB_FILE}")

    data = json.load(open(CYBERLAB_FILE))
    sessions: list[dict] = []

    for entry in data:
        for sid, events in entry.items():
            cmds = []
            for e in events:
                prefix = _COMMAND_EVENT_PREFIXES.get(e.get("eventid"))
                if prefix is None:
                    continue
                msg = e.get("message", "")
                cmd = (msg.split(prefix, 1)[-1].strip()
                       if prefix in msg else msg.strip())
                if cmd:
                    cmds.append(cmd)
            if cmds:
                sessions.append({"session_id": sid, "commands": cmds})
            if max_sessions is not None and len(sessions) >= max_sessions:
                return sessions
    return sessions