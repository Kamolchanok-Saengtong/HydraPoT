import sys
import os
import json
import time
import getpass
import re
import paramiko
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fi_manager import FIScorer, FI_LABELS

# ─── Config ───────────────────────────────────────────────────────────────────
BASE_OUTPUT_DIR = "/mnt/data-partition/honeypot/evaluation/interaction_mode"
os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)

COWRIE_HOST   = "127.0.0.1"
COWRIE_PORT   = 2222
CMD_DELAY     = 0.5
RECV_TIMEOUT  = 8.0
CYBERLAB_FILE = "/mnt/data-partition/honeypot/cyberlab_2019-05-13.json"
BATCH_SIZE    = 50
MAX_SESSIONS  = 10

SKIP_CMDS = {
    'ping', 'traceroute', 'top', 'watch',
    'adduser', 'useradd', 'passwd', 'userdel',
    'vim', 'vi', 'nano', 'less', 'more',
    'ssh', 'telnet', 'ftp',
}

SLOW_CMDS = {'wget', 'curl', 'apt', 'apt-get', 'pip', 'pip3', 'git', 'tar', 'unzip'}

# ─── Load CyberLab Dataset ────────────────────────────────────────────────────
def load_interaction_commands(max_sessions: int = MAX_SESSIONS) -> list:
    if not os.path.exists(CYBERLAB_FILE):
        print(f"[!] CyberLab file not found: {CYBERLAB_FILE}")
        return []

    with open(CYBERLAB_FILE) as f:
        data = json.load(f)

    session_commands = []

    for session in data:
        for sid, events in session.items():
            has_command = any(
                e.get("eventid") == "cowrie.command.success"
                for e in events
            )
            if not has_command:
                continue

            commands = []
            for i, event in enumerate(events):
                if event.get("eventid") != "cowrie.command.success":
                    continue

                message = event.get("message", "")
                cmd = (
                    message.split("Command found:")[-1].strip()
                    if "Command found:" in message
                    else message.strip()
                )
                if not cmd:
                    continue

                commands.append({"cmd": cmd})  

            if commands:
                session_commands.append({"session_id": sid, "commands": commands})

            if len(session_commands) >= max_sessions:
                return session_commands

    return session_commands


# ─── SSH Connect ──────────────────────────────────────────────────────────────
def connect(username: str, password: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=COWRIE_HOST, port=COWRIE_PORT,
        username=username, password=password,
        timeout=10,
    )
    shell = client.invoke_shell(width=220, height=50)
    time.sleep(0.8)
    if shell.recv_ready():
        shell.recv(65535)
    print(f"[✓] Connected to Cowrie at {COWRIE_HOST}:{COWRIE_PORT}\n")
    return client, shell


# ─── Send & Receive ───────────────────────────────────────────────────────────
def send(shell: paramiko.Channel, cmd: str) -> str:
    cmd_base = cmd.strip().split()[0] if cmd.strip() else ""
    is_slow = cmd_base in SLOW_CMDS or any(s in cmd for s in ['wget', 'curl', 'http'])
    timeout = 25.0 if is_slow else RECV_TIMEOUT

    shell.send(cmd + "\n")
    full_output = ""
    last_recv   = time.time()

    while True:
        if shell.recv_ready():
            chunk = shell.recv(8192).decode(errors="ignore")
            full_output += chunk
            last_recv = time.time()
        elif time.time() - last_recv > timeout:
            break
        else:
            time.sleep(0.05)

    print(f"[RAW] {repr(full_output[:300])}")  # ← add this temporarily
    return clean_output(full_output, cmd)


# ─── Output Cleaner ───────────────────────────────────────────────────────────
def collapse_cr_lines(text: str) -> str:
    result = []
    for segment in text.split('\n'):
        if '\r' in segment:
            # keep last non-empty \r-overwritten state
            parts = [p.strip() for p in segment.split('\r') if p.strip()]
            if parts:
                result.append(parts[-1])
        else:
            if segment.strip():
                result.append(segment)
    return '\n'.join(result)


def clean_output(raw: str, cmd: str) -> str:
    raw = re.sub(r'\x1b\[[0-9;]*[mGKHFJA-Z]', '', raw)
    raw = re.sub(r'\x1b\([A-Z]', '', raw)
    raw = collapse_cr_lines(raw)

    lines = raw.split('\n')
    lines = [l for l in lines if l.strip()]

    if lines and cmd.strip() in lines[0]:
        lines = lines[1:]
    if lines and re.search(r'[$#>]\s*$', lines[-1]):
        lines = lines[:-1]

    return '\n'.join(lines).strip()


# ─── Save Helper ──────────────────────────────────────────────────────────────
def save_json(path: str, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[✓] Saved → {path}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def run():
    scorer   = FIScorer()
    sessions = load_interaction_commands()

    if not sessions:
        print("[!] No sessions found — check CYBERLAB_FILE path")
        return

    print(f"[INFO] Loaded {len(sessions)} sessions")

    username = input("Cowrie username: ")
    password = getpass.getpass("Cowrie password: ")
    client, shell = connect(username, password)

    run_id      = datetime.now().strftime("%Y%m%d_%H%M%S")
    all_results = []

    def reconnect():
        nonlocal client, shell
        print("[~] Reconnecting to Cowrie...")
        try:
            client.close()
        except Exception:
            pass
        time.sleep(1.0)
        client, shell = connect(username, password)
        print("[✓] Reconnected\n")

    try:
        for s_idx, session in enumerate(sessions, start=1):
            session_id = session["session_id"]
            commands   = session["commands"]
            print(f"\n{'═'*60}")
            print(f"  Session {s_idx}/{len(sessions)} → {session_id}  ({len(commands)} commands)")
            print(f"{'═'*60}\n")

            session_dir = os.path.join(BASE_OUTPUT_DIR, f"{run_id}_{session_id}")
            os.makedirs(session_dir, exist_ok=True)

            session_results = []
            skipped = 0
            batches = [
                commands[i:i + BATCH_SIZE]
                for i in range(0, len(commands), BATCH_SIZE)
            ]

            for batch_idx, batch in enumerate(batches, start=1):
                print(f"\n--- Batch {batch_idx}/{len(batches)} ({len(batch)} commands) ---")
                batch_results = []

                for local_i, entry in enumerate(batch):
                    global_i = (batch_idx - 1) * BATCH_SIZE + local_i + 1
                    cmd      = entry["cmd"]
                    cmd_base = cmd.strip().split()[0] if cmd.strip() else ""
                    fi, _    = scorer.score(cmd)

                    if cmd_base in SKIP_CMDS:
                        skipped += 1
                        batch_results.append({
                            "index":         global_i,
                            "session_id":    session_id,
                            "cmd":           cmd,
                            "cowrie_output": "SKIPPED",
                            "latency_ms":    None,
                            "fi":            fi,
                            "fi_label":      FI_LABELS[fi],
                            "skipped":       True,
                        })
                        print(f"  [{global_i:>3}] SKIP  {cmd}")
                        continue

                    print(f"  [{global_i:>3}] >> {cmd}")
                    try:
                        t0     = time.perf_counter()
                        output = send(shell, cmd)
                        lat    = round((time.perf_counter() - t0) * 1000, 2)
                    except OSError:
                        print(f"  [!] Socket closed after '{cmd}' — reconnecting...")
                        reconnect()
                        output = "CONNECTION_RESET"
                        lat    = None

                    print(f"         << {repr(output[:120])}{'...' if len(output) > 120 else ''}")
                    if lat:
                        print(f"         latency={lat}ms")

                    batch_results.append({
                        "index":         global_i,
                        "session_id":    session_id,
                        "cmd":           cmd,
                        "cowrie_output": output,
                        "latency_ms":    lat,
                        "fi":            fi,
                        "fi_label":      FI_LABELS[fi],
                        "skipped":       False,
                    })
                    time.sleep(CMD_DELAY)

                session_results.extend(batch_results)

                batch_file = os.path.join(session_dir, f"batch_{batch_idx}.json")
                save_json(batch_file, batch_results)

            all_results.extend(session_results)

            evaluated = len(session_results) - skipped
            avg_lat   = (
                sum(r["latency_ms"] for r in session_results if r["latency_ms"]) / evaluated
                if evaluated else 0
            )
            fi_counts = {fi: sum(1 for r in session_results if r.get("fi") == fi) for fi in range(5)}

            print(f"\n{'═'*50}")
            print(f"  SESSION {s_idx} SUMMARY → {session_id}")
            print(f"{'═'*50}")
            print(f"  Total    : {len(session_results)}")
            print(f"  Evaluated: {evaluated}  |  Skipped: {skipped}")
            print(f"  Avg lat  : {avg_lat:.1f} ms")
            print("  FI breakdown:")
            for fi in range(5):
                print(f"    FI {fi} ({FI_LABELS[fi]}): {fi_counts[fi]}")

            session_file = os.path.join(session_dir, "session_results.json")
            save_json(session_file, session_results)

    except KeyboardInterrupt:
        print("\n[!] Interrupted — saving progress...")

    finally:
        client.close()

        if all_results:
            out_file = os.path.join(BASE_OUTPUT_DIR, f"eval_cowrie_interaction_{run_id}.json")
            save_json(out_file, all_results)

        total     = len(all_results)
        evaluated = sum(1 for r in all_results if not r.get("skipped"))
        skipped   = total - evaluated
        avg_lat   = (
            sum(r["latency_ms"] for r in all_results if r.get("latency_ms")) / evaluated
            if evaluated else 0
        )
        fi_counts = {fi: sum(1 for r in all_results if r.get("fi") == fi) for fi in range(5)}

        print(f"\n{'═'*50}")
        print("  OVERALL EVAL SUMMARY")
        print(f"{'═'*50}")
        print(f"  Sessions   : {len(sessions)}")
        print(f"  Total cmds : {total}")
        print(f"  Evaluated  : {evaluated}  |  Skipped: {skipped}")
        print(f"  Avg latency: {avg_lat:.1f} ms")
        print("  FI breakdown:")
        for fi in range(5):
            print(f"    FI {fi} ({FI_LABELS[fi]}): {fi_counts[fi]}")
        print(f"{'═'*50}\n")


if __name__ == "__main__":
    run()