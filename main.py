import json
import os
import re
import time
from datetime import datetime
from router import classify
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from prompt.fi_manager import FILogManager
from prompt.prompt_manager import PromptManager
from ssh_server import start_server             
from agent_manager.static_handler import is_static, dispatch_static      

# ─── Init ─────────────────────────────────────────────────────────────────────

LOG_FILE   = "data/logs/session_log.json"
SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
ondevice   = OnDeviceAgent()

fi_manager = FILogManager(
    impactful_path = "data/logs/impactful_log.json",
    max_events     = 10,
    min_fi         = 2,
)

SYSTEM_STATE = {
    "versions":  {},
    "installed": [],
    "files": {
        "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
        "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
        "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
    },
}

prompt_manager = PromptManager(fi_manager, SYSTEM_STATE)

# ─── Logger ───────────────────────────────────────────────────────────────────

def log(cmd, agent, response, fi_score=0, latency_ms=0.0):
    entry = {
        "session_id": SESSION_ID,
        "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cmd":        cmd,
        "agent":      agent,
        "response":   response,
        "fi_score":   fi_score,
        "latency_ms": round(latency_ms, 2),
    }
    existing = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                existing = json.load(f)
        except json.JSONDecodeError:
            existing = []
    existing.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(existing, f, indent=2)

# ─── System State Updater ─────────────────────────────────────────────────────
# at the top of main.py
PACKAGE_VERSIONS = {
    "python3.9":  "3.9.18",
    "python3.10": "3.10.13",
    "python3.11": "3.11.7",
    "python3":    "3.10.13",
    "python":     "3.10.13",
    "nodejs":     "18.19.0",
    "node":       "18.19.0",
    "nginx":      "1.22.1",
    "apache2":    "2.4.57",
    "mysql":      "8.0.36",
    "redis":      "7.0.15",
    "git":        "2.39.2",
    "docker":     "24.0.7",
    "vim":        "9.0.1378",
    "gcc":        "12.2.0",
    "perl":       "5.36.0",
    "php":        "8.2.7",
    "curl":       "7.88.1",
    "wget":       "1.21.3",
    "openssl":    "3.0.11",
}

def update_state(cmd, response):
    # ── apt install ───────────────────────────────────────────────────────
    if re.search(r'\b(apt|apt-get)\s+install\b', cmd):
        parts = cmd.strip().split()
        try:
            i = parts.index('install')
            pkgs = [p for p in parts[i + 1:] if not p.startswith('-')]
        except ValueError:
            pkgs = []
        for pkg in pkgs:
            if pkg not in SYSTEM_STATE["installed"]:
                SYSTEM_STATE["installed"].append(pkg)

    # ── apt remove / purge ────────────────────────────────────────────────
    if re.search(r'\b(apt|apt-get)\s+(remove|purge)\b', cmd):
        parts = cmd.strip().split()
        verb_idx = next((i for i, p in enumerate(parts) if p in ("remove", "purge")), -1)
        pkgs = [p for p in parts[verb_idx + 1:] if not p.startswith('-')] if verb_idx >= 0 else []
        for pkg in pkgs:
            if pkg in SYSTEM_STATE["installed"]:
                SYSTEM_STATE["installed"].remove(pkg)
            SYSTEM_STATE["versions"].pop(pkg, None)
            short = re.sub(r'[\d.]+$', '', pkg)
            SYSTEM_STATE["versions"].pop(short, None)

    # ── version EXTRACTION from LLM response (only for on_device replies) ─
    # When LLM responds to "* --version", capture the version it generated
    # so future queries return the same answer.
    tool_match = re.match(r'^(?:sudo\s+)?([\w\.\-]+)\s+(--version|-V)', cmd.strip())
    if tool_match and response:
        tool = tool_match.group(1)
        # try to extract the first version-looking number from LLM response
        ver_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', response)
        if ver_match:
            ver = ver_match.group(1)
            SYSTEM_STATE["versions"][tool] = ver
            # also map short name (python3.9 → python)
            short = re.sub(r'[\d.]+$', '', tool)
            if short and short != tool:
                SYSTEM_STATE["versions"][short] = ver

    # ── apt remove ────────────────────────────────────────────────────────
    if re.search(r'(apt remove|apt-get remove|apt purge)', cmd):
        parts = cmd.strip().split()
        pkgs  = [p for p in parts[2:] if not p.startswith('-')]
        for pkg in pkgs:
            if pkg in SYSTEM_STATE["installed"]:
                SYSTEM_STATE["installed"].remove(pkg)
            SYSTEM_STATE["versions"].pop(pkg, None)
            short = re.sub(r'[\d.]+$', '', pkg)
            SYSTEM_STATE["versions"].pop(short, None)

# ─── Cowrie history sync ───────────────────────────────────────────────────────

def sync_history(cowrie, cmd):
    try:
        safe_cmd = cmd.replace("'", "'\\''")
        cowrie.shell.send(f"HISTFILE=~/.bash_history; history -s '{safe_cmd}'; history -w\n")
        time.sleep(0.1)
        if cowrie.shell.recv_ready():
            cowrie.shell.recv(9999)
    except Exception:
        pass

# ─── Command handler (called by SSH server for every command) ─────────────────
def make_command_handler(cowrie: CowrieAgent, session: list):
    """
    handle(cmd, write_fn, read_fn) -> (response, new_prompt)
    Routes cmd to the right cowrie/static/ondevice path based on type.
    """
    SLOW        = ('wget', 'curl', 'masscan')
    INTERACTIVE = ('passwd', 'adduser', 'useradd', 'userdel')

    prompt_state = {"current": "root@svr04:~#"}

    def handle(cmd: str, write_fn, read_fn):
        if cmd == "fi status":
            fi_manager.status()
            return "", prompt_state["current"]

        agent      = classify(cmd, session)
        t_start    = time.time()
        output     = ""           # for logging
        streamed   = False        # already pushed to attacker via write_fn?
        new_prompt = ""
        cmd_base   = cmd.strip().split()[0] if cmd.strip() else ""

        if agent == "cowrie":
            from agent_manager.static_handler import is_static, dispatch_static

            if is_static(cmd):
                output   = dispatch_static(cmd, write_fn)
                streamed = True
            elif cmd_base in SLOW:
                output, np = cowrie.send_streaming(cmd, write_fn)
                streamed = True
                if np and np != "CLEAR":
                    prompt_state["current"] = np
                    new_prompt = np
            elif cmd_base in INTERACTIVE:
                output, np = cowrie.send_interactive(cmd, write_fn, read_fn)
                streamed = True
                if np and np != "CLEAR":
                    prompt_state["current"] = np
                    new_prompt = np
            else:
                output, np = cowrie.send(cmd)
                if np and np != "CLEAR":
                    prompt_state["current"] = np
                    new_prompt = np
            update_state(cmd, output)

        elif agent == "on_device":
            sys_p, usr_p = prompt_manager.build_prompt(cmd)
            output = ondevice.send(sys_p, usr_p)
            update_state(cmd, output)
            sync_history(cowrie, cmd)

        elif agent == "cloud":
            sys_p, usr_p = prompt_manager.build_prompt(cmd)
            output = "[cloud LLM coming soon]"
            sync_history(cowrie, cmd)

        latency_ms = (time.time() - t_start) * 1000
        fi_event = fi_manager.process(
            command    = cmd,
            output     = output,
            agent      = agent,
            session_id = SESSION_ID,
        )
        session.append({"cmd": cmd, "agent": agent, "response": output})
        log(cmd, agent, output, fi_event["fi"], latency_ms)

        # if the agent already streamed to the attacker, return empty so
        # ssh_server doesn't write it again.
        if streamed:
            return "", new_prompt
        return output, new_prompt
    return handle     
# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    session = []
    cowrie  = CowrieAgent()
    cowrie.connect()

    handler = make_command_handler(cowrie, session)

    try:
        # Blocks here — SSH server runs until Ctrl+C
        start_server(command_handler=handler, host="127.0.0.1", port=2223)
    except KeyboardInterrupt:
        print("\n[HydraPot] Shutting down...")
    finally:
        cowrie.disconnect()
        fi_manager.status()
        print(f"[session] log saved → {LOG_FILE}")

if __name__ == "__main__":
    main()