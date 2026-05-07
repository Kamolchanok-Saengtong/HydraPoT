"""main.py — HydraPoT honeypot orchestrator."""

import json
import os
import re
import time
from datetime import datetime

from config_loader import load_config
from router import classify
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from agent_manager.static_handler import is_static, dispatch_static
from prompt.fi_manager import FILogManager
from prompt.prompt_manager import PromptManager
from ssh_server import start_server


# populated by main()
config   = None
ondevice = None


# ─── Command handler ─────────────────────────────────────────────────────────
def make_command_handler(cowrie: CowrieAgent, src_ip: str = "?"):

    SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"[HydraPot] New session {SESSION_ID} from {src_ip}")

    os.makedirs(config.logging.session_dir,   exist_ok=True)
    os.makedirs(config.logging.impactful_dir, exist_ok=True)
    LOG_FILE       = f"{config.logging.session_dir}/{SESSION_ID}.json"
    impactful_file = f"{config.logging.impactful_dir}/{SESSION_ID}.json"

    fi_manager = FILogManager(
        impactful_path = impactful_file,
        max_events     = 10,
        min_fi         = config.logging.fi_threshold,
    )

    SYSTEM_STATE = {
        "versions":  {},
        "installed": [],
        "files":     config.system_state.get("starting_files", {}),
    }

    prompt_manager = PromptManager(fi_manager, SYSTEM_STATE)
    session        = []
    prompt_state   = {"current": f"root@{config.honeypot.hostname}:~#"}

    # ── log writer ────────────────────────────────────────────────────────
    def log(cmd, agent, response, fi_score=0, latency_ms=0.0):
        entry = {
            "session_id": SESSION_ID,
            "src_ip":     src_ip,
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

    # ── system state updater ──────────────────────────────────────────────
    def update_state(cmd, response):
        # apt install — record packages
        if re.search(r'\b(apt|apt-get)\s+install\b', cmd):
            parts = cmd.strip().split()
            try:
                i    = parts.index('install')
                pkgs = [p for p in parts[i+1:] if not p.startswith('-')]
            except ValueError:
                pkgs = []
            for pkg in pkgs:
                if pkg not in SYSTEM_STATE["installed"]:
                    SYSTEM_STATE["installed"].append(pkg)

        # apt remove / purge — drop packages
        if re.search(r'\b(apt|apt-get)\s+(remove|purge)\b', cmd):
            parts    = cmd.strip().split()
            verb_idx = next((i for i, p in enumerate(parts) if p in ("remove", "purge")), -1)
            pkgs     = [p for p in parts[verb_idx+1:] if not p.startswith('-')] if verb_idx >= 0 else []
            for pkg in pkgs:
                if pkg in SYSTEM_STATE["installed"]:
                    SYSTEM_STATE["installed"].remove(pkg)
                SYSTEM_STATE["versions"].pop(pkg, None)
                short = re.sub(r'[\d.]+$', '', pkg)
                SYSTEM_STATE["versions"].pop(short, None)

        # version queries — capture reported versions
        tool_match = re.match(r'^(?:sudo\s+)?([\w.\-]+)\s+(--version|-V)', cmd.strip())
        if tool_match and response:
            tool      = tool_match.group(1)
            ver_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', response)
            if ver_match:
                ver = ver_match.group(1)
                SYSTEM_STATE["versions"][tool] = ver
                short = re.sub(r'[\d.]+$', '', tool)
                if short and short != tool:
                    SYSTEM_STATE["versions"][short] = ver

    # ── cowrie history sync ───────────────────────────────────────────────
    def sync_history(cmd):
        try:
            safe_cmd = cmd.replace("'", "'\\''")
            cowrie.shell.send(
                f"HISTFILE=~/.bash_history; history -s '{safe_cmd}'; history -w\n"
            )
            time.sleep(0.1)
            if cowrie.shell.recv_ready():
                cowrie.shell.recv(9999)
        except Exception:
            pass

    SLOW        = ('wget', 'curl', 'masscan')
    INTERACTIVE = ('passwd', 'adduser', 'useradd', 'userdel')

    # ── main per-command dispatch ─────────────────────────────────────────
    def handle(cmd: str, write_fn, read_fn):
        if cmd.strip() == "fi status":
            fi_manager.status()
            return "", ""

        agent      = classify(cmd, session)
        t_start    = time.time()
        output     = ""
        streamed   = False
        cmd_base   = cmd.strip().split()[0] if cmd.strip() else ""

        if agent == "cowrie":
            if is_static(cmd):
                output   = dispatch_static(cmd, write_fn)
                streamed = True
            elif cmd_base in SLOW:
                output, _np = cowrie.send_streaming(cmd, write_fn)
                streamed = True
            elif cmd_base in INTERACTIVE:
                output, _np = cowrie.send_interactive(cmd, write_fn, read_fn)
                streamed = True
            else:
                output, _np = cowrie.send(cmd)
            update_state(cmd, output)

        elif agent == "on_device":
            if ondevice is None:
                output, _np = cowrie.send(cmd)
            else:
                sys_p, usr_p = prompt_manager.build_prompt(cmd)
                output = ondevice.send(sys_p, usr_p)
                sync_history(cmd)

        elif agent == "cloud":
            sys_p, usr_p = prompt_manager.build_prompt(cmd)
            output       = "[cloud LLM coming soon]"
            sync_history(cmd)

        latency_ms = (time.time() - t_start) * 1000
        fi_event   = fi_manager.process(
            command    = cmd,
            output     = output,
            agent      = agent,
            session_id = SESSION_ID,
        )
        session.append({"cmd": cmd, "agent": agent, "response": output})
        log(cmd, agent, output, (fi_event or {}).get("fi", 0), latency_ms)

        if streamed:
            return "", ""       # ← no new_prompt, ssh_server keeps its own
        return output, ""       # ← same: always return empty string for prompt
    return handle

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    global config, ondevice
    config = load_config()

    if config.agents.on_device.enabled:
        ondevice = OnDeviceAgent(
            model        = config.agents.on_device.model,
            quantization = config.agents.on_device.quantization,
            temperature  = config.agents.on_device.temperature,
            max_tokens   = config.agents.on_device.max_tokens,
            do_sample    = config.agents.on_device.do_sample,
        )
    else:
        ondevice = None

    cowrie = CowrieAgent(
        host     = config.agents.cowrie.host,
        port     = config.agents.cowrie.port,
        username = config.agents.cowrie.username,
        password = config.agents.cowrie.password,
    )
    cowrie._connect() 

    def handler_factory(src_ip: str = "?"):
        return make_command_handler(cowrie, src_ip=src_ip)

    try:
        start_server(
            handler_factory = handler_factory,
            host            = config.honeypot.host,
            port            = config.honeypot.port,
            hostname        = config.honeypot.hostname,   # ← must be here
            os_banner       = config.honeypot.os,         # ← must be here
        )
    except KeyboardInterrupt:
        print("\n[HydraPot] Shutting down...")
    finally:
        cowrie.disconnect()
        print("[HydraPot] Done.")


if __name__ == "__main__":
    main()