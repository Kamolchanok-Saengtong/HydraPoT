# import readline
# import json
# import os
# import re
# import time
# from datetime import datetime
# from router import classify
# from agent_manager.cowrie_agent import CowrieAgent
# from agent_manager.ondevice_agent import OnDeviceAgent
# from fi_manager import FILogManager

# # ─── Init ─────────────────────────────────────────────────────────────────────

# LOG_FILE   = "session_log.json"
# SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
# ondevice   = OnDeviceAgent()

# fi_manager = FILogManager(
#     impactful_path = "impactful_log.json",
#     max_events     = 10,
#     min_fi         = 2,
# )

# # ─── System State ─────────────────────────────────────────────────────────────

# SYSTEM_STATE = {
#     "versions":  {},    # tracks ANY tool version
#     "installed": [],
# }

# # ─── Logger ───────────────────────────────────────────────────────────────────

# def log(cmd: str, agent: str, response: str):
#     entry = {
#         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "cmd":       cmd,
#         "agent":     agent,
#         "response":  response,
#     }
#     existing = []
#     if os.path.exists(LOG_FILE):
#         try:
#             with open(LOG_FILE, "r") as f:
#                 existing = json.load(f)
#         except json.JSONDecodeError:
#             existing = []
#     existing.append(entry)
#     with open(LOG_FILE, "w") as f:
#         json.dump(existing, f, indent=2)

# # ─── Prompt Builder ───────────────────────────────────────────────────────────

# def build_simple_prompt(cmd: str, fi_manager: FILogManager) -> str:
#     history_text = fi_manager.build_terminal_history()
#     current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#     state_lines = []
#     for tool, ver in SYSTEM_STATE["versions"].items():
#         state_lines.append(f"{tool} --version output: {tool} version {ver}")
#     if SYSTEM_STATE["installed"]:
#         state_lines.append(f"installed packages: {', '.join(SYSTEM_STATE['installed'])}")
#     state_text = "\n".join(state_lines) if state_lines else "clean system"

#     return f"""You are a Linux terminal simulator. Reply with ONLY the terminal output for the LAST command below.
# Do NOT repeat previous responses. Do NOT execute previous commands again.
# Current date: {current_date}

# System state:
# {state_text}

# {history_text}
# ---
# NOW EXECUTE ONLY THIS COMMAND AND SHOW ITS OUTPUT:
# $ {cmd}"""

# # ─── System State Updater ─────────────────────────────────────────────────────

# def update_state(cmd: str, response: str):
#     # track installs — works for both 'apt install' and 'sudo apt install'
#     if re.search(r'(apt install|apt-get install)', cmd):
#         pkg = cmd.strip().split()[-1]
#         if pkg not in SYSTEM_STATE["installed"]:
#             SYSTEM_STATE["installed"].append(pkg)

#     # track versions
#     tool_match = re.match(r'^(\w+)\s+--version', cmd.strip())
#     if tool_match:
#         tool = tool_match.group(1)
#         ver_match = re.search(r'(\d+\.\d+[\.\d]*)', response)
#         if ver_match:
#             if tool not in SYSTEM_STATE["versions"]:
#                 SYSTEM_STATE["versions"][tool] = ver_match.group(1)  # lock first seen version
#         else:
#             if tool not in SYSTEM_STATE["versions"]:
#                 SYSTEM_STATE["versions"][tool] = "unknown"  # lock unknown too so it stays consistent

# # ─── Inject command into Cowrie history ───────────────────────────────────────

# def sync_history(cowrie: CowrieAgent, cmd: str):
#     try:
#         # write directly to history file without it appearing in history
#         safe_cmd = cmd.replace("'", "'\\''")
#         cowrie.shell.send(f"HISTFILE=~/.bash_history; history -s '{safe_cmd}'; history -w\n")
#         time.sleep(0.1)
#         if cowrie.shell.recv_ready():
#             cowrie.shell.recv(9999)
#     except Exception:
#         pass

# # ─── Main ─────────────────────────────────────────────────────────────────────

# def main():
#     session = []
#     cowrie  = CowrieAgent()
#     cowrie.connect()
#     prompt = "root@svr04:~#"

#     try:
#         while True:
#             try:
#                 cmd = input(f"{prompt} ").strip()
#             except (EOFError, KeyboardInterrupt):
#                 print("\nlogout")
#                 break

#             if not cmd: continue

#             if cmd == 'fi status':
#                 fi_manager.status()
#                 continue

#             if cmd == 'exit':
#                 print("logout")
#                 break

#             agent = classify(cmd, session)

#             # ── Cowrie ────────────────────────────────────────────────────────
#             if agent == 'cowrie':
#                 output, new_prompt = cowrie.send(cmd)
#                 if new_prompt == "CLEAR":
#                     print(f"{prompt} ", end="", flush=True)
#                 elif new_prompt:
#                     prompt = new_prompt
#                 update_state(cmd, output) 
#                 log(cmd, 'cowrie', output)
#                 session.append({"cmd": cmd, "agent": "cowrie", "response": output})

#             # ── On-Device LLM ─────────────────────────────────────────────────
#             elif agent == 'on_device':
#                 simple_prompt = build_simple_prompt(cmd, fi_manager)
#                 response = ondevice.send(simple_prompt)
#                 print(response)
#                 update_state(cmd, response)
#                 sync_history(cowrie, cmd)
#                 log(cmd, 'on_device', response)
#                 session.append({"cmd": cmd, "agent": "on_device", "response": response})

#             # ── Cloud LLM ─────────────────────────────────────────────────────
#             elif agent == 'cloud':
#                 simple_prompt = build_simple_prompt(cmd, fi_manager)
#                 response = "[cloud LLM coming soon]"
#                 print(response)
#                 sync_history(cowrie, cmd)
#                 log(cmd, 'cloud', response)
#                 session.append({"cmd": cmd, "agent": "cloud", "response": response})

#             # ── FI score every command ─────────────────────────────────────────
#             fi_manager.process(
#                 command    = cmd,
#                 output     = session[-1]["response"],
#                 agent      = agent,
#                 session_id = SESSION_ID,
#             )

#     finally:
#         cowrie.disconnect()
#         fi_manager.status()
#         print(f"[session] log saved → {LOG_FILE}")

# if __name__ == "__main__":
#     main()

import readline
import json
import os
import re
import time
from datetime import datetime
from router import classify
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from fi_manager import FILogManager
from prompt_manager import PromptManager                     # ← added

# ─── Init ─────────────────────────────────────────────────────────────────────

LOG_FILE   = "session_log.json"
SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
ondevice   = OnDeviceAgent()

fi_manager = FILogManager(
    impactful_path = "impactful_log.json",
    max_events     = 10,
    min_fi         = 2,
)

# ─── System State ─────────────────────────────────────────────────────────────

SYSTEM_STATE = {
    "versions":  {},
    "installed": [],
    "files": {
        "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
        "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
        "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
    },
}

prompt_manager = PromptManager(fi_manager, SYSTEM_STATE)     # ← added (after SYSTEM_STATE)

# ─── Logger ───────────────────────────────────────────────────────────────────

def log(cmd: str, agent: str, response: str):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cmd":       cmd,
        "agent":     agent,
        "response":  response,
    }
    existing = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                existing = json.load(f)
        except json.JSONDecodeError:
            existing = []
    existing.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(existing, f, indent=2)

# ─── System State Updater ─────────────────────────────────────────────────────

def update_state(cmd: str, response: str):
    if re.search(r'(apt install|apt-get install)', cmd):
        pkg = cmd.strip().split()[-1]
        if pkg not in SYSTEM_STATE["installed"]:
            SYSTEM_STATE["installed"].append(pkg)

    tool_match = re.match(r'^(\w+)\s+--version', cmd.strip())
    if tool_match:
        tool = tool_match.group(1)
        ver_match = re.search(r'(\d+\.\d+[\.\d]*)', response)
        if ver_match:
            if tool not in SYSTEM_STATE["versions"]:
                SYSTEM_STATE["versions"][tool] = ver_match.group(1)
        else:
            if tool not in SYSTEM_STATE["versions"]:
                SYSTEM_STATE["versions"][tool] = "unknown"

# ─── Inject command into Cowrie history ───────────────────────────────────────

def sync_history(cowrie: CowrieAgent, cmd: str):
    try:
        safe_cmd = cmd.replace("'", "'\\''")
        cowrie.shell.send(f"HISTFILE=~/.bash_history; history -s '{safe_cmd}'; history -w\n")
        time.sleep(0.1)
        if cowrie.shell.recv_ready():
            cowrie.shell.recv(9999)
    except Exception:
        pass

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    session = []
    cowrie  = CowrieAgent()
    cowrie.connect()
    prompt = "root@svr04:~#"

    try:
        while True:
            try:
                cmd = input(f"{prompt} ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nlogout")
                break

            if not cmd: continue

            if cmd == 'fi status':
                fi_manager.status()
                continue

            if cmd == 'exit':
                print("logout")
                break

            agent = classify(cmd, session)

            # ── Cowrie ────────────────────────────────────────────────────────
            if agent == 'cowrie':
                output, new_prompt = cowrie.send(cmd)
                if new_prompt == "CLEAR":
                    print(f"{prompt} ", end="", flush=True)
                elif new_prompt:
                    prompt = new_prompt
                update_state(cmd, output)
                log(cmd, 'cowrie', output)
                session.append({"cmd": cmd, "agent": "cowrie", "response": output})

            # ── On-Device LLM ─────────────────────────────────────────────────
            elif agent == 'on_device':
                sys_p, usr_p = prompt_manager.build_prompt(cmd)  # ← changed
                response = ondevice.send(sys_p, usr_p)           # ← changed
                print(response)
                update_state(cmd, response)
                sync_history(cowrie, cmd)
                log(cmd, 'on_device', response)
                session.append({"cmd": cmd, "agent": "on_device", "response": response})

            # ── Cloud LLM ─────────────────────────────────────────────────────
            elif agent == 'cloud':
                sys_p, usr_p = prompt_manager.build_prompt(cmd)  # ← changed (ready for later)
                response = "[cloud LLM coming soon]"
                print(response)
                sync_history(cowrie, cmd)
                log(cmd, 'cloud', response)
                session.append({"cmd": cmd, "agent": "cloud", "response": response})

            # ── FI score every command ─────────────────────────────────────────
            fi_manager.process(
                command    = cmd,
                output     = session[-1]["response"],
                agent      = agent,
                session_id = SESSION_ID,
            )

    finally:
        cowrie.disconnect()
        fi_manager.status()
        print(f"[session] log saved → {LOG_FILE}")

if __name__ == "__main__":
    main()