"""main.py — HydraPoT honeypot orchestrator."""

import json
import os
import re
import time
from datetime import datetime

from config_loader import load_config
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from agent_manager.static_handler import is_static, dispatch_static
from prompt.fi_manager import FILogManager
from prompt.prompt_manager import PromptManager
from ssh_server import start_server
from router import _is_cloud

config   = None
ondevice = None


def make_command_handler(cowrie: CowrieAgent, src_ip: str = "?"):

    TOOL_TO_PACKAGE = {
        "nmap": "nmap", "masscan": "masscan", "ncat": "nmap",
        "netcat": "netcat-openbsd", "nc": "netcat-openbsd",
        "tcpdump": "tcpdump", "socat": "socat", "whois": "whois",
        "python": "python3", "python3": "python3", "python2": "python2",
        "perl": "perl", "ruby": "ruby", "php": "php",
        "node": "nodejs", "lua": "lua5.3",
        "gcc": "gcc", "g++": "g++", "make": "make",
        "gdb": "gdb", "git": "git", "strace": "strace",
        "nginx": "nginx", "apache2": "apache2",
        "mysql": "mysql-server", "mysqldump": "mysql-client",
        "redis-cli": "redis-tools", "docker": "docker.io",
        "vim": "vim", "nano": "nano", "emacs": "emacs",
        "wget": "wget", "curl": "curl",
        "htop": "htop", "screen": "screen", "tmux": "tmux",
        "zip": "zip", "unzip": "unzip", "7z": "p7zip-full",
        "jq": "jq", "tree": "tree",
    }

    BUILTIN_TOOLS = {
        "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "touch",
        "echo", "pwd", "cd", "head", "tail", "less", "more",
        "grep", "sed", "awk", "cut", "tr", "sort", "uniq", "wc",
        "find", "xargs", "tee", "dd", "tar", "gzip", "gunzip",
        "chmod", "chown", "chgrp", "umask",
        "ps", "top", "kill", "bg", "fg", "jobs", "nice",
        "whoami", "id", "who", "w", "last", "groups", "finger",
        "uname", "hostname", "date", "uptime", "free", "df", "du",
        "netstat", "ss", "ip", "ifconfig", "arp", "ping", "traceroute",
        "mount", "umount", "fdisk", "lsblk",
        "apt", "apt-get", "dpkg", "sudo", "su",
        "passwd", "adduser", "useradd", "userdel", "usermod",
        "crontab", "at", "bash", "sh", "ssh", "scp", "sftp",
        "env", "export", "alias", "history", "source",
        "clear", "exit", "logout",
        "dig", "nslookup", "host",
        "systemctl", "service", "journalctl",
    }

    EDITORS      = {"vim", "vi", "nano", "emacs"}
    SLOW         = ("wget", "curl", "masscan", "apt", "apt-get")
    INTERACTIVE  = ("passwd", "adduser", "useradd", "userdel")

    DEFAULT_VERSIONS = {
        "nmap":      "Nmap version 7.80 ( https://nmap.org )",
        "python3":   "Python 3.10.12",
        "python":    "Python 3.10.12",
        "git":       "git version 2.34.1",
        "vim":       "VIM - Vi IMproved 8.2 (2019 Dec 12)",
        "gcc":       "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
        "g++":       "g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
        "curl":      "curl 7.81.0 (x86_64-pc-linux-gnu)",
        "wget":      "GNU Wget 1.21.2 built on linux-gnu.",
        "perl":      "This is perl 5, version 34, subversion 0 (v5.34.0)",
        "ruby":      "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233)",
        "php":       "PHP 8.1.2-1ubuntu2.14 (cli)",
        "node":      "v18.19.0",
        "make":      "GNU Make 4.3",
        "docker":    "Docker version 24.0.7, build afdd53b",
        "nginx":     "nginx version: nginx/1.18.0 (Ubuntu)",
        "htop":      "htop 3.2.1",
        "tmux":      "tmux 3.2a",
        "screen":    "Screen version 4.09.00 (GNU) 01-Sep-21",
        "nano":      "GNU nano, version 6.2",
        "emacs":     "GNU Emacs 27.1",
        "mysql":     "mysql  Ver 8.0.36-0ubuntu0.22.04.1 for Linux on x86_64",
        "strace":    "strace -- version 5.16",
        "gdb":       "GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1",
        "systemctl": "systemd 249 (249.11-0ubuntu3.12)",
    }

    SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"[HydraPot] New session {SESSION_ID} from {src_ip}")

    os.makedirs(config.logging.session_dir,   exist_ok=True)
    os.makedirs(config.logging.impactful_dir, exist_ok=True)
    LOG_FILE       = f"{config.logging.session_dir}/{SESSION_ID}.json"
    impactful_file = f"{config.logging.impactful_dir}/{SESSION_ID}.json"

    fi_manager = FILogManager(
        impactful_path=impactful_file,
        max_events=10,
        min_fi=config.logging.fi_threshold,
    )

    SYSTEM_STATE = {
        "versions":  {},
        "installed": list(config.system_state.get("pre_installed", [])),
        "files":     config.system_state.get("starting_files", {}),
    }

    prompt_manager = PromptManager(
        fi_manager,
        SYSTEM_STATE,
        hostname=config.honeypot.hostname,
        os_name=config.honeypot.os,
    )
    session = []

    # ── helpers ───────────────────────────────────────────────────────────

    def _is_tool_available(cmd_base: str) -> bool:
        if cmd_base in BUILTIN_TOOLS:
            return True
        pkg = TOOL_TO_PACKAGE.get(cmd_base)
        if pkg and pkg in SYSTEM_STATE["installed"]:
            return True
        if cmd_base in SYSTEM_STATE["installed"]:
            return True
        pre = config.system_state.get("pre_installed", [])
        if cmd_base in pre:
            return True
        if pkg and pkg in pre:
            return True
        return False

    def _handle_version_query(cmd: str, cmd_base: str) -> str:
        if cmd_base in SYSTEM_STATE["versions"]:
            return SYSTEM_STATE["versions"][cmd_base]
        ver = DEFAULT_VERSIONS.get(cmd_base, f"{cmd_base} version 1.0.0")
        SYSTEM_STATE["versions"][cmd_base] = ver
        return ver

    def _handle_systemctl(cmd: str) -> str:
        parts = cmd.strip().split()
        if len(parts) < 3:
            return "Usage: systemctl [OPTIONS...] COMMAND ..."
        # systemctl <action> <service>  vs  service <service> <action>
        if parts[0] == "service":
            service, action = parts[1], parts[2]
        else:
            action, service = parts[1], parts[2]
        if action == "status":
            return (
                f"● {service}.service - {service.upper()} Service\n"
                f"     Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\n"
                f"     Active: active (running) since Mon 2026-05-05 03:22:11 UTC; 3 days ago\n"
                f"   Main PID: {1000 + hash(service) % 9000} ({service})\n"
                f"      Tasks: {2 + hash(service) % 8}\n"
                f"     Memory: {4 + hash(service) % 60}.{hash(service) % 10}M\n"
                f"        CPU: {hash(service) % 500}ms\n"
                f"     CGroup: /system.slice/{service}.service"
            )
        elif action in ("restart", "start", "stop", "reload"):
            return ""
        elif action == "enable":
            return f"Created symlink /etc/systemd/system/multi-user.target.wants/{service}.service"
        elif action == "disable":
            return f"Removed /etc/systemd/system/multi-user.target.wants/{service}.service"
        return f"systemctl: unknown command '{action}'"

    def _needs_llm(cmd: str, cmd_base: str, state: dict) -> bool:
        files = state.get("files", {})
        if re.search(r'--version\b|-V\b', cmd):
            return _is_tool_available(cmd_base)
        if cmd_base in ("systemctl", "service", "journalctl"):
            return True
        if cmd_base in ("bash", "sh", "python", "python3", "perl", "node", "ruby", "php", "lua"):
            parts = cmd.strip().split()
            if len(parts) > 1 and parts[1] in files and files[parts[1]].get("content"):
                return True
        if cmd.strip().startswith("./"):
            script = cmd.strip()[2:].split()[0]
            if script in files:          # any tracked file, even downloaded ones
                return True
        if cmd_base == "cat":
            for p in cmd.strip().split()[1:]:
                if not p.startswith("-") and p in files and files[p].get("content"):
                    return True
        if cmd_base == "sed":
            # use last token as filename — same as update_state
            parts = cmd.strip().split()
            filename = parts[-1] if len(parts) > 1 else ""
            if filename in files:
                return True
        if cmd_base == "hostname":
            return True
        if cmd_base in ("gcc", "g++", "make", "gdb", "strace", "ltrace"):
            return True
        return False

    def _execute_tracked_script(cmd: str, write_fn):
        parts = cmd.strip().split()
        if cmd.strip().startswith("./"):
            script = cmd.strip()[2:].split()[0]
        elif parts[0] in ("bash", "sh") and len(parts) > 1:
            script = parts[1]
        else:
            return None
        file_info = SYSTEM_STATE["files"].get(script, {})
        content   = file_info.get("content", "")
        if not content or content.startswith("[downloaded from"):
            return None
        combined = ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line_base = line.split()[0]
            if is_static(line):
                combined += dispatch_static(line, write_fn) + "\n"
            elif line_base == "echo":
                arg = line[5:].strip().strip('"').strip("'")
                combined += arg + "\n"
                write_fn(arg + "\r\n")
            elif ondevice is not None:
                sys_p, usr_p = prompt_manager.build_prompt(line)
                out = ondevice.send(sys_p, usr_p)
                if out:
                    combined += out + "\n"
            time.sleep(0.1)
        return combined.strip()

    def update_state(cmd, response):
        # ── apt install: track packages, strip flags and single chars ─────
        if re.search(r'\b(apt|apt-get)\s+install\b', cmd):
            parts = cmd.strip().split()
            try:
                i    = parts.index('install')
                pkgs = [
                    p for p in parts[i+1:]
                    if not p.startswith('-') and len(p) > 1
                ]
            except ValueError:
                pkgs = []
            for pkg in pkgs:
                if pkg not in SYSTEM_STATE["installed"]:
                    SYSTEM_STATE["installed"].append(pkg)
                    print(f"[state] installed: {pkg}")

        # ── apt remove/purge ──────────────────────────────────────────────
        if re.search(r'\b(apt|apt-get)\s+(remove|purge)\b', cmd):
            parts    = cmd.strip().split()
            verb_idx = next((i for i, p in enumerate(parts) if p in ("remove", "purge")), -1)
            pkgs     = [p for p in parts[verb_idx+1:] if not p.startswith('-')] if verb_idx >= 0 else []
            for pkg in pkgs:
                if pkg in SYSTEM_STATE["installed"]:
                    SYSTEM_STATE["installed"].remove(pkg)
                SYSTEM_STATE["versions"].pop(pkg, None)

        # ── version cache: store full string, never overwrite ─────────────
        m = re.match(r'^(?:sudo\s+)?([\w.\-]+)\s+(--version|-V)', cmd.strip())
        if m and response:
            tool = m.group(1)
            if tool not in SYSTEM_STATE["versions"]:
                # store the first line of the response as-is (full string)
                SYSTEM_STATE["versions"][tool] = response.strip().splitlines()[0]

        # ── file writes ───────────────────────────────────────────────────
        m = re.match(r"^echo\s+['\"]?(.+?)['\"]?\s*>\s*(.+)$", cmd.strip())
        if m:
            SYSTEM_STATE["files"][m.group(2).strip()] = {
                "content": m.group(1), "perms": "-rw-r--r--", "size": f"{len(m.group(1))}B",
            }

        m = re.match(r"^echo\s+['\"]?(.+?)['\"]?\s*>>\s*(.+)$", cmd.strip())
        if m:
            path = m.group(2).strip()
            if path in SYSTEM_STATE["files"] and "content" in SYSTEM_STATE["files"][path]:
                SYSTEM_STATE["files"][path]["content"] += "\n" + m.group(1)
            else:
                SYSTEM_STATE["files"][path] = {
                    "content": m.group(1), "perms": "-rw-r--r--", "size": f"{len(m.group(1))}B",
                }

        m = re.match(r"^touch\s+(.+)$", cmd.strip())
        if m:
            path = m.group(1).strip()
            if path not in SYSTEM_STATE["files"]:
                SYSTEM_STATE["files"][path] = {"content": "", "perms": "-rw-r--r--", "size": "0B"}

        # ── wget/curl: track downloaded file by destination path ──────────
        # curl ... -o /dest/file  →  use -o target
        m_curl_o = re.match(r"^curl\s+.*?-o\s+(\S+)", cmd.strip())
        if m_curl_o:
            dest = m_curl_o.group(1)
            url_m = re.search(r"https?://\S+", cmd)
            url   = url_m.group(0) if url_m else "unknown"
            SYSTEM_STATE["files"][dest] = {
                "content": f"[downloaded from {url}]", "source": url,
                "perms": "-rw-r--r--", "size": "4.2K",
            }
        else:
            # wget or curl without -o → filename from URL
            m = re.match(r"^(wget|curl)\s+.*?(https?://\S+)", cmd.strip())
            if m:
                url      = m.group(2)
                filename = url.rstrip("/").split("/")[-1] or "index.html"
                SYSTEM_STATE["files"][filename] = {
                    "content": f"[downloaded from {url}]", "source": url,
                    "perms": "-rw-r--r--", "size": "4.2K",
                }

        m = re.match(r"^chmod\s+\+x\s+(.+)$", cmd.strip())
        if m and m.group(1).strip() in SYSTEM_STATE["files"]:
            SYSTEM_STATE["files"][m.group(1).strip()]["perms"] = "-rwxr-xr-x"

        m = re.match(r"^rm\s+(?!.*-rf)(.+)$", cmd.strip())
        if m:
            SYSTEM_STATE["files"].pop(m.group(1).strip(), None)

        m = re.match(r"^mkdir\s+(?:-p\s+)?(.+)$", cmd.strip())
        if m:
            SYSTEM_STATE["files"][m.group(1).strip()] = {"perms": "drwxr-xr-x", "size": "4.0K"}

        # ── sed -i on tracked file ────────────────────────────────────────
        m = re.match(r"^sed\s+(-i\s+)?'s/(.+?)/(.+?)/(g?)'\s+(.+)$", cmd.strip())
        if m:
            old, new, g, path = m.group(2), m.group(3), m.group(4), m.group(5).strip()
            if path in SYSTEM_STATE["files"] and "content" in SYSTEM_STATE["files"][path]:
                c = SYSTEM_STATE["files"][path]["content"]
                SYSTEM_STATE["files"][path]["content"] = c.replace(old, new) if g else c.replace(old, new, 1)

    def sync_history(cmd):
        try:
            safe = cmd.replace("'", "'\\''")
            cowrie.shell.send(f"HISTFILE=~/.bash_history; history -s '{safe}'; history -w\n")
            time.sleep(0.1)
            if cowrie.shell.recv_ready():
                cowrie.shell.recv(9999)
        except Exception:
            pass

    def log(cmd, agent, response, fi_score=0, latency_ms=0.0):
        entry = {
            "session_id": SESSION_ID, "src_ip": src_ip,
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cmd": cmd, "agent": agent, "response": response,
            "fi_score": fi_score, "latency_ms": round(latency_ms, 2),
        }
        existing = []
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE) as f:
                    existing = json.load(f)
            except json.JSONDecodeError:
                pass
        existing.append(entry)
        with open(LOG_FILE, "w") as f:
            json.dump(existing, f, indent=2)

    # ── main dispatch ─────────────────────────────────────────────────────

    def handle(cmd: str, write_fn, read_fn):
        if cmd.strip() == "fi status":
            fi_manager.status()
            return "", ""

        t_start  = time.time()
        output   = ""
        streamed = False

        actual_cmd  = cmd.strip()[5:].strip() if cmd.strip().startswith("sudo ") else cmd.strip()
        actual_base = actual_cmd.split()[0] if actual_cmd else ""

        fi_score, _ = fi_manager.scorer.score(cmd)
        needs_llm   = _needs_llm(cmd, actual_base, SYSTEM_STATE)

        # ── Editor shortcut: installed editor → silent success ────────────
        if actual_base in EDITORS and _is_tool_available(actual_base):
            if not re.search(r'--version\b|-V\b', cmd):
                agent      = "on_device"
                output     = ""
                latency_ms = (time.time() - t_start) * 1000
                fi_manager.process(command=cmd, output=output, agent=agent, session_id=SESSION_ID)
                session.append({"cmd": cmd, "agent": agent, "response": output})
                log(cmd, agent, output, fi_score, latency_ms)
                return output, ""
            # --version falls through to Step 3

        # ── Step 0: not installed → command not found ─────────────────────
        skip_not_found = (
            not actual_base
            or actual_base in ("echo", "cd", "exit", "logout", "clear")
            or actual_cmd.startswith("./")
            or actual_cmd.startswith("apt")
            or actual_cmd.startswith("dpkg")
            or needs_llm
            or _is_tool_available(actual_base)
        )
        if not skip_not_found:
            agent      = "cowrie"
            output     = f"bash: {actual_base}: command not found"
            latency_ms = (time.time() - t_start) * 1000
            fi_manager.process(command=cmd, output=output, agent=agent, session_id=SESSION_ID)
            session.append({"cmd": cmd, "agent": agent, "response": output})
            log(cmd, agent, output, fi_score, latency_ms)
            return output, ""

        # ── Step 1: obfuscated → cloud ────────────────────────────────────
        if _is_cloud(cmd):
            agent  = "cloud"
            output = "[cloud LLM coming soon]"
            sync_history(cmd)

        # ── Step 2: FI 4 → cloud ─────────────────────────────────────────
        elif fi_score == 4:
            agent  = "cloud"
            output = "[cloud LLM coming soon]"
            sync_history(cmd)

        # ── Step 3: context-dependent ─────────────────────────────────────
        elif needs_llm:

            # version query — always handled directly
            if re.search(r'--version\b|-V\b', cmd):
                agent  = "on_device"
                output = _handle_version_query(cmd, actual_base)
                update_state(cmd, output)

            # systemctl / service — always handled directly
            elif actual_base in ("systemctl", "service"):
                agent  = "on_device"
                output = _handle_systemctl(cmd)
                update_state(cmd, output)

            # sed on tracked file — silent success, state already mutated
            elif actual_base == "sed":
                agent  = "on_device"
                update_state(cmd, "")
                output = ""

            # everything else — LLM if loaded, else Cowrie best-effort
            elif ondevice is not None:
                agent         = "on_device"
                script_output = _execute_tracked_script(cmd, write_fn)
                if script_output is not None:
                    output, streamed = script_output, True
                else:
                    sys_p, usr_p = prompt_manager.build_prompt(cmd)
                    output = ondevice.send(sys_p, usr_p)
                sync_history(cmd)
                update_state(cmd, output)

            else:
                agent     = "cowrie"
                output, _ = cowrie.send(cmd)
                update_state(cmd, output)

        # ── Step 4: FI 2-3 → cowrie ──────────────────────────────────────
        elif fi_score in (2, 3):
            agent = "cowrie"
            if is_static(cmd):
                output, streamed = dispatch_static(cmd, write_fn), True
            elif actual_base in SLOW:
                output, _ = cowrie.send_streaming(cmd, write_fn)
                streamed   = True
            elif actual_base in INTERACTIVE:
                output, _ = cowrie.send_interactive(cmd, write_fn, read_fn)
                streamed   = True
            else:
                output, _ = cowrie.send(cmd)
            update_state(cmd, output)

        # ── Step 5: FI 0-1 → cowrie ──────────────────────────────────────
        else:
            agent = "cowrie"
            if is_static(cmd):
                output, streamed = dispatch_static(cmd, write_fn), True
            elif actual_base in SLOW:
                output, _ = cowrie.send_streaming(cmd, write_fn)
                streamed   = True
            elif actual_base in INTERACTIVE:
                output, _ = cowrie.send_interactive(cmd, write_fn, read_fn)
                streamed   = True
            else:
                output, _ = cowrie.send(cmd)
            update_state(cmd, output)

        latency_ms = (time.time() - t_start) * 1000
        fi_manager.process(command=cmd, output=output, agent=agent, session_id=SESSION_ID)
        session.append({"cmd": cmd, "agent": agent, "response": output})
        log(cmd, agent, output, fi_score, latency_ms)
        return ("", "") if streamed else (output, "")

    return handle


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global config, ondevice
    config = load_config()

    ondevice = OnDeviceAgent(
        model        = config.agents.on_device.model,
        quantization = config.agents.on_device.quantization,
        temperature  = config.agents.on_device.temperature,
        max_tokens   = config.agents.on_device.max_tokens,
        do_sample    = config.agents.on_device.do_sample,
    ) if config.agents.on_device.enabled else None

    print(f"[HydraPot] on_device: {'loaded' if ondevice else 'DISABLED'}")

    cowrie = CowrieAgent(
        host     = config.agents.cowrie.host,
        port     = config.agents.cowrie.port,
        username = config.agents.cowrie.username,
        password = config.agents.cowrie.password,
    )
    cowrie._connect()

    try:
        start_server(
            handler_factory = lambda src_ip="?": make_command_handler(cowrie, src_ip=src_ip),
            host            = config.honeypot.host,
            port            = config.honeypot.port,
            hostname        = config.honeypot.hostname,
            os_banner       = config.honeypot.os,
        )
    except KeyboardInterrupt:
        print("\n[HydraPot] Shutting down...")
    finally:
        cowrie.disconnect()
        print("[HydraPot] Done.")


if __name__ == "__main__":
    main()