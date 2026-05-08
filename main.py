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


# populated by main()
config   = None
ondevice = None


def make_command_handler(cowrie: CowrieAgent, src_ip: str = "?"):
    # tool → package name (which package provides this binary?)
    TOOL_TO_PACKAGE = {
        # networking/scanning
        "nmap":       "nmap",
        "masscan":    "masscan",
        "ncat":       "nmap",
        "netcat":     "netcat-openbsd",
        "nc":         "netcat-openbsd",
        "tcpdump":    "tcpdump",
        "socat":      "socat",
        "whois":      "whois",
        # languages
        "python":     "python3",
        "python3":    "python3",
        "python2":    "python2",
        "perl":       "perl",
        "ruby":       "ruby",
        "php":        "php",
        "node":       "nodejs",
        "lua":        "lua5.3",
        # compilers/dev
        "gcc":        "gcc",
        "g++":        "g++",
        "make":       "make",
        "gdb":        "gdb",
        "git":        "git",
        "strace":     "strace",
        # servers
        "nginx":      "nginx",
        "apache2":    "apache2",
        "mysql":      "mysql-server",
        "mysqldump":  "mysql-client",
        "redis-cli":  "redis-tools",
        "docker":     "docker.io",
        # editors
        "vim":        "vim",
        "nano":       "nano",
        "emacs":      "emacs",
        # download tools
        "wget":       "wget",
        "curl":       "curl",
        # misc
        "htop":       "htop",
        "screen":     "screen",
        "tmux":       "tmux",
        "zip":        "zip",
        "unzip":      "unzip",
        "7z":         "p7zip-full",
        "jq":         "jq",
        "tree":       "tree",
    }

    # tools that are always available (part of coreutils/base system)
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
        "versions":      {},
        "installed":     list(config.system_state.get("pre_installed", [])),
        "files":         config.system_state.get("starting_files", {}),
    }

    prompt_manager = PromptManager(
    fi_manager,
    SYSTEM_STATE,
    hostname = config.honeypot.hostname,
    os_name  = config.honeypot.os,
    )
    session        = []
    
    def _is_tool_available(cmd_base: str) -> bool:
        """Is this tool installed or built-in?"""
        # always available
        if cmd_base in BUILTIN_TOOLS:
            return True

        # check if the tool's package was installed via apt
        pkg = TOOL_TO_PACKAGE.get(cmd_base)
        if pkg and pkg in SYSTEM_STATE["installed"]:
            return True

        # check if the tool name itself was installed directly
        if cmd_base in SYSTEM_STATE["installed"]:
            return True

        # tools installed from config pre_installed list
        pre = config.system_state.get("pre_installed", [])
        if cmd_base in pre:
            return True
        # check if any pre-installed package provides this tool
        if pkg and pkg in pre:
            return True

        return False

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
    
    def _execute_tracked_script(cmd: str, write_fn) -> str:
        """
        If cmd is executing a tracked script, run each line through
        the appropriate handler (static, cowrie, or LLM).
        Returns combined output, or None if not a tracked script.
        """
        parts = cmd.strip().split()

        # figure out the script path
        if cmd.strip().startswith("./"):
            script = cmd.strip()[2:].split()[0]
        elif parts[0] in ("bash", "sh") and len(parts) > 1:
            script = parts[1]
        else:
            return None

        # check if we have the content
        file_info = SYSTEM_STATE["files"].get(script, {})
        content = file_info.get("content", "")
        if not content or content.startswith("[downloaded from"):
            return None  # no real content — let LLM handle it

        # execute each line
        combined_output = ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            line_base = line.split()[0] if line else ""

            # static handler (nmap, ping, traceroute, etc.)
            if is_static(line):
                out = dispatch_static(line, write_fn)
                combined_output += out + "\n"
            # echo — just print the argument
            elif line_base == "echo":
                # strip 'echo ' prefix and quotes
                arg = line[5:].strip().strip('"').strip("'")
                combined_output += arg + "\n"
                write_fn(arg + "\r\n")
            # other commands — let LLM handle this line
            elif ondevice is not None:
                sys_p, usr_p = prompt_manager.build_prompt(line)
                out = ondevice.send(sys_p, usr_p)
                if out:
                    combined_output += out + "\n"
            
            import time
            time.sleep(0.1)  # small delay between lines for realism

        return combined_output.strip()

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

        # ── Track file writes ─────────────────────────────────────────
        # echo 'content' > /path/file
        echo_write = re.match(r"^echo\s+['\"]?(.+?)['\"]?\s*>\s*(.+)$", cmd.strip())
        if echo_write:
            content = echo_write.group(1)
            path    = echo_write.group(2).strip()
            SYSTEM_STATE["files"][path] = {
                "content": content,
                "perms": "-rw-r--r--",
                "size": f"{len(content)}B",
            }

        # echo 'content' >> /path/file (append)
        echo_append = re.match(r"^echo\s+['\"]?(.+?)['\"]?\s*>>\s*(.+)$", cmd.strip())
        if echo_append:
            content = echo_append.group(1)
            path    = echo_append.group(2).strip()
            if path in SYSTEM_STATE["files"] and "content" in SYSTEM_STATE["files"][path]:
                SYSTEM_STATE["files"][path]["content"] += "\n" + content
            else:
                SYSTEM_STATE["files"][path] = {
                    "content": content,
                    "perms": "-rw-r--r--",
                    "size": f"{len(content)}B",
                }

        # touch /path/file
        touch_match = re.match(r"^touch\s+(.+)$", cmd.strip())
        if touch_match:
            path = touch_match.group(1).strip()
            if path not in SYSTEM_STATE["files"]:
                SYSTEM_STATE["files"][path] = {
                    "content": "",
                    "perms": "-rw-r--r--",
                    "size": "0B",
                }

        # wget/curl download
        download_match = re.match(r"^(wget|curl)\s+.*?(https?://\S+)", cmd.strip())
        if download_match:
            url = download_match.group(2)
            filename = url.rstrip("/").split("/")[-1] or "index.html"
            SYSTEM_STATE["files"][filename] = {
                "content": f"[downloaded from {url}]",
                "source": url,
                "perms": "-rw-r--r--",
                "size": "4.2K",
            }

        # chmod +x /path/file
        chmod_match = re.match(r"^chmod\s+\+x\s+(.+)$", cmd.strip())
        if chmod_match:
            path = chmod_match.group(1).strip()
            if path in SYSTEM_STATE["files"]:
                SYSTEM_STATE["files"][path]["perms"] = "-rwxr-xr-x"

        # rm file (not rm -rf)
        rm_match = re.match(r"^rm\s+(?!.*-rf)(.+)$", cmd.strip())
        if rm_match:
            path = rm_match.group(1).strip()
            SYSTEM_STATE["files"].pop(path, None)

        # mkdir
        mkdir_match = re.match(r"^mkdir\s+(?:-p\s+)?(.+)$", cmd.strip())
        if mkdir_match:
            path = mkdir_match.group(1).strip()
            SYSTEM_STATE["files"][path] = {
                "perms": "drwxr-xr-x",
                "size": "4.0K",
            }
        # sed substitution on tracked file
        sed_match = re.match(r"^sed\s+(-i\s+)?'s/(.+?)/(.+?)/(g?)'\s+(.+)$", cmd.strip())
        if sed_match:
            old_text = sed_match.group(2)
            new_text = sed_match.group(3)
            global_flag = sed_match.group(4)
            path = sed_match.group(5).strip()
            if path in SYSTEM_STATE["files"] and "content" in SYSTEM_STATE["files"][path]:
                content = SYSTEM_STATE["files"][path]["content"]
                if global_flag:
                    content = content.replace(old_text, new_text)
                else:
                    content = content.replace(old_text, new_text, 1)
                SYSTEM_STATE["files"][path]["content"] = content

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

    SLOW = ('wget', 'curl', 'masscan', 'apt', 'apt-get')
    INTERACTIVE = ('passwd', 'adduser', 'useradd', 'userdel')
        # ── context check: does this command need the LLM? ────────────────────
    def _needs_llm(cmd: str, cmd_base: str, state: dict) -> bool:
        """Does this command need LLM context to respond correctly?"""
        files = state.get("files", {})

        # version queries — Cowrie can't handle these properly
        if re.search(r'--version\b|-V\b', cmd):
            if _is_tool_available(cmd_base):
                return True
            else:
                return False

        # service management — Cowrie doesn't have systemctl
        if cmd_base in ("systemctl", "service", "journalctl"):
            return True

        # script execution with interpreter
        if cmd_base in ("bash", "sh", "python", "python3", "perl", "node", "ruby", "php", "lua"):
            parts = cmd.strip().split()
            if len(parts) > 1:
                script = parts[1]
                if script in files and files[script].get("content"):
                    return True

        # ./ execution
        if cmd.strip().startswith("./"):
            script = cmd.strip()[2:].split()[0]
            if script in files:
                return True

        # cat a tracked file
        if cmd_base == "cat":
            parts = cmd.strip().split()
            for p in parts[1:]:
                if not p.startswith("-") and p in files and files[p].get("content"):
                    return True

        # sed on a tracked file
        if cmd_base == "sed":
            parts = cmd.strip().split()
            for p in parts[1:]:
                if not p.startswith("-") and p in files:
                    return True

        if cmd_base == "hostname":
            return True

        # commands Cowrie fundamentally can't execute
        if cmd_base in ("gcc", "g++", "make", "gdb", "strace", "ltrace"):
            return True

        return False
    # ── main per-command dispatch ─────────────────────────────────────────
    def handle(cmd: str, write_fn, read_fn):
        if cmd.strip() == "fi status":
            fi_manager.status()
            return "", ""

        t_start  = time.time()
        output   = ""
        streamed = False
        cmd_base = cmd.strip().split()[0] if cmd.strip() else ""

        # strip sudo to check the actual tool
        actual_cmd = cmd.strip()
        if actual_cmd.startswith("sudo "):
            actual_cmd = actual_cmd[5:].strip()
        actual_base = actual_cmd.split()[0] if actual_cmd else ""

        fi_score, _ = fi_manager.scorer.score(cmd)

        # ── Step 0: tool not installed? ──────────────────────────
        if (actual_base
            and actual_base not in ("echo", "cd", "exit", "logout", "clear")
            and not actual_cmd.startswith("./")
            and not actual_cmd.startswith("apt")
            and not actual_cmd.startswith("dpkg")
            and not _needs_llm(cmd, actual_base, SYSTEM_STATE)   # ← add this line
            and not _is_tool_available(actual_base)):
            agent  = "cowrie"
            output = f"bash: {actual_base}: command not found"
            # still log it
            latency_ms = (time.time() - t_start) * 1000
            fi_event = fi_manager.process(
                command=cmd, output=output, agent=agent, session_id=SESSION_ID,
            )
            session.append({"cmd": cmd, "agent": agent, "response": output})
            log(cmd, agent, output, fi_score, latency_ms)
            return output, ""

        # ── Step 1: obfuscated → cloud ────────────────────────────
        if _is_cloud(cmd):
            agent  = "cloud"
            output = "[cloud LLM coming soon]"
            sync_history(cmd)

        # ── Step 2: FI 4 → cloud ─────────────────────────────────
        elif fi_score == 4:
            agent  = "cloud"
            output = "[cloud LLM coming soon]"
            sync_history(cmd)

        # ── Step 3: context-dependent → on_device ─────────────────
        elif _needs_llm(cmd, cmd_base, SYSTEM_STATE) and ondevice is not None:
            agent = "on_device"

            # try script execution with sub-command dispatch
            script_output = _execute_tracked_script(cmd, write_fn)
            if script_output is not None:
                output = script_output
                streamed = True  # already written to attacker via write_fn
            else:
                # not a script, or downloaded file — LLM handles directly
                sys_p, usr_p = prompt_manager.build_prompt(cmd)
                output = ondevice.send(sys_p, usr_p)

            sync_history(cmd)
            update_state(cmd, output)

        # ── Step 4: FI 2-3 without context → cowrie ──────────────
        elif fi_score in (2, 3):
            agent = "cowrie"
            if is_static(cmd):
                output = dispatch_static(cmd, write_fn)
                streamed = True
            elif cmd_base in SLOW:
                output, _ = cowrie.send_streaming(cmd, write_fn)
                streamed = True
            elif cmd_base in INTERACTIVE:
                output, _ = cowrie.send_interactive(cmd, write_fn, read_fn)
                streamed = True
            else:
                output, _ = cowrie.send(cmd)
            update_state(cmd, output)

        # ── Step 5: FI 0-1 → cowrie ──────────────────────────────
        else:
            agent = "cowrie"
            if is_static(cmd):
                output = dispatch_static(cmd, write_fn)
                streamed = True
            elif cmd_base in SLOW:
                output, _ = cowrie.send_streaming(cmd, write_fn)
                streamed = True
            elif cmd_base in INTERACTIVE:
                output, _ = cowrie.send_interactive(cmd, write_fn, read_fn)
                streamed = True
            else:
                output, _ = cowrie.send(cmd)
            update_state(cmd, output)

        latency_ms = (time.time() - t_start) * 1000
        fi_event   = fi_manager.process(
            command    = cmd,
            output     = output,
            agent      = agent,
            session_id = SESSION_ID,
        )
        session.append({"cmd": cmd, "agent": agent, "response": output})
        log(cmd, agent, output, fi_score, latency_ms)

        if streamed:
            return "", ""
        return output, ""

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