"""main.py — HydraPoT honeypot orchestrator."""
import json
import os
import re
import time
import random
from datetime import datetime

from config_loader import load_config
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from agent_manager.static_handler import is_static, dispatch_static
from prompt.fi_manager import FILogManager
from prompt.prompt_manager import PromptManager
from agent_manager.cloud_agent import CloudAgent
from ssh_server import start_server
from router import _is_cloud
import sys 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from plugins.plugin_loader import PluginManager

config   = None
ondevice = None
cloud = None


def make_command_handler(cowrie: CowrieAgent, src_ip: str = "?", public_ip: str = "?", plugins=None, sri_max_events: int = 10):

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

    # Base system tools — SINGLE SOURCE: config.yaml system_state.base_tools.
    # Parsed robustly so the comma-per-line YAML format works (each line may
    # list several tools separated by commas).
    def _parse_base_tools(raw):
        tools = set()
        for entry in (raw or []):
            for t in str(entry).split(","):
                t = t.strip()
                if t:
                    tools.add(t)
        return tools

    BUILTIN_TOOLS = _parse_base_tools(config.system_state.get("base_tools", []))
    # shell builtins handled directly in handle() (cd/exit/clear/etc.) — added
    # so version/availability checks treat them as present too.
    BUILTIN_TOOLS |= {"cd", "exit", "logout", "clear", "alias", "export",
                      "history", "source", "bg", "fg", "jobs", "umask"}

    EDITORS     = {"vim", "vi", "nano", "emacs"}
    SLOW        = ("masscan",)
    INTERACTIVE = ("adduser", "useradd", "userdel")

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
        max_events=sri_max_events,
        min_fi=config.logging.fi_threshold,
    )
    if plugins:
        plugins.apply_fi_rules(fi_manager.scorer)

    SYSTEM_STATE = {
        "versions":  {},
        "installed": {},
        "files":     dict(config.system_state.get("starting_files", {})),
        "users": {
            "root":     {"uid": 0,    "gid": 0,    "home": "/root",       "shell": "/bin/bash"},
            "daemon":   {"uid": 1,    "gid": 1,    "home": "/usr/sbin",   "shell": "/bin/sh"},
            "bin":      {"uid": 2,    "gid": 2,    "home": "/bin",        "shell": "/bin/sh"},
            "www-data": {"uid": 33,   "gid": 33,   "home": "/var/www",    "shell": "/bin/sh"},
            "nobody":   {"uid": 65534,"gid": 65534,"home": "/nonexistent","shell": "/bin/sh"},
            "sshd":     {"uid": 101,  "gid": 65534,"home": "/var/run/sshd","shell": "/usr/sbin/nologin"},
            "phil":     {"uid": 1000, "gid": 1000, "home": "/home/phil",  "shell": "/bin/bash"},
        },
        "shadow": {
            "root": "$6$4aOmWdpJ$/kyPOik9rR0kSLyABIYNXgg/UqlWX3c1eIaovOLWphShTGXmuUAMq6iu9DrcQqlVUw3Pirizns4u27w3Ugvb6.",
            "phil": "$6$ErqInBoz$FibX212AFnHMvyZdWW87bq5Cm3214CoffqFuUyzz.ZKmZ725zKqSPRRlQ1fGGP02V/WawQWQrDda6YiKERNR61",
        },
    }

    for pkg in config.system_state.get("pre_installed", []):
        if pkg not in SYSTEM_STATE["installed"]:
            display = DEFAULT_VERSIONS.get(pkg)
            num_m   = re.search(r'(\d+\.\d+(?:\.\d+)*)', display or "")
            ver_num = num_m.group(1) if num_m else "1.0.0"
            SYSTEM_STATE["installed"][pkg] = {
                "version":     ver_num,
                "version_str": display or f"{pkg} version {ver_num}",
            }

    prompt_manager = PromptManager(
        fi_manager,
        SYSTEM_STATE,
        hostname=config.honeypot.hostname,
        os_name=config.honeypot.os,
        builtins   = BUILTIN_TOOLS,

    )
    session = []

    # ── helpers ───────────────────────────────────────────────────────────

    def _rand_ver() -> str:
        return f"{random.randint(1,3)}.{random.randint(0,19)}.{random.randint(0,9)}"

    def _is_tool_available(cmd_base: str) -> bool:
        if cmd_base in BUILTIN_TOOLS:
            return True
        if cmd_base in SYSTEM_STATE["installed"]:
            return True
        pkg = TOOL_TO_PACKAGE.get(cmd_base)
        if pkg and pkg in SYSTEM_STATE["installed"]:
            return True
        return False
    
    # ── Virtual file generation ───────────────────────────────────────────
    # /etc/passwd and /etc/shadow are generated on-demand from SYSTEM_STATE
    # ["users"] / ["shadow"] — no stored content to keep in sync.

    def _generate_passwd() -> str:
        lines = []
        for name, u in SYSTEM_STATE["users"].items():
            uid  = u.get("uid", 1000)
            gid  = u.get("gid", uid)
            home = u.get("home", f"/home/{name}")
            sh   = u.get("shell", "/bin/sh")
            gecos = u.get("gecos", name)
            lines.append(f"{name}:x:{uid}:{gid}:{gecos}:{home}:{sh}")
        return "\n".join(lines)

    def _generate_shadow() -> str:
        lines = []
        for name in SYSTEM_STATE["users"]:
            pw = SYSTEM_STATE["shadow"].get(name, "*")
            lines.append(f"{name}:{pw}:15800:0:99999:7:::")
        return "\n".join(lines)

    VIRTUAL_FILES = {
        "/etc/passwd": _generate_passwd,
        "/etc/shadow": _generate_shadow,
    }

    def _virtual_file(path: str) -> str | None:
        """Return generated content for virtual files, None for real tracked files."""
        if path in VIRTUAL_FILES:
            return VIRTUAL_FILES[path]()
        f = SYSTEM_STATE["files"].get(path, {})
        return f.get("content") if f else None

    def _handle_version_query(cmd: str, cmd_base: str) -> str:
        if cmd_base in SYSTEM_STATE["versions"]:
            return SYSTEM_STATE["versions"][cmd_base]
        if cmd_base in DEFAULT_VERSIONS:
            ver = DEFAULT_VERSIONS[cmd_base]
            SYSTEM_STATE["versions"][cmd_base] = ver
            return ver
        pkg_info = SYSTEM_STATE["installed"].get(cmd_base, {})
        ver = pkg_info.get("version_str") or f"{cmd_base} version {pkg_info.get('version', '1.0.0')}"
        SYSTEM_STATE["versions"][cmd_base] = ver
        return ver

    def _handle_systemctl(cmd: str) -> str:
        parts = cmd.strip().split()
        if len(parts) < 3:
            return "Usage: systemctl [OPTIONS...] COMMAND ..."
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

    def _handle_passwd(cmd: str, write_fn, read_fn) -> str:
        time.sleep(random.uniform(1.5, 3.0))
        time.sleep(random.uniform(1.5, 3.0))
        return "passwd: password updated successfully"

    def _needs_llm(cmd: str, cmd_base: str, state: dict) -> bool:
        files = state.get("files", {})
        if re.search(r'--version\b|-V\b', cmd):
            return _is_tool_available(cmd_base)
        if cmd_base in ("systemctl", "service", "journalctl"):
            return True
        pre_installed = config.system_state.get("pre_installed", [])
        if (cmd_base not in BUILTIN_TOOLS
            and cmd_base in SYSTEM_STATE["installed"]
            and cmd_base not in pre_installed):
            return True
        pkg = TOOL_TO_PACKAGE.get(cmd_base)
        if (pkg and cmd_base not in BUILTIN_TOOLS
            and pkg in SYSTEM_STATE["installed"]
            and pkg not in pre_installed):
            return True
        if cmd_base in ("bash", "sh", "python", "python3", "perl", "node", "ruby", "php", "lua"):
            parts = cmd.strip().split()
            if len(parts) > 1 and parts[1] in files and files[parts[1]].get("content"):
                return True
        if cmd.strip().startswith("./"):
            script = cmd.strip()[2:].split()[0]
            if script in files:
                return True
        if cmd_base == "cat":
            for p in cmd.strip().split()[1:]:
                if p.startswith("-"):
                    continue
                if p in VIRTUAL_FILES:          # virtual: always has content
                    return True
                if p in files and files[p].get("content"):
                    return True
        if cmd_base == "sed":
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
    def _canonical_package(pkg: str) -> str:
        if re.match(r'^python3\.\d+', pkg):  return "python3"
        if re.match(r'^python2\.\d+', pkg):  return "python2"
        if re.match(r'^gcc-\d+',      pkg):  return "gcc"
        if re.match(r'^g\+\+-\d+',    pkg):  return "g++"
        if re.match(r'^ruby\d+\.\d+', pkg):  return "ruby"
        if re.match(r'^php\d+\.\d+',  pkg):  return "php"
        if re.match(r'^nodejs\d+',    pkg):  return "node"
        return pkg

    def _register_packages(pkgs: list):
        for pkg in pkgs:
            canonical = _canonical_package(pkg)
            if canonical not in SYSTEM_STATE["installed"]:
                ver_num = _rand_ver()
                display = DEFAULT_VERSIONS.get(canonical) or f"{canonical} {ver_num}"
                SYSTEM_STATE["installed"][canonical] = {
                    "version":     ver_num,
                    "version_str": display,
                }
                print(f"[state] installed: {canonical} {ver_num}")

    def _fake_apt_output(pkgs: list) -> str:
        total_kb = sum(random.randint(200, 900) for _ in pkgs)
        total_mb = round(total_kb * 2.2 / 1024, 1)
        lines = [
            "Reading package lists... Done",
            "Building dependency tree",
            "Reading state information... Done",
            "The following NEW packages will be installed:",
            f"  {' '.join(pkgs)}",
            f"0 upgraded, {len(pkgs)} newly installed, 0 to remove and 259 not upgraded.",
            f"Need to get {total_kb}.2kB of archives.",
            f"After this operation, {total_mb}MB of additional disk space will be used.",
        ]
        for pkg in pkgs:
            ver = SYSTEM_STATE["installed"][_canonical_package(pkg)]["version"]
            kb  = random.randint(200, 900)
            lines.append(f"Get:1 http://archive.ubuntu.com/ubuntu jammy/main amd64 {pkg} {ver} [{kb}.2 kB]")
        lines += [
            f"Fetched {total_kb}.2kB in 1s (4493B/s)",
            "Selecting previously unselected package(s).",
            "(Reading database ... 177887 files and directories currently installed.)",
        ]
        for pkg in pkgs:
            ver = SYSTEM_STATE["installed"][_canonical_package(pkg)]["version"]
            lines.append(f"Preparing to unpack .../archives/{pkg}_{ver}_amd64.deb ...")
            lines.append(f"Unpacking {pkg} ({ver}) ...")
        lines.append("Processing triggers for man-db (2.10.2-1) ...")
        for pkg in pkgs:
            ver = SYSTEM_STATE["installed"][_canonical_package(pkg)]["version"]
            lines.append(f"Setting up {pkg} ({ver}) ...")
        return "\n".join(lines)

    def _fake_download_output(cmd: str, actual_base: str) -> str:
        url_m    = re.search(r'https?://\S+', cmd)
        url      = url_m.group(0) if url_m else "http://unknown"
        dest_m   = re.search(r'-o\s+(\S+)', cmd)
        if dest_m:
            dest = dest_m.group(1)
        else:
            fname = url.rstrip("/").split("/")[-1] or "index.html"
            dest  = f"/root/{fname}"
        size_kb  = random.randint(4, 800)
        speed_kb = random.randint(100, 1200)
        now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if actual_base == "wget":
            return (
                f"--{now}--  {url}\n"
                f"Connecting to {url.split('/')[2]}:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size_kb * 1024} ({size_kb}K) [application/octet-stream]\n"
                f"Saving to: '{dest}'\n\n"
                f"{size_kb}K [======================================>] "
                f"{size_kb * 1024}  {speed_kb}.{random.randint(10,99)}KB/s   in 0.{random.randint(1,9)}s\n\n"
                f"{now} ({speed_kb}.{random.randint(10,99)} KB/s) - '{dest}' saved [{size_kb*1024}/{size_kb*1024}]"
            )
        else:
            return (
                f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                f"100 {size_kb}K  100 {size_kb}K    0     0  {speed_kb}k      0  0:00:01  0:00:01 --:--:-- {speed_kb}k"
            )

    def update_state(cmd, response):
        if re.search(r'\b(apt|apt-get)\s+(remove|purge)\b', cmd):
            parts    = cmd.strip().split()
            verb_idx = next((i for i, p in enumerate(parts) if p in ("remove", "purge")), -1)
            pkgs     = [p for p in parts[verb_idx+1:] if not p.startswith('-')] if verb_idx >= 0 else []
            for pkg in pkgs:
                SYSTEM_STATE["installed"].pop(pkg, None)
                SYSTEM_STATE["versions"].pop(pkg, None)

        m = re.match(r'^(?:sudo\s+)?([\w.\-]+)\s+(--version|-V)', cmd.strip())
        if m and response:
            tool = m.group(1)
            if tool not in SYSTEM_STATE["versions"]:
                SYSTEM_STATE["versions"][tool] = response.strip().splitlines()[0]

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

        m_curl_o = re.match(r"^curl\s+.*?-o\s+(\S+)", cmd.strip())
        if m_curl_o:
            dest  = m_curl_o.group(1)
            url_m = re.search(r"https?://\S+", cmd)
            url   = url_m.group(0) if url_m else "unknown"
            SYSTEM_STATE["files"][dest] = {
                "content": f"[downloaded from {url}]", "source": url,
                "perms": "-rw-r--r--", "size": "4.2K",
            }
        else:
            m = re.match(r"^(wget|curl)\s+.*?(https?://\S+)", cmd.strip())
            if m:
                url      = m.group(2)
                filename = url.rstrip("/").split("/")[-1] or "index.html"
                SYSTEM_STATE["files"][filename] = {
                    "content": f"[downloaded from {url}]", "source": url,
                    "perms": "-rw-r--r--", "size": "4.2K",
                }
        # chpasswd — update shadow passwords
        m = re.match(r'^echo\s+["\']?(\w+):(\S+?)["\']?\s*\|\s*chpasswd', cmd.strip())
        if m:
            user, pw = m.group(1), m.group(2)
            if user in SYSTEM_STATE["users"]:
                SYSTEM_STATE["shadow"][user] = f"$6$salt${pw}_hashed"

        m = re.match(r"^chmod\s+\+x\s+(.+)$", cmd.strip())
        if m and m.group(1).strip() in SYSTEM_STATE["files"]:
            SYSTEM_STATE["files"][m.group(1).strip()]["perms"] = "-rwxr-xr-x"

        m = re.match(r"^rm\s+(?!.*-rf)(.+)$", cmd.strip())
        if m:
            SYSTEM_STATE["files"].pop(m.group(1).strip(), None)

        m = re.match(r"^mkdir\s+(?:-p\s+)?(.+)$", cmd.strip())
        if m:
            SYSTEM_STATE["files"][m.group(1).strip()] = {"perms": "drwxr-xr-x", "size": "4.0K"}

        m = re.match(r"^sed\s+(-i\s+)?'s/(.+?)/(.+?)/(g?)'\s+(.+)$", cmd.strip())
        if m:
            old, new, g, path = m.group(2), m.group(3), m.group(4), m.group(5).strip()
            if path in SYSTEM_STATE["files"] and "content" in SYSTEM_STATE["files"][path]:
                c = SYSTEM_STATE["files"][path]["content"]
                SYSTEM_STATE["files"][path]["content"] = c.replace(old, new) if g else c.replace(old, new, 1)

        m = re.match(r"^mv\s+(\S+)\s+(\S+)$", cmd.strip())
        if m:
            src, dst = m.group(1).strip(), m.group(2).strip()
            if src in SYSTEM_STATE["files"]:
                SYSTEM_STATE["files"][dst] = SYSTEM_STATE["files"].pop(src)

    def sync_history(cmd):
        try:
            safe = cmd.replace("'", "'\\''")
            cowrie.shell.send(f"HISTFILE=~/.bash_history; history -s '{safe}'; history -w\n")
            time.sleep(0.1)
            if cowrie.shell.recv_ready():
                cowrie.shell.recv(9999)
        except Exception as e:
            print(f"[sync_history] FAILED: {e}")  # ← add this

    def log(cmd, agent, response, fi_score=0, latency_ms=0.0):
        entry = {
            "session_id": SESSION_ID, "src_ip": src_ip,
            "public_ip":  public_ip,
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

    # ── shortcut: log + return ────────────────────────────────────────────
    def _finish(cmd, agent, output, fi_score, t_start, streamed=False):
        handle.last_agent = agent
        latency_ms = (time.time() - t_start) * 1000
        fi_manager.process(command=cmd, output=output, agent=agent, session_id=SESSION_ID)
        session.append({"cmd": cmd, "agent": agent, "response": output})
        log(cmd, agent, output, fi_score, latency_ms)

        # export to SIEM
        if plugins:
            plugins.export_event({
                "session_id": SESSION_ID, "src_ip": src_ip,
                "timestamp": datetime.now().isoformat(),
                "cmd": cmd, "agent": agent, "fi_score": fi_score,
                "latency_ms": round(latency_ms, 2),
            })

        return ("", "") if streamed else (output, "")

    # ── main dispatch ─────────────────────────────────────────────────────

    def handle(cmd: str, write_fn, read_fn, force_agent: str | None = None):
        if cmd.strip() == "fi status":
            fi_manager.status()
            return "", ""

        t_start  = time.time()
        output   = ""
        streamed = False

        actual_cmd  = cmd.strip()[5:].strip() if cmd.strip().startswith("sudo ") else cmd.strip()
        actual_base = actual_cmd.split()[0] if actual_cmd else ""
        lookup_base = os.path.basename(actual_base)   # strip path for tool-availability checks

        fi_score, _ = fi_manager.scorer.score(cmd)

        # ── evaluation-only forced routing ───────────────────────────────────
        # force_agent is only set by the eval framework (run_partB.py).
        # Production always calls handle(cmd, write_fn, read_fn) — force_agent
        # defaults to None and this block is completely skipped.
        if force_agent is not None:
            if force_agent == "cloud":
                agent = "cloud"
                if cloud is not None:
                    sys_p, usr_p = prompt_manager.build_cloud_prompt(cmd)
                    output = cloud.send(sys_p, usr_p)
                else:
                    output = ""
                sync_history(cmd)
                return _finish(cmd, agent, output, fi_score, t_start)
            elif force_agent == "on_device":
                agent = "on_device"
                if ondevice is not None:
                    sys_p, usr_p = prompt_manager.build_prompt(cmd)
                    output = ondevice.send(sys_p, usr_p)
                else:
                    output = ""
                update_state(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)
            elif force_agent == "cowrie":
                agent  = "cowrie"
                output, _ = cowrie.send(cmd)
                update_state(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)

        # ── apt install — fully local, streamed ───────────────────────────
        if re.search(r'\b(apt|apt-get)\s+install\b', actual_cmd):
            parts = actual_cmd.strip().split()
            try:
                i    = parts.index('install')
                pkgs = [p for p in parts[i+1:] if not p.startswith('-') and len(p) > 1]
            except ValueError:
                pkgs = []
            if pkgs:
                _register_packages(pkgs)
                output = _fake_apt_output(pkgs)
                for line in output.split("\n"):
                    write_fn(line + "\r\n")
                    time.sleep(random.uniform(0.1, 0.4))
                return _finish(cmd, "cowrie", output, fi_score, t_start, streamed=True)

        # ── wget/curl — fake download, streamed ──────────────────────────
        if actual_base in ("wget", "curl") and re.search(r'https?://', actual_cmd):
            output = _fake_download_output(actual_cmd, actual_base)
            for line in output.split("\n"):
                write_fn(line + "\r\n")
                time.sleep(random.uniform(0.2, 0.6))
            update_state(cmd, output)
            return _finish(cmd, "cowrie", output, fi_score, t_start, streamed=True)

        if actual_base == "passwd":
            fi_manager.process(command=cmd, output="", agent="on_device", session_id=SESSION_ID)
            session.append({"cmd": cmd, "agent": "on_device", "response": ""})
            log(cmd, "on_device", "", fi_score, t_start)
            return "", ""
        
        if actual_base in INTERACTIVE:
            parts = actual_cmd.strip().split()
            if len(parts) < 2:
                output, _ = cowrie.send(cmd)
                return _finish(cmd, "cowrie", output, fi_score, t_start)

            if actual_base == "userdel":
                username = parts[-1]
                SYSTEM_STATE["users"].pop(username, None)
                SYSTEM_STATE["shadow"].pop(username, None)
                output = ""
                return _finish(cmd, "cowrie", output, fi_score, t_start)

            # useradd / adduser — register user
            username = parts[-1]
            shell_m  = re.search(r'-s\s+(\S+)', actual_cmd)
            shell    = shell_m.group(1) if shell_m else "/bin/bash"
            uid      = 1000 + len(SYSTEM_STATE["users"])
            SYSTEM_STATE["users"][username] = {
                "uid": uid, "gid": uid,
                "home": f"/home/{username}", "shell": shell,
            }
            SYSTEM_STATE["shadow"][username] = "*"
            output = ""
            return _finish(cmd, "cowrie", output, fi_score, t_start)

        # ── editor (installed, not --version) — silent success ────────────
        if actual_base in EDITORS and _is_tool_available(actual_base):
            if re.search(r'--version\b|-V\b', cmd):
                output = _handle_version_query(cmd, lookup_base)
                return _finish(cmd, "on_device", output, fi_score, t_start)
            else:
                return _finish(cmd, "on_device", "", fi_score, t_start)

        # ── chmod on tracked file — handle locally ────────────────────────
        if actual_base == "chmod" and not re.search(r'--version\b|-V\b', cmd):
            parts  = actual_cmd.split()
            target = parts[-1] if len(parts) >= 3 else ""
            if target in SYSTEM_STATE["files"]:
                update_state(cmd, "")
                return _finish(cmd, "cowrie", "", fi_score, t_start)
        
        # ── find — return plausible results for common attacker queries ───
        if actual_base == "find" and not re.search(r'--version\b', cmd):
            if re.search(r'-perm\s+-?4000', actual_cmd):
                output = "\n".join([
                    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
                    "/usr/bin/chfn", "/bin/mount", "/bin/umount", "/bin/ping",
                ])
                return _finish(cmd, "cowrie", output, fi_score, t_start)
            if re.search(r'-name\s+["\']?\*\.conf', actual_cmd):
                output = "\n".join([
                    "/etc/ssh/sshd_config", "/etc/mysql/mysql.conf.d/mysqld.cnf",
                    "/etc/nginx/nginx.conf", "/etc/php/8.1/cli/php.ini",
                    "/etc/fail2ban/fail2ban.conf", "/etc/logrotate.conf",
                ])
                return _finish(cmd, "cowrie", output, fi_score, t_start)
            if re.search(r'-name\s+["\']?\*\.env', actual_cmd):
                output = "/var/www/html/.env\n/opt/app/.env"
                return _finish(cmd, "cowrie", output, fi_score, t_start)

        needs_llm = _needs_llm(cmd, lookup_base, SYSTEM_STATE)
        agent = "cowrie"   # ← add this line
        # ── Step 0: not installed → command not found ─────────────────────
        skip_not_found = (
            not actual_base
            or actual_base in ("echo", "cd", "exit", "logout", "clear")
            or actual_cmd.startswith("./")
            or actual_cmd.startswith("apt")
            or actual_cmd.startswith("dpkg")
            or needs_llm
            or _is_tool_available(lookup_base)
        )
        if _is_cloud(cmd):
            agent = "cloud"
            if cloud is not None:
                sys_p, usr_p = prompt_manager.build_cloud_prompt(cmd)
                output = cloud.send(sys_p, usr_p)
            else:
                output = ""
            sync_history(cmd)
            return _finish(cmd, agent, output, fi_score, t_start)

        # ── Step 1: not installed → command not found ─────────────────────
        if not skip_not_found:
            output = f"bash: {actual_base}: command not found"
            return _finish(cmd, "cowrie", output, fi_score, t_start)

        # Step 2: FI 4 → cloud
        elif fi_score == 4:
            agent = "cloud"
            if cloud is not None:
                sys_p, usr_p = prompt_manager.build_cloud_prompt(cmd) 
                output = cloud.send(sys_p, usr_p)
            else:
                output = ""
            sync_history(cmd)

        # ── Step 3: context-dependent ─────────────────────────────────────
        elif needs_llm:
            if re.search(r'--version\b|-V\b', cmd):
                agent  = "on_device"
                output = _handle_version_query(cmd, lookup_base)
                update_state(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)
            
            elif actual_base == "touch":
                update_state(cmd, "")
                return _finish(cmd, "cowrie", "", fi_score, t_start)

            elif actual_base == "mkdir":
                update_state(cmd, "")
                return _finish(cmd, "cowrie", "", fi_score, t_start)
            # ── mv — handle locally if source file is tracked ─────────────────
            elif actual_base == "mv":
                parts = actual_cmd.split()
                if len(parts) >= 3:
                    src = parts[1]
                    if src in SYSTEM_STATE["files"]:
                        update_state(cmd, "")
                        return _finish(cmd, "cowrie", "", fi_score, t_start)

            elif actual_base in ("systemctl", "service"):
                agent  = "on_device"
                output = _handle_systemctl(actual_cmd)
                update_state(cmd, output)

            elif actual_base == "sed":
                agent = "on_device"
                update_state(cmd, "")
                output = ""
                
            elif is_static(cmd):
                agent = "cowrie"
                output = dispatch_static(cmd, write_fn)
                streamed = True
    
            elif ondevice is not None:
                agent         = "on_device"
                script_output = _execute_tracked_script(cmd, write_fn)
                if script_output is not None:
                    output, streamed = script_output, True
                else:
                    file_key  = cmd.strip()[2:].split()[0] if cmd.strip().startswith("./") else actual_cmd.split()[-1]
                    file_info = SYSTEM_STATE["files"].get(file_key, {})
                    if file_info.get("content", "").startswith("[downloaded from"):
                        sys_p = (
                            f"You are a Linux terminal. The attacker ran: {cmd}\n"
                            f"This is a script downloaded from the internet. "
                            f"Simulate realistic terminal output as if it executed. "
                            f"3-6 lines max. No explanation, no markdown."
                        )
                        output = ondevice.send(sys_p, cmd)
                    else:
                        # for cat on virtual/tracked files, inject actual content
                        # so the LLM doesn't hallucinate — it reads what's really there
                        extra = ""
                        if actual_base == "cat":
                            for p in actual_cmd.split()[1:]:
                                if p.startswith("-") or p.startswith("|"):
                                    continue
                                content = _virtual_file(p)
                                if content:
                                    extra += f"\nFILE CONTENT of {p}:\n{content}\n"
                        sys_p, usr_p = prompt_manager.build_prompt(cmd)
                        if extra:
                            usr_p = usr_p + extra
                        output = ondevice.send(sys_p, usr_p)
                sync_history(cmd)
                update_state(cmd, output)

            else:
                agent     = "cowrie"
                output, _ = cowrie.send(cmd)
                update_state(cmd, output)
        
        else:
            agent     = "cowrie"
            output, _ = cowrie.send(cmd)
            update_state(cmd, output)

        if (agent == "cowrie" and not streamed
                and ("command not found" in (output or "") or "cannot execute binary file" in (output or ""))
                and _is_tool_available(actual_base)
                and ondevice is not None):
            sys_p, usr_p = prompt_manager.build_prompt(cmd)
            llm_out = ondevice.send(sys_p, usr_p)
            if llm_out and "command not found" not in llm_out:
                output = llm_out
                agent  = "on_device"
                update_state(cmd, output)
        return _finish(cmd, agent, output, fi_score, t_start, streamed)

    return handle
# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    global config, ondevice, cloud
    config = load_config()
    plugins = PluginManager("plugins/")
    plugins.load_all()

    ondevice = OnDeviceAgent(
        model        = config.agents.on_device.model,
        quantization = config.agents.on_device.quantization,
        temperature  = config.agents.on_device.temperature,
        max_tokens   = config.agents.on_device.max_tokens,
        do_sample    = config.agents.on_device.do_sample,
    ) if config.agents.on_device.enabled else None

    cloud = CloudAgent(
        provider    = config.agents.cloud.provider,
        model       = config.agents.cloud.model,
        api_key_env = config.agents.cloud.api_key_env,
        base_url    = getattr(config.agents.cloud, "base_url", "https://ai.psu.blue/v1"),
        temperature = config.agents.cloud.temperature,
        max_tokens  = config.agents.cloud.max_tokens,
    ) if config.agents.cloud.enabled else None

    print(f"[HydraPot] on_device: {'loaded' if ondevice else 'DISABLED'}")
    print(f"[HydraPot] cloud: {'loaded' if cloud else 'DISABLED'}")

    def _make_cowrie():
        c = CowrieAgent(
            host     = config.agents.cowrie.host,
            port     = config.agents.cowrie.port,
            username = config.agents.cowrie.username,
            password = config.agents.cowrie.password,
        )
        c._connect()
        return c

    try:
        start_server(
            handler_factory = lambda src_ip="?", public_ip="?": make_command_handler(
                _make_cowrie(), src_ip=src_ip, public_ip=public_ip, plugins=plugins
            ),
            host            = config.honeypot.host,
            port            = config.honeypot.port,
            hostname        = config.honeypot.hostname,
            os_banner       = config.honeypot.os,
        )
    except KeyboardInterrupt:
        print("\n[HydraPot] Shutting down...")
    finally:
        plugins.flush_exporters()
        print("[HydraPot] Done.")


if __name__ == "__main__":
    main()