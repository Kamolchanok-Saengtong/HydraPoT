"""
config_loader.py — Reads config.yaml and returns a typed Config object.

Usage:
    from config_loader import load_config
    config = load_config()
    print(config.honeypot.hostname)   # → "svr04"
    print(config.agents.on_device.model)  # → "Qwen/Qwen2.5-Coder-7B-Instruct"
"""

import os
import sys
import yaml
from dataclasses import dataclass, field
from typing import Optional

CONFIG_PATH = "config.yaml"


# ─── Typed config sections ────────────────────────────────────────────────────

@dataclass
class HoneypotCfg:
    hostname: str = "svr04"
    os: str = "Ubuntu 12.04 LTS"
    host: str = "127.0.0.1"
    port: int = 2223
    # Self-identifies this deployment in every log record it writes (e.g.
    # "Database Server", "DMZ Web Server") — set once via `hp init`, not a
    # runtime flag. Lets a central SOC dashboard aggregate many HydraPoT
    # instances and tell them apart WITHOUT relying on which folder/host a
    # log file happened to be collected from.
    instance_name: str = "default"

@dataclass
class CowrieCfg:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 2222
    username: str = "root"
    password: str = "root"

@dataclass
class OnDeviceCfg:
    enabled: bool = True
    model: str = "Qwen/Qwen2.5-Coder-7B-Instruct"
    quantization: str = "4bit"
    gguf_file: str = ""   # which cached .gguf file to load when `model` has multiple variants
    temperature: float = 0.7
    max_tokens: int = 256
    do_sample: bool = True

@dataclass
class CloudCfg:
    enabled: bool = False
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key_env: str = "OPENAI_API_KEY"
    base_url: Optional[str] = None          # ← add this
    temperature: float = 0.3
    max_tokens: int = 512

@dataclass
class AgentsCfg:
    cowrie: CowrieCfg = field(default_factory=CowrieCfg)
    on_device: OnDeviceCfg = field(default_factory=OnDeviceCfg)
    cloud: CloudCfg = field(default_factory=CloudCfg)

@dataclass
class RoutingCfg:
    fallback: str = "cowrie"
    fi_routing: dict = field(default_factory=lambda: {
        0: "cowrie",
        1: "cowrie",
        2: "on_device",
        3: "on_device",
        4: "on_device",
    })

@dataclass
class LoggingCfg:
    session_dir: str = "data/logs/sessions"
    impactful_dir: str = "data/logs/impactful"
    auth_log: str = "data/logs/auth_log.json"
    fi_threshold: int = 2

@dataclass
class Config:
    honeypot: HoneypotCfg = field(default_factory=HoneypotCfg)
    agents: AgentsCfg = field(default_factory=AgentsCfg)
    routing: RoutingCfg = field(default_factory=RoutingCfg)
    logging: LoggingCfg = field(default_factory=LoggingCfg)
    # {sensor_key: {instance_name, hostname, host, port, cowrie_host,
    # cowrie_port, session_dir, impactful_dir, auth_log}} — multi-sensor
    # deployments. Selected via HYDRAPOT_SENSOR env var, merged onto
    # honeypot/agents.cowrie/logging above at load time.
    sensors: dict = field(default_factory=dict)
    static_commands: list = field(default_factory=lambda: [...])
    # MEA/PEA residential tariff (ประเภท 1.2) — plain dict like system_state
    # below, since tiers is a list-of-dicts that doesn't map cleanly onto a
    # typed dataclass. See config.yaml's power_tariff section for the shape.
    power_tariff: dict = field(default_factory=lambda: {
        "tiers": [
            {"max_units": 15,  "rate_thb_per_unit": 2.3488},
            {"max_units": 150, "rate_thb_per_unit": 3.2484},
            {"max_units": 400, "rate_thb_per_unit": 4.2218},
            {"max_units": None, "rate_thb_per_unit": 4.4217},
        ],
        "ft_surcharge_thb_per_unit": 0.1623,
        "vat_rate": 0.07,
    })
    system_state: dict = field(default_factory=lambda: {
        "pre_installed": [
            "coreutils", "bash", "ssh", "apt", "apt-get", "dpkg",
            "grep", "sed", "awk", "tar", "gzip", "net-tools",
            "procps", "util-linux", "cron", "sudo", "passwd",
            "wget", "curl",
        ],
        "starting_files": {
            "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
            "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
            "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
        },
        # ── Persona: what the fake machine IS ────────────────────────────
        # These four used to be hardcoded in main.py. They describe the box
        # an attacker thinks they landed on, so a deployment must be able to
        # change them without editing Python: a database sensor wants
        # `postgres`, a web sensor wants `www-data`, and a CentOS persona
        # needs entirely different version strings.
        #
        # Note `phil` is deliberately absent — it is Cowrie's stock demo
        # account, and shipping it makes the honeypot fingerprintable.

        # Fake /etc/passwd. `home` is also what `cd ~` and bare `cd` resolve
        # to for that account.
        "users": {
            "root":     {"uid": 0,    "gid": 0,    "home": "/root",        "shell": "/bin/bash"},
            "daemon":   {"uid": 1,    "gid": 1,    "home": "/usr/sbin",    "shell": "/bin/sh"},
            "bin":      {"uid": 2,    "gid": 2,    "home": "/bin",         "shell": "/bin/sh"},
            "www-data": {"uid": 33,   "gid": 33,   "home": "/var/www",     "shell": "/bin/sh"},
            "nobody":   {"uid": 65534,"gid": 65534,"home": "/nonexistent", "shell": "/bin/sh"},
            "sshd":     {"uid": 101,  "gid": 65534,"home": "/var/run/sshd","shell": "/usr/sbin/nologin"},
        },
        # Fake /etc/shadow. Values are shown verbatim by `cat /etc/shadow`.
        "shadow": {
            "root": "$6$4aOmWdpJ$/kyPOik9rR0kSLyABIYNXgg/UqlWX3c1eIaovOLWphShTGXmuUAMq6iu9DrcQqlVUw3Pirizns4u27w3Ugvb6.",
        },
        # `<tool> --version` output. Pins the persona to a distro/release.
        "versions": {
            "nmap":    "Nmap version 7.80 ( https://nmap.org )",
            "python3": "Python 3.10.12",
            "python":  "Python 3.10.12",
            "git":     "git version 2.34.1",
            "vim":     "VIM - Vi IMproved 8.2 (2019 Dec 12)",
            "gcc":     "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
            "g++":     "g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
            "curl":    "curl 7.81.0 (x86_64-pc-linux-gnu)",
            "wget":    "GNU Wget 1.21.2 built on linux-gnu.",
            "perl":    "This is perl 5, version 34, subversion 0 (v5.34.0)",
            "ruby":    "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233)",
            "php":     "PHP 8.1.2-1ubuntu2.14 (cli)",
            "node":    "v18.19.0",
            "make":    "GNU Make 4.3",
            "docker":  "Docker version 24.0.7, build afdd53b",
            "nginx":   "nginx version: nginx/1.18.0 (Ubuntu)",
            "htop":    "htop 3.2.1",
            "tmux":    "tmux 3.2a",
            "screen":  "Screen version 4.09.00 (GNU) 01-Sep-21",
            "nano":    "GNU nano, version 6.2",
            "emacs":   "GNU Emacs 27.1",
            "mysql":   "mysql  Ver 8.0.36-0ubuntu0.22.04.1 for Linux on x86_64",
        },
        # Directories that exist even with no file tracked under them, so
        # `cd /opt` succeeds. Each user's `home` above is added automatically.
        "known_dirs": [
            "/", "/root", "/home", "/tmp", "/var", "/etc", "/usr", "/bin",
            "/sbin", "/proc", "/sys", "/dev", "/opt", "/srv", "/mnt", "/media",
            "/run", "/lib", "/lib64", "/boot", "/var/tmp", "/var/log",
            "/var/run", "/usr/bin", "/usr/sbin", "/usr/local",
        ],
        # `apt install <pkg>` -> which command that provides. Package names
        # are distro-specific, so this is data; the resolution/routing logic
        # around it stays in main.py.
        "tool_packages": {
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
        },
    })


# ─── Loader ───────────────────────────────────────────────────────────────────

def _merge_dict_into_dataclass(dc_class, data: dict):
    """Recursively create a dataclass instance from a dict, using defaults for missing keys."""
    if data is None:
        return dc_class()

    kwargs = {}
    for f in dc_class.__dataclass_fields__:
        val = data.get(f, None)
        ft  = dc_class.__dataclass_fields__[f].type

        if val is None:
            # use default
            continue

        # if the field is itself a dataclass, recurse
        if hasattr(ft, '__dataclass_fields__'):
            kwargs[f] = _merge_dict_into_dataclass(ft, val)
        else:
            kwargs[f] = val

    return dc_class(**kwargs)


def load_config(path: str = CONFIG_PATH) -> Config:
    """
    Load config.yaml → Config object.
    If file doesn't exist, returns defaults.
    If file has missing fields, defaults fill in.
    """
    if not os.path.exists(path):
        return Config()

    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"[config] Error parsing {path}: {e}")
        print("[config] Using defaults.")
        return Config()

    # build Config from raw dict
    honeypot = _merge_dict_into_dataclass(HoneypotCfg, raw.get("honeypot"))
    cowrie   = _merge_dict_into_dataclass(CowrieCfg,   raw.get("agents", {}).get("cowrie"))
    ondev    = _merge_dict_into_dataclass(OnDeviceCfg,  raw.get("agents", {}).get("on_device"))
    cloud    = _merge_dict_into_dataclass(CloudCfg,     raw.get("agents", {}).get("cloud"))
    agents   = AgentsCfg(cowrie=cowrie, on_device=ondev, cloud=cloud)
    routing  = _merge_dict_into_dataclass(RoutingCfg,   raw.get("routing"))
    logging_ = _merge_dict_into_dataclass(LoggingCfg,   raw.get("logging"))

    sensors = raw.get("sensors") or {}
    sensor_key = os.environ.get("HYDRAPOT_SENSOR")
    if sensor_key and sensor_key in sensors:
        s = sensors[sensor_key]
        honeypot.hostname      = s.get("hostname", honeypot.hostname)
        honeypot.instance_name = s.get("instance_name", honeypot.instance_name)
        honeypot.host          = s.get("host", honeypot.host)
        honeypot.port          = s.get("port", honeypot.port)
        cowrie.host            = s.get("cowrie_host", cowrie.host)
        cowrie.port            = s.get("cowrie_port", cowrie.port)
        logging_.session_dir   = s.get("session_dir", logging_.session_dir)
        logging_.impactful_dir = s.get("impactful_dir", logging_.impactful_dir)
        logging_.auth_log      = s.get("auth_log", logging_.auth_log)
    elif sensor_key:
        print(f"[config] HYDRAPOT_SENSOR={sensor_key!r} not found in config.yaml's "
              f"sensors: section — using top-level honeypot/logging values.")

    static_cmds   = raw.get("static_commands")
    system_state  = raw.get("system_state")
    power_tariff  = raw.get("power_tariff")

    # handle the field defaults properly
    if static_cmds is None:
        static_cmds = Config().static_commands
    if power_tariff is None:
        power_tariff = Config().power_tariff

    # system_state: merge PER-KEY with the defaults rather than replacing the
    # whole dict. Previously any config.yaml that defined system_state at all
    # replaced the default wholesale, so a key it happened to omit silently
    # became absent — this is exactly how "pre_installed" went missing and the
    # LLM started reporting "wget: command not found". Merging keeps this
    # loader's documented promise ("missing fields, defaults fill in") true for
    # nested keys too, while anything the user DOES specify still wins.
    _default_state = Config().system_state
    if system_state is None:
        system_state = _default_state
    else:
        merged = dict(_default_state)
        merged.update(system_state)
        system_state = merged

    return Config(
        honeypot=honeypot,
        agents=agents,
        routing=routing,
        logging=logging_,
        sensors=sensors,
        static_commands=static_cmds,
        system_state=system_state,
        power_tariff=power_tariff,
    )


def save_config(config_dict: dict, path: str = CONFIG_PATH):
    """Write a config dict to YAML."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write("# ═══════════════════════════════════════════════════════════════════════════════\n")
        f.write("# HydraPoT Configuration\n")
        f.write("# ═══════════════════════════════════════════════════════════════════════════════\n")
        f.write("# Edit this file directly OR run `hp init` to reconfigure.\n\n")
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False, allow_unicode=True)