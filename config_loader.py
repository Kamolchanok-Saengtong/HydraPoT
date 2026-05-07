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
    temperature: float = 0.7
    max_tokens: int = 256
    do_sample: bool = True

@dataclass
class CloudCfg:
    enabled: bool = False
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key_env: str = "OPENAI_API_KEY"
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
        4: "cloud",
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
    static_commands: list = field(default_factory=lambda: [
        "nmap", "ping", "traceroute", "tracepath",
        "top", "htop", "watch", "tail",
        "vim", "vi", "nano", "emacs",
        "less", "more",
    ])
    system_state: dict = field(default_factory=lambda: {
        "starting_files": {
            "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
            "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
            "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
        }
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

    static_cmds  = raw.get("static_commands")
    system_state = raw.get("system_state")

    # handle the field defaults properly
    if static_cmds is None:
        static_cmds = Config().static_commands
    if system_state is None:
        system_state = Config().system_state

    return Config(
        honeypot=honeypot,
        agents=agents,
        routing=routing,
        logging=logging_,
        static_commands=static_cmds,
        system_state=system_state,
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