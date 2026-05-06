"""
setup_wizard.py — HydraPoT interactive setup wizard.

Run directly:   python setup_wizard.py
Via CLI:         hp init

Walks the user through configuration, writes config.yaml,
and offers to launch the honeypot or dashboard.
"""

import os
import sys
import yaml
import subprocess

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False


console = Console() if HAS_RICH else None

CONFIG_PATH = "config.yaml"

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _print(text: str, style: str = ""):
    if console:
        console.print(text, style=style)
    else:
        print(text)

def _prompt(text: str, default: str = "") -> str:
    """Simple prompt with default value shown."""
    if default:
        display = f"{text} [{default}]: "
    else:
        display = f"{text}: "

    if HAS_CLICK:
        return click.prompt(text, default=default, show_default=True)
    else:
        val = input(display).strip()
        return val if val else default

def _choice(text: str, options: list[tuple[str, str]], default: int = 1) -> int:
    """
    Show numbered options, return the index (1-based).
    options = list of (label, description) tuples.
    """
    _print(f"\n{text}")
    for i, (label, desc) in enumerate(options, 1):
        marker = "→" if i == default else " "
        _print(f"  {marker} {i}) {label}  {desc}", style="dim" if i != default else "bold")

    while True:
        raw = input(f"  Choice [{default}]: ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if 1 <= val <= len(options):
                return val
        except ValueError:
            pass
        _print(f"  Please enter a number between 1 and {len(options)}", style="red")

def _confirm(text: str, default: bool = True) -> bool:
    """Yes/no confirmation."""
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"  {text} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


# ─── Welcome Banner ──────────────────────────────────────────────────────────

def show_welcome():
    if console:
        banner = Text()
        banner.append("\n")
        banner.append("  🍯  Welcome to HydraPoT\n", style="bold yellow")
        banner.append("  Honeypot Framework Setup\n\n", style="dim")
        banner.append("  An Intelligent Honeypot Framework Using\n", style="")
        banner.append("  Large Language Models for Interactive\n", style="")
        banner.append("  Attack Analysis\n\n", style="")
        banner.append("  by Kamolchanok Saengtong\n", style="dim italic")
        console.print(Panel(banner, border_style="yellow", box=box.DOUBLE_EDGE,
                            width=52, padding=(0, 2)))
    else:
        print("=" * 52)
        print("  🍯  Welcome to HydraPoT")
        print("  Honeypot Framework Setup")
        print("")
        print("  An Intelligent Honeypot Framework Using")
        print("  Large Language Models for Interactive")
        print("  Attack Analysis")
        print("")
        print("  by Kamolchanok Saengtong")
        print("=" * 52)

    print()
    _print("This wizard will configure your honeypot.", style="bold")
    _print("Press Enter to accept defaults shown in [brackets].\n", style="dim")


# ─── Load existing config (for re-run) ────────────────────────────────────────

def load_existing() -> dict:
    """Load current config.yaml if it exists, for pre-filling defaults."""
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


# ─── Wizard Questions ─────────────────────────────────────────────────────────

def ask_honeypot(existing: dict) -> dict:
    """Section 1: Honeypot identity."""
    hp = existing.get("honeypot", {})

    _print("─── Honeypot Identity ───", style="bold cyan")

    hostname = _prompt("[1] Hostname for the fake server", hp.get("hostname", "svr04"))

    os_choices = [
        ("Ubuntu 12.04 LTS", "(recommended — CVE-rich, attacker-attractive)"),
        ("Ubuntu 22.04 LTS", "(modern)"),
        ("Debian 11",        "(stable)"),
        ("CentOS 7",         "(enterprise)"),
    ]
    # find current default
    current_os = hp.get("os", "Ubuntu 12.04 LTS")
    os_default = 1
    for i, (label, _) in enumerate(os_choices, 1):
        if label == current_os:
            os_default = i
            break

    os_idx = _choice("[2] OS to impersonate", os_choices, default=os_default)
    chosen_os = os_choices[os_idx - 1][0]

    port = int(_prompt("[3] Honeypot SSH port", str(hp.get("port", 2223))))

    return {
        "hostname": hostname,
        "os": chosen_os,
        "port": port,
    }


def ask_deployment(existing: dict) -> dict:
    """Section 2: Deployment mode (localhost / LAN / custom)."""
    hp = existing.get("honeypot", {})

    _print("\n─── Deployment Mode ───", style="bold cyan")

    deploy_choices = [
        ("Localhost only (127.0.0.1)", "(safest — self-testing only)"),
        ("LAN (0.0.0.0)",             "(anyone on your network can connect)"),
        ("Custom IP",                 "(you specify the bind address)"),
    ]

    current_host = hp.get("host", "127.0.0.1")
    if current_host == "127.0.0.1":
        deploy_default = 1
    elif current_host == "0.0.0.0":
        deploy_default = 2
    else:
        deploy_default = 3

    deploy_idx = _choice("[4] Bind address", deploy_choices, default=deploy_default)

    if deploy_idx == 1:
        host = "127.0.0.1"
    elif deploy_idx == 2:
        host = "0.0.0.0"
        _print("\n  ⚠️  WARNING: binding to 0.0.0.0 exposes the honeypot", style="bold red")
        _print("  to everyone on your network (and internet if port-forwarded).", style="red")
        if not _confirm("Continue with 0.0.0.0?", default=False):
            host = "127.0.0.1"
            _print("  → Falling back to 127.0.0.1 (localhost)", style="yellow")
    else:
        host = _prompt("  Enter bind IP address", current_host)

    return {"host": host}


def ask_cowrie(existing: dict) -> dict:
    """Section 3: Cowrie backend connection."""
    cw = existing.get("agents", {}).get("cowrie", {})

    _print("\n─── Cowrie Backend ───", style="bold cyan")
    _print("  Cowrie is the low-interaction SSH emulator (Docker container).", style="dim")

    host     = _prompt("[5] Cowrie host",     cw.get("host", "127.0.0.1"))
    port     = int(_prompt("[6] Cowrie port", str(cw.get("port", 2222))))
    username = _prompt("[7] Cowrie username",  cw.get("username", "root"))
    password = _prompt("[8] Cowrie password",  cw.get("password", "root"))

    return {
        "enabled": True,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
    }


def ask_on_device(existing: dict) -> dict:
    """Section 4: On-device LLM."""
    od = existing.get("agents", {}).get("on_device", {})

    _print("\n─── On-Device LLM ───", style="bold cyan")
    _print("  Local model for version queries, scripts, and context-aware responses.", style="dim")

    model_choices = [
        ("Qwen 2.5 1.5B Instruct",  "(small, fast, ~3GB RAM)"),
        ("Qwen 2.5 7B Instruct",    "(better quality, ~15GB RAM)"),
        ("Qwen 2.5 Coder 7B",       "(code-focused, ~15GB RAM)"),
        ("Custom model",             "(enter HuggingFace model name)"),
        ("None — disable",          "(cowrie + cloud only)"),
    ]

    MODEL_MAP = {
        1: "Qwen/Qwen2.5-1.5B-Instruct",
        2: "Qwen/Qwen2.5-7B-Instruct",
        3: "Qwen/Qwen2.5-Coder-7B-Instruct",
    }

    # detect current model to set default
    current_model = od.get("model", "Qwen/Qwen2.5-Coder-7B-Instruct")
    model_default = 3  # default to Coder 7B
    for idx, m in MODEL_MAP.items():
        if m == current_model:
            model_default = idx
            break
    if not od.get("enabled", True):
        model_default = 5

    model_idx = _choice("[9] On-device LLM", model_choices, default=model_default)

    if model_idx == 5:
        return {"enabled": False, "model": "", "quantization": "4bit",
                "temperature": 0.7, "max_tokens": 256, "do_sample": True}

    if model_idx == 4:
        model = _prompt("  Enter HuggingFace model name", current_model)
    else:
        model = MODEL_MAP[model_idx]

    quant_choices = [
        ("4-bit", "(fastest, least RAM)"),
        ("8-bit", "(balanced)"),
        ("None",  "(full precision — needs lots of RAM)"),
    ]
    quant_map = {1: "4bit", 2: "8bit", 3: "none"}
    current_quant = od.get("quantization", "4bit")
    quant_default = {v: k for k, v in quant_map.items()}.get(current_quant, 1)

    quant_idx = _choice("[10] Quantization", quant_choices, default=quant_default)

    temperature = float(_prompt("[11] Temperature", str(od.get("temperature", 0.7))))
    max_tokens  = int(_prompt("[12] Max tokens",   str(od.get("max_tokens", 256))))

    return {
        "enabled": True,
        "model": model,
        "quantization": quant_map[quant_idx],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "do_sample": True,
    }


def ask_cloud(existing: dict) -> dict:
    """Section 5: Cloud LLM."""
    cl = existing.get("agents", {}).get("cloud", {})

    _print("\n─── Cloud LLM ───", style="bold cyan")
    _print("  API-based model for high-impact / obfuscated attack commands.", style="dim")

    enable = _confirm("[13] Enable cloud LLM?", default=cl.get("enabled", False))

    if not enable:
        return {
            "enabled": False,
            "provider": cl.get("provider", "openai"),
            "model": cl.get("model", "gpt-4o-mini"),
            "api_key_env": cl.get("api_key_env", "OPENAI_API_KEY"),
            "temperature": cl.get("temperature", 0.3),
            "max_tokens": cl.get("max_tokens", 512),
        }

    provider_choices = [
        ("OpenAI",    "(GPT-4o, GPT-4o-mini, etc.)"),
        ("Anthropic", "(Claude Sonnet, Haiku, etc.)"),
        ("Google",    "(Gemini Pro, Flash, etc.)"),
        ("Other",     "(custom provider)"),
    ]

    current_provider = cl.get("provider", "openai").lower()
    prov_default = {"openai": 1, "anthropic": 2, "google": 3}.get(current_provider, 1)

    prov_idx = _choice("[14] Cloud provider", provider_choices, default=prov_default)

    PROVIDER_MAP = {1: "openai", 2: "anthropic", 3: "google", 4: "other"}
    KEY_ENV_MAP  = {1: "OPENAI_API_KEY", 2: "ANTHROPIC_API_KEY", 3: "GOOGLE_API_KEY", 4: "CLOUD_API_KEY"}

    provider    = PROVIDER_MAP[prov_idx]
    model       = _prompt("[15] Model name",         cl.get("model", "gpt-4o-mini"))
    api_key_env = _prompt("[16] API key env var name", cl.get("api_key_env", KEY_ENV_MAP[prov_idx]))
    temperature = float(_prompt("[17] Temperature",   str(cl.get("temperature", 0.3))))
    max_tokens  = int(_prompt("[18] Max tokens",      str(cl.get("max_tokens", 512))))

    # check if the env var is actually set
    if not os.environ.get(api_key_env):
        _print(f"\n  ⚠️  Environment variable '{api_key_env}' is not set.", style="yellow")
        _print(f"  Set it before running: export {api_key_env}=sk-...", style="dim")

    return {
        "enabled": True,
        "provider": provider,
        "model": model,
        "api_key_env": api_key_env,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }


# ─── Build final config dict ─────────────────────────────────────────────────

def build_config(honeypot: dict, deployment: dict, cowrie: dict,
                 on_device: dict, cloud: dict) -> dict:
    """Assemble all answers into a single config dict for YAML output."""
    return {
        "honeypot": {
            "hostname": honeypot["hostname"],
            "os":       honeypot["os"],
            "host":     deployment["host"],
            "port":     honeypot["port"],
        },
        "agents": {
            "cowrie":    cowrie,
            "on_device": on_device,
            "cloud":     cloud,
        },
        "routing": {
            "fallback": "cowrie",
            "fi_routing": {
                0: "cowrie",
                1: "cowrie",
                2: "on_device" if on_device["enabled"] else "cowrie",
                3: "on_device" if on_device["enabled"] else "cowrie",
                4: "cloud"     if cloud["enabled"]     else ("on_device" if on_device["enabled"] else "cowrie"),
            },
        },
        "static_commands": [
            "nmap", "ping", "traceroute", "tracepath",
            "top", "htop", "watch", "tail",
            "vim", "vi", "nano", "emacs",
            "less", "more",
        ],
        "logging": {
            "session_dir":   "data/logs/sessions",
            "impactful_dir": "data/logs/impactful",
            "auth_log":      "data/logs/auth_log.json",
            "fi_threshold":  2,
        },
        "system_state": {
            "starting_files": {
                "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
                "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
                "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
            },
        },
    }


# ─── Save config ──────────────────────────────────────────────────────────────

def save_config(config_dict: dict):
    """Write config dict to config.yaml with comments."""
    with open(CONFIG_PATH, "w") as f:
        f.write("# ═══════════════════════════════════════════════════════════════════════════════\n")
        f.write("# HydraPoT Configuration\n")
        f.write("# ═══════════════════════════════════════════════════════════════════════════════\n")
        f.write("# Generated by `hp init`. Edit directly or re-run `hp init` to reconfigure.\n\n")
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ─── Show summary ─────────────────────────────────────────────────────────────

def show_summary(config_dict: dict):
    """Print a summary of the config that was saved."""
    hp    = config_dict["honeypot"]
    cw    = config_dict["agents"]["cowrie"]
    od    = config_dict["agents"]["on_device"]
    cl    = config_dict["agents"]["cloud"]

    print()
    _print("✓ Configuration saved to ./config.yaml\n", style="bold green")

    if console:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Hostname",   hp["hostname"])
        table.add_row("OS",         hp["os"])
        table.add_row("Bind",       f"{hp['host']}:{hp['port']}")
        table.add_row("Cowrie",     f"{cw['host']}:{cw['port']}  ({cw['username']})")
        table.add_row("On-device",  od["model"] if od["enabled"] else "disabled")
        table.add_row("Cloud",      f"{cl['provider']} / {cl['model']}" if cl["enabled"] else "disabled")

        console.print(Panel(table, title="[bold]Config Summary[/bold]",
                            border_style="green", width=60))
    else:
        print(f"  Hostname:   {hp['hostname']}")
        print(f"  OS:         {hp['os']}")
        print(f"  Bind:       {hp['host']}:{hp['port']}")
        print(f"  Cowrie:     {cw['host']}:{cw['port']}  ({cw['username']})")
        print(f"  On-device:  {od['model'] if od['enabled'] else 'disabled'}")
        print(f"  Cloud:      {cl['provider']} / {cl['model']}" if cl['enabled'] else "  Cloud:      disabled")

    print()


# ─── "What now?" menu ────────────────────────────────────────────────────────

def what_now_menu():
    """Post-setup menu: run, dashboard, edit again, or quit."""
    while True:
        if console:
            menu = Text()
            menu.append("  1) ", style="bold")
            menu.append("Run honeypot\n")
            menu.append("  2) ", style="bold")
            menu.append("Open dashboard\n")
            menu.append("  3) ", style="bold")
            menu.append("Edit config again\n")
            menu.append("  q) ", style="bold")
            menu.append("Quit\n")
            console.print(Panel(menu, title="[bold]What now?[/bold]",
                                border_style="yellow", width=40))
        else:
            print("─── What now? ──────────────────")
            print("  1) Run honeypot")
            print("  2) Open dashboard")
            print("  3) Edit config again")
            print("  q) Quit")
            print("────────────────────────────────")

        choice = input("  > ").strip().lower()

        if choice == "1":
            _print("\nStarting honeypot...\n", style="bold green")
            try:
                import main
                main.main()
            except KeyboardInterrupt:
                _print("\nHoneypot stopped.", style="yellow")
            return

        elif choice == "2":
            _print("\nOpening dashboard...\n", style="bold green")
            try:
                subprocess.run([
                    sys.executable, "-m", "streamlit", "run", "dashboard.py",
                    "--server.headless", "true",
                ])
            except KeyboardInterrupt:
                _print("\nDashboard closed.", style="yellow")
            return

        elif choice == "3":
            return "rerun"

        elif choice in ("q", "quit", "exit"):
            _print("\nGoodbye! Run `hp run` when you're ready.\n", style="dim")
            return

        else:
            _print("  Invalid choice. Pick 1, 2, 3, or q.", style="red")


# ─── Main wizard flow ────────────────────────────────────────────────────────

def run_wizard():
    """The main wizard loop. Can be called directly or via `hp init`."""
    while True:
        show_welcome()

        existing = load_existing()

        # ask all sections
        honeypot   = ask_honeypot(existing)
        deployment = ask_deployment(existing)
        cowrie     = ask_cowrie(existing)
        on_device  = ask_on_device(existing)
        cloud      = ask_cloud(existing)

        # build and save
        config_dict = build_config(honeypot, deployment, cowrie, on_device, cloud)
        save_config(config_dict)
        show_summary(config_dict)

        # what now?
        result = what_now_menu()
        if result == "rerun":
            print("\n" * 2)
            continue   # restart wizard
        break


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        run_wizard()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled. No changes written.")
        sys.exit(1)