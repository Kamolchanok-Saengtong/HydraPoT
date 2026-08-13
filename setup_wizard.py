"""
setup_wizard.py — HydraPoT interactive setup wizard.

Run directly:   python setup_wizard.py
Via CLI:         hp init

Walks the user through configuration, writes config.yaml,
and offers to launch the honeypot or dashboard.
"""

import os
import sys
import time
import yaml
import questionary
from questionary import Style
import readchar

WIZARD_STYLE = Style([
    ("qmark",       "fg:#ffaa00 bold"),
    ("question",    "bold"),
    ("answer",      "fg:#ffaa00 bold"),
    ("pointer",     "fg:#ffaa00 bold"),
    ("highlighted", ""),          # ← completely empty, no color, no bg, nothing
    ("selected",    "fg:#888888"),
    ("instruction", "fg:#888888"),
])
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

# Anchored to this file's own location (repo root), not the process's current
# working directory — otherwise running `hp init` from any other directory
# silently finds no config.yaml and falls back to generic wizard defaults
# instead of your real, already-configured values.
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")


# ─── Default system_state template ────────────────────────────────────────────
# Used ONLY for a brand-new config (no existing config.yaml). On any re-run the
# wizard PRESERVES whatever system_state is already in config.yaml — including
# base_tools — so `hp init` never wipes hand-edited tools. This is the single
# source of truth for "what tools exist on the fake machine".
DEFAULT_SYSTEM_STATE = {
    "base_tools": [
        "ls, cat, cp, mv, rm, mkdir, rmdir, touch, echo, pwd, head, tail, sort, uniq",
        "wc, cut, tr, tee, dd, df, du, chmod, chown, chgrp, ln, basename, dirname",
        "readlink, stat, truncate, nproc, id, whoami, who, users, groups, env, printenv",
        "date, sleep, seq, yes, test, expr, base64, md5sum, sha1sum, sha256sum, sha512sum",
        "cksum, comm, fold, nl, od, paste, split, tac, mktemp, realpath, timeout, install",
        "mkfifo, nice, nohup, printf, tty, uname, vdir, dir, arch, logname, shred, sync",
        "mount, umount, fdisk, lsblk, blkid, dmesg, more, kill, mountpoint, hexdump",
        "getopt, flock, renice, taskset, lscpu, lsmem, findmnt, rev, column, whereis",
        "cal, last, su, login, fsck, mkswap, swapon, swapoff, uuidgen, namei, ionice",
        "ps, top, free, pkill, pgrep, pmap, pwdx, sysctl, tload, uptime, vmstat, w, watch",
        "ifconfig, netstat, route, arp, ip, ss, bridge, tc, nstat, ping, arping, tracepath",
        "grep, egrep, fgrep, sed, awk, gawk, tar, gzip, gunzip, zcat, bzip2, bunzip2",
        "xz, unxz, find, xargs, diff, cmp, file, less, nano, vi, hostname, which, logger",
        "passwd, useradd, userdel, usermod, groupadd, gpasswd, chage, crontab, adduser",
        "apt, apt-get, apt-cache, dpkg, dpkg-query, update-alternatives",
        "systemctl, journalctl, loginctl, timedatectl, hostnamectl, sudo, sudoedit, service",
        "bash, sh, ssh, scp, sftp, ssh-keygen, perl, python3, gpg, curl, wget, openssl",
        "dig, nslookup, host, traceroute, umask, xxd, at, finger, ltrace, strace",
    ],
    "starting_files": {
        "/etc/passwd": {"perms": "-rw-r--r--", "size": "2.1K"},
        "/etc/shadow": {"perms": "-rw-r-----", "size": "1.4K"},
        "/var/log":    {"perms": "drwxr-xr-x", "size": "4.0K"},
    },
}


class GoBack(Exception):
    """User chose 'Go back' or typed 'b'."""
    pass


def build_default_config(existing: dict) -> dict:
    """Build a config dict from defaults (or last saved config if it exists)."""
    hp = existing.get("honeypot", {})
    cw = existing.get("agents", {}).get("cowrie", {})
    od = existing.get("agents", {}).get("on_device", {})
    cl = existing.get("agents", {}).get("cloud", {})

    return build_config(
        honeypot   = {
            "hostname":      hp.get("hostname", "svr04"),
            "instance_name": hp.get("instance_name", "default"),
            "os":            hp.get("os",       "Ubuntu 12.04 LTS"),
            "port":          hp.get("port",     2223),
        },
        deployment = {"host": hp.get("host", "127.0.0.1")},
        cowrie     = {
            "enabled":  cw.get("enabled",  True),
            "host":     cw.get("host",     "127.0.0.1"),
            "port":     cw.get("port",     2222),
            "username": cw.get("username", "root"),
            "password": cw.get("password", "root"),
        },
        on_device  = {
            "enabled":      od.get("enabled",      True),
            "model":        od.get("model",        "Qwen/Qwen2.5-1.5B-Instruct"),
            "quantization": od.get("quantization", "4bit"),
            "gguf_file":    od.get("gguf_file",    ""),
            "temperature":  od.get("temperature",  0.7),
            "max_tokens":   od.get("max_tokens",   256),
            "do_sample":    od.get("do_sample",    True),
        },
        cloud      = _cloud_dict_with_base_url(cl),
        # PRESERVE existing system_state/logging/routing.fallback/
        # static_commands/fi_routing across re-runs — none of these should
        # ever get silently reset
        existing_system_state    = existing.get("system_state"),
        existing_logging          = existing.get("logging"),
        existing_fallback         = existing.get("routing", {}).get("fallback"),
        existing_static_commands  = existing.get("static_commands"),
        existing_fi_routing       = existing.get("routing", {}).get("fi_routing"),
    )


def _cloud_dict_with_base_url(cl: dict) -> dict:
    """Build the cloud agent dict, preserving base_url if it was already set
    — base_url has no interactive prompt of its own (only review_and_edit's
    per-field editor sets it), so it must be carried through here or `hp init`
    silently drops it back to agents.py's hardcoded fallback URL."""
    d = {
        "enabled":     cl.get("enabled",     False),
        "provider":    cl.get("provider",    "openai"),
        "model":       cl.get("model",       "gpt-4o-mini"),
        "api_key_env": cl.get("api_key_env", "OPENAI_API_KEY"),
        "temperature": cl.get("temperature", 0.3),
        "max_tokens":  cl.get("max_tokens",  512),
    }
    if "base_url" in cl:
        d["base_url"] = cl["base_url"]
    return d

# help
def _print(text: str, style: str = ""):
    if console:
        console.print(text, style=style)
    else:
        print(text)

def _prompt(text: str, default: str = "") -> str:
    """Single-line text input. Type 'b' to go back."""
    answer = questionary.text(
        f"{text} (b=back)",
        default=str(default),
        style=WIZARD_STYLE,
    ).ask()
    if answer is None:
        return default
    if answer.strip().lower() in ("b", "back"):
        raise GoBack()
    return answer if answer else default


def _choice(text: str, options: list[tuple[str, str]], default: int = 1,
            allow_back: bool = True) -> int:
    
    all_options = [(label, desc) for label, desc in options]
    if allow_back:
        all_options.append(("← Go back", ""))
    
    idx = default - 1
    n = len(all_options)

    def render():
        sys.stdout.write(f"\n\033[93m?\033[0m \033[1m{text}\033[0m  \033[90m(↑/↓ arrows, Enter to select)\033[0m\n")
        for i, (label, desc) in enumerate(all_options):
            if i == idx:
                sys.stdout.write(f"  \033[93m» {label}  {desc}\033[0m\n")
            else:
                sys.stdout.write(f"    {label}  \033[90m{desc}\033[0m\n")
        sys.stdout.flush()

    def clear(n_lines):
        for _ in range(n_lines + 1):
            sys.stdout.write("\033[A\033[2K")
        sys.stdout.flush()

    render()
    while True:
        key = readchar.readkey()
        if key == readchar.key.UP:
            idx = (idx - 1) % n
        elif key == readchar.key.DOWN:
            idx = (idx + 1) % n
        elif key in (readchar.key.ENTER, "\r", "\n"):
            clear(n + 1)
            if allow_back and idx == n - 1:
                raise GoBack()
            return idx + 1
        elif key in ("b", "B") and allow_back:
            clear(n + 1)
            raise GoBack()
        clear(n + 1)
        render()


def _confirm(text: str, default: bool = True) -> bool:
    """Yes/no, defaults to the highlighted option."""
    answer = questionary.confirm(text, default=default, style=WIZARD_STYLE).ask()
    return answer if answer is not None else default

# ─── Welcome Banner ──────────────────────────────────────────────────────────

_HYDRAPOT_LOGO = r"""
██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ██████╗  ██████╗ ████████╗
██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
███████║ ╚████╔╝ ██║  ██║██████╔╝███████║██████╔╝██║   ██║   ██║
██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║██╔═══╝ ██║   ██║   ██║
██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║     ╚██████╔╝   ██║
╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝    ╚═╝
"""

# tiny pixel-art squid — no emoji, built from block/box-drawing characters.
# Sits to the LEFT of the wordmark (both rendered as one banner), body still
# while the tentacles wiggle, same spirit as Claude Code's animated intro glyph.
# Every row is 9 cells wide and the eye row is a palindrome, so the face
# can't drift off-centre (the old 5-wide "█▄█▄█" put an eye on one side of
# the middle column and a solid block on the other, which read as lopsided).
_SQUID_BODY = [
    " ▄█████▄ ",
    " █▀███▀█ ",
    " ███████ ",
]
_SQUID_TENTACLES = {
    "straight": " │ │ │ │ ",
    "left":     " ╲ │ │ ╱ ",
    "right":    " ╱ │ │ ╲ ",
}
_SQUID_SEQUENCE = ["straight", "left", "straight", "right"]


def _squid_frame(variant: str) -> str:
    """Just the squid, for the solo intro before the wordmark appears."""
    return "\n".join(_SQUID_BODY + [_SQUID_TENTACLES[variant]])


def _banner_frame(variant: str) -> str:
    """Squid beside the HYDRAPOT wordmark, squid vertically centred against it."""
    squid = _SQUID_BODY + [_SQUID_TENTACLES[variant]]
    logo  = _HYDRAPOT_LOGO.strip("\n").splitlines()
    sw    = max(len(s) for s in squid)
    lw    = max(len(l) for l in logo)
    pad   = max(0, (len(logo) - len(squid)) // 2)
    squid = [""] * pad + squid
    squid += [""] * (len(logo) - len(squid))
    # BOTH columns padded to a fixed width: rich centres each line on its own,
    # so ragged line lengths made the wordmark rows drift sideways.
    return "\n".join(f"{s:<{sw}} {l:<{lw}}" for s, l in zip(squid, logo))


def _play_squid_intro(loops: int = 2):
    """Two beats: the squid wiggles on its own, then the wordmark joins it.

    Phase 1 is transient (Live clears it), so the squid appears to swim in
    place and then slide into the finished banner rather than being drawn
    twice."""
    if not console:
        return
    from rich.live import Live
    from rich.align import Align
    banner = Text(_banner_frame("straight"), style="bold #F59E0B")
    try:
        with Live(console=console, refresh_per_second=14, transient=True) as live:
            for _ in range(loops):
                for variant in _SQUID_SEQUENCE:
                    live.update(Align.center(Text(_squid_frame(variant), style="bold #F59E0B")))
                    time.sleep(0.16)
        console.print(banner, justify="center")
    except Exception:
        # cosmetic only — never let a terminal quirk block the wizard
        console.print(banner, justify="center")


def show_welcome():
    if console:
        _play_squid_intro()
        subtitle = Text()
        subtitle.append("  An Intelligent Honeypot Framework Using Large Language\n", style="")
        subtitle.append("  Models for Interactive Attack Analysis\n\n", style="")
        subtitle.append("  by Kamolchanok Saengtong\n", style="dim italic")
        console.print(Panel(subtitle, border_style="#F59E0B", box=box.DOUBLE_EDGE,
                            width=68, padding=(0, 2)))
    else:
        print("=" * 68)
        print(_banner_frame("straight"))
        print("  An Intelligent Honeypot Framework Using Large Language")
        print("  Models for Interactive Attack Analysis")
        print("")
        print("  by Kamolchanok Saengtong")
        print("=" * 68)

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
        "instance_name": hp.get("instance_name", "default"),
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

    enable = _confirm("[5] Enable Cowrie agent?", default=cw.get("enabled", True))
    if not enable:
        _print("  → Cowrie disabled — HoneyRouter will never route to it.", style="yellow")
        return {
            "enabled": False,
            "host": cw.get("host", "127.0.0.1"),
            "port": cw.get("port", 2222),
            "username": cw.get("username", "root"),
            "password": cw.get("password", "root"),
        }

    host     = _prompt("[6] Cowrie host",     cw.get("host", "127.0.0.1"))
    port     = int(_prompt("[7] Cowrie port", str(cw.get("port", 2222))))
    username = _prompt("[8] Cowrie username",  cw.get("username", "root"))
    password = _prompt("[9] Cowrie password",  cw.get("password", "root"))

    return {
        "enabled": True,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
    }


# models that are used internally by the framework, not for chat
_INTERNAL_MODELS = {"roberta-large"}

def _scan_cached_models() -> list[str]:
    """Scan ~/.cache/huggingface/hub/ and return downloaded chat model IDs."""
    cache = os.path.expanduser("~/.cache/huggingface/hub/")
    models = []
    try:
        for folder in os.listdir(cache):
            if not folder.startswith("models--"):
                continue

            name = folder[len("models--"):]
            name = name.replace("--", "/", 1)

            # skip internal/evaluation models
            if name in _INTERNAL_MODELS:
                continue

            # skip if no actual model files downloaded yet
            folder_path = os.path.join(cache, folder)
            has_files = any(
                f.endswith((".gguf", ".safetensors", ".bin"))
                for root, _, files in os.walk(folder_path)
                for f in files
            )
            if not has_files:
                continue

            models.append(name)
    except FileNotFoundError:
        pass
    return sorted(models)


def _is_cached(model_id: str) -> bool:
    """Check if a model is fully downloaded (no incomplete files)."""
    folder = "models--" + model_id.replace("/", "--")
    cache  = os.path.expanduser("~/.cache/huggingface/hub/")
    folder_path = os.path.join(cache, folder)

    if not os.path.isdir(folder_path):
        return False

    has_model_files   = False
    has_incomplete    = False

    for root, _, files in os.walk(folder_path):
        for f in files:
            if f.endswith((".gguf", ".safetensors", ".bin")):
                has_model_files = True
            if f.endswith(".incomplete") or f.endswith(".part"):
                has_incomplete = True

    return has_model_files and not has_incomplete


def _is_gguf(model_id: str) -> bool:
    """Check if a model ID looks like a GGUF repo."""
    return "gguf" in model_id.lower()


def _list_remote_gguf_files(model_id: str) -> list[tuple[str, int]]:
    """
    Query the HF Hub for the actual .gguf files in this repo (no download) —
    (filename, size_in_bytes) pairs, size 0 if the API didn't report one.
    Returns [] if the repo can't be reached/listed (caller falls back).
    """
    try:
        from huggingface_hub import HfApi
        info = HfApi().model_info(model_id, files_metadata=True)
        return [
            (s.rfilename, s.size or 0)
            for s in info.siblings
            if s.rfilename.lower().endswith(".gguf")
        ]
    except Exception as e:
        _print(f"  (couldn't list repo files: {e})", style="dim")
        return []


def _ask_gguf_filter(model_id: str) -> str | None:
    """
    Ask the user which GGUF file they want. Returns an exact filename (never
    a fuzzy pattern) or None to download all variants.

    Repos like Unsloth's mix TWO naming schemes for overlapping bit-widths —
    e.g. both 'Qwen3.5-9B-Q6_K.gguf' AND 'Qwen3.5-9B-UD-Q6_K_XL.gguf' exist
    side by side. A substring filter like '*Q6_K*' matches BOTH (16GB+
    instead of the ~7-9GB you meant to get), so this lists the REAL files in
    the repo and has the user pick the exact one — no ambiguity possible.
    """
    _print("\n  This is a GGUF repo — it contains many quant variants.", style="yellow")
    _print("  Downloading all variants can be 20GB+.", style="dim")

    files = sorted(_list_remote_gguf_files(model_id))
    if files:
        choices = [(name, f"({size / 1e9:.2f} GB)" if size else "") for name, size in files]
        choices.append(("All variants", "(download everything — slow!)"))
        idx = _choice(f"Which file do you want? ({len(files)} found in repo)",
                      choices, default=1)
        if idx == len(choices):
            return None
        return files[idx - 1][0]   # exact filename — unambiguous download

    # ── fallback: couldn't list remote files (offline, gated repo, etc.) ──
    _print("  Falling back to a generic quant picker — this may match more", style="dim")
    _print("  than one file if the repo mixes naming styles.", style="dim")
    common = [
        ("Q2_K", "(~2-bit — smallest, lowest quality)"),
        ("Q4_K", "(~4-bit — recommended, best balance of size/quality)"),
        ("Q5_K", "(~5-bit — higher quality, larger)"),
        ("Q6_K", "(~6-bit — near full quality)"),
        ("Q8_0", "(~8-bit — near full quality, largest common quant)"),
        ("F16",  "(~16-bit — full precision, huge)"),
        ("All variants", "(download everything — slow!)"),
    ]
    idx = _choice("Which quant variant do you want?", common, default=2)
    if idx == len(common):
        return None  # download all
    return common[idx - 1][0]   # e.g. "Q6_K" — still a substring pattern in this fallback


def _download_model(model_id: str) -> bool:
    """
    Download a model from HuggingFace inside the wizard.
    Handles GGUF repos by asking which quant variant to download.
    Returns True if successful, False if failed.
    """
    _print(f"\n  Downloading {model_id} from HuggingFace...", style="bold yellow")
    _print("  This may take a while depending on model size.\n", style="dim")

    try:
        from huggingface_hub import snapshot_download

        kwargs = {"repo_id": model_id}

        # ── GGUF: ask which variant to download ───────────────────────────
        if _is_gguf(model_id):
            variant = _ask_gguf_filter(model_id)
            if variant:
                # exact filename (the normal case, from the real repo listing)
                # downloads precisely that one file; a bare quant token (only
                # reached via the offline fallback picker) still needs the
                # substring wildcard.
                pattern = variant if variant.lower().endswith(".gguf") else f"*{variant}*"
                kwargs["allow_patterns"] = [pattern, "*.json", "*.md"]
                _print(f"\n  Downloading {variant} only...", style="dim")
            else:
                _print(f"\n  Downloading all variants...", style="dim")

        snapshot_download(**kwargs)
        _print(f"\n  ✓ Download complete!", style="bold green")
        return True

    except Exception as e:
        _print(f"\n  ✗ Download failed: {e}", style="bold red")
        _print("  Check the model name is correct and you have internet access.", style="yellow")
        return False


def _resolve_gguf_file(model_id: str, current: str = "") -> str:
    """
    Figure out which cached .gguf file to record as agents.on_device.gguf_file
    for this repo — discovered dynamically from what's actually on disk, never
    hardcoded to one filename/naming scheme.

    - 0 files cached yet  -> "" (nothing to pick; ondevice_agent will error
      clearly at load time if this model turns out not to be GGUF-compatible)
    - 1 file cached       -> that file, no prompt needed
    - 2+ files cached     -> ask which one to load (this is exactly the
      ambiguity `_find_gguf_file()` used to resolve by silently taking
      whichever glob() listed first)
    """
    if not _is_gguf(model_id):
        return ""

    from agent_manager.ondevice_agent import _list_gguf_files
    files = [os.path.basename(f) for f in _list_gguf_files(model_id)]
    if not files:
        return ""
    if len(files) == 1:
        return files[0]

    choices = [(f, "") for f in files]
    default = files.index(current) + 1 if current in files else 1
    idx = _choice("  Multiple quant files cached for this model — which one to load?",
                  choices, default=default)
    return files[idx - 1]

def ask_on_device(existing: dict) -> dict:
    """Section 4: On-device LLM."""
    od = existing.get("agents", {}).get("on_device", {})

    _print("\n─── On-Device LLM ───", style="bold cyan")
    _print("  Local model for version queries, scripts, and context-aware responses.", style="dim")

    cached = _scan_cached_models()
    model_choices = [(m, "(cached ✓)") for m in cached]
    model_choices.append(("Custom model", "(enter HuggingFace model name)"))
    model_choices.append(("None — disable", "(cowrie + cloud only)"))

    custom_idx  = len(cached) + 1
    disable_idx = len(cached) + 2

    current_model = od.get("model", "")
    model_default = 1
    for i, m in enumerate(cached, 1):
        if m == current_model:
            model_default = i
            break
    if not od.get("enabled", True):
        model_default = disable_idx

    model_idx = _choice("[9] On-device LLM", model_choices, default=model_default)

    if model_idx == disable_idx:
        return {"enabled": False, "model": "", "quantization": "4bit", "gguf_file": "",
                "temperature": 0.7, "max_tokens": 256, "do_sample": True}

    if model_idx == custom_idx:
        while True:
            model = _prompt("  Enter HuggingFace model name (e.g. Qwen/Qwen2.5-3B-Instruct)",
                            current_model)
            if _is_cached(model):
                _print(f"  ✓ Already cached — no download needed.", style="green")
                break
            else:
                _print(f"  Model not found in cache.", style="yellow")
                if _confirm(f"  Download {model} now?", default=True):
                    if _download_model(model):
                        break
                    if not _confirm("  Try a different model name?", default=True):
                        raise GoBack()
                else:
                    if not _confirm("  Pick a different model?", default=True):
                        raise GoBack()
    else:
        model = cached[model_idx - 1]

    gguf_file = _resolve_gguf_file(model, od.get("gguf_file", ""))

    if _is_gguf(model):
        # For GGUF models the bit-depth is whatever the .gguf FILE already is
        # (Q2/Q4/Q5/Q6/Q8/F16/... — picked above) — ondevice_agent.py's GGUF
        # loader never reads `quantization` at all, only _load_transformers()
        # does. Asking 4-bit/8-bit/None here would be a second, unused
        # quantization question, so skip it and just keep whatever value was
        # already on record (harmless — never consumed on this path).
        _print(f"  [10] Quantization: determined by the GGUF file you picked "
               f"({gguf_file or 'auto'}) — nothing more to choose here.", style="dim")
        quantization = od.get("quantization", "4bit")
    else:
        # bitsandbytes (the library behind this path) only implements 4-bit
        # and 8-bit quantization — there is no 6-bit/2-bit option to add here,
        # that's a hard limitation of bitsandbytes itself, not this wizard.
        quant_choices = [
            ("4-bit", "(fastest, least RAM)"),
            ("8-bit", "(balanced)"),
            ("None",  "(full precision — needs lots of RAM)"),
        ]
        quant_map     = {1: "4bit", 2: "8bit", 3: "none"}
        current_quant = od.get("quantization", "4bit")
        quant_default = {v: k for k, v in quant_map.items()}.get(current_quant, 1)

        quant_idx = _choice("[10] Quantization", quant_choices, default=quant_default)
        quantization = quant_map[quant_idx]

    temperature = float(_prompt("[11] Temperature", str(od.get("temperature", 0.7))))
    max_tokens  = int(_prompt("[12] Max tokens",   str(od.get("max_tokens", 256))))

    return {
        "enabled":      True,
        "model":        model,
        "quantization": quantization,
        "gguf_file":    gguf_file,
        "temperature":  temperature,
        "max_tokens":   max_tokens,
        "do_sample":    True,
    }


def ask_cloud(existing: dict) -> dict:
    """Section 5: Cloud LLM."""
    cl = existing.get("agents", {}).get("cloud", {})

    _print("\n─── Cloud LLM ───", style="bold cyan")
    _print("  API-based model for high-impact / obfuscated attack commands.", style="dim")

    enable = _confirm("[13] Enable cloud LLM?", default=cl.get("enabled", False))

    if not enable:
        d = {
            "enabled": False,
            "provider": cl.get("provider", "openai"),
            "model": cl.get("model", "gpt-4o-mini"),
            "api_key_env": cl.get("api_key_env", "OPENAI_API_KEY"),
            "temperature": cl.get("temperature", 0.3),
            "max_tokens": cl.get("max_tokens", 512),
        }
        if "base_url" in cl:
            d["base_url"] = cl["base_url"]
        return d

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
    base_url    = _prompt("[17] API base URL (blank = ai.psu.blue proxy default — "
                          "e.g. https://api.deepseek.com for DeepSeek's own API)",
                          cl.get("base_url", ""))
    temperature = float(_prompt("[18] Temperature",   str(cl.get("temperature", 0.3))))
    max_tokens  = int(_prompt("[19] Max tokens",      str(cl.get("max_tokens", 512))))

    # check if the env var is actually set
    if not os.environ.get(api_key_env):
        _print(f"\n  ⚠️  Environment variable '{api_key_env}' is not set.", style="yellow")
        _print(f"  Set it before running: export {api_key_env}=sk-...", style="dim")

    d = {
        "enabled": True,
        "provider": provider,
        "model": model,
        "api_key_env": api_key_env,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if base_url.strip():
        d["base_url"] = base_url.strip()
    return d


# ─── Build final config dict ─────────────────────────────────────────────────

DEFAULT_LOGGING = {
    "session_dir":   "data/logs/sessions",
    "impactful_dir": "data/logs/impactful",
    "auth_log":      "data/logs/auth_log.json",
    "fi_threshold":  2,
}

DEFAULT_STATIC_COMMANDS = [
    "nmap", "ping", "traceroute", "tracepath",
    "top", "htop", "watch", "tail",
    "vim", "vi", "nano", "emacs",
    "less", "more",
]


# capability rank, weakest to strongest — same ranking router.py uses at
# runtime for its own fallback logic. Kept in sync intentionally: both are
# "cowrie is the simplest agent, cloud is the most capable" statements.
_AGENT_RANK = {"cowrie": 0, "on_device": 1, "cloud": 2}


def _default_fi_routing(cowrie_enabled: bool, on_device_enabled: bool, cloud_enabled: bool) -> dict:
    """
    Today's designed default (see project notes), generalized by how many
    agents are actually enabled — always just a STARTING template; classify()
    in router.py reads whatever ends up in config.yaml, hand-edited or not.
      1 agent enabled  -> every FI band routes to that one agent
      2 agents enabled -> bottom 2 bands (0-1) to the weaker agent,
                          top 3 bands (2-4) to the stronger one
      3 agents enabled -> 0-1 cowrie, 2-4 on_device (cloud stays purely
                          obfuscation-triggered, no FI band maps to it here)
    """
    enabled = [a for a, on in (("cowrie", cowrie_enabled),
                                ("on_device", on_device_enabled),
                                ("cloud", cloud_enabled)) if on]
    if not enabled:
        enabled = ["cowrie"]   # never leave routing with nowhere to go

    if len(enabled) == 1:
        agent = enabled[0]
        return {i: agent for i in range(5)}

    if len(enabled) == 2:
        weak, strong = sorted(enabled, key=lambda a: _AGENT_RANK[a])
        return {0: weak, 1: weak, 2: strong, 3: strong, 4: strong}

    return {0: "cowrie", 1: "cowrie", 2: "on_device", 3: "on_device", 4: "on_device"}


def build_config(honeypot: dict, deployment: dict, cowrie: dict,
                 on_device: dict, cloud: dict,
                 existing_system_state: dict | None = None,
                 existing_logging: dict | None = None,
                 existing_fallback: str | None = None,
                 existing_static_commands: list | None = None,
                 existing_fi_routing: dict | None = None) -> dict:
    """
    Assemble all answers into a single config dict for YAML output.

    system_state (base_tools / starting_files), logging, routing.fallback,
    static_commands, AND routing.fi_routing are all PRESERVED from the
    existing config when present — the wizard never regenerates or wipes
    hand-edited values. Only a brand-new config (nothing existing yet), or
    an fi_routing table that references an agent you just disabled, gets a
    freshly generated default (see _default_fi_routing) — with a printed
    note explaining why, since that changes HydraPoT's behavior.
    """
    enabled_now = {a for a, c in (("cowrie", cowrie), ("on_device", on_device), ("cloud", cloud))
                   if c["enabled"]}

    existing_fi_agents = set(existing_fi_routing.values()) if existing_fi_routing else set()
    if existing_fi_routing and existing_fi_agents.issubset(enabled_now):
        fi_routing = existing_fi_routing
    else:
        fi_routing = _default_fi_routing(cowrie["enabled"], on_device["enabled"], cloud["enabled"])
        if existing_fi_routing:
            _print(
                "\n  ℹ️  Routing table regenerated for your current agent selection "
                f"({', '.join(sorted(enabled_now)) or 'none'}) — the previous FI-band "
                "mapping referenced an agent you just disabled. You can hand-edit "
                "config.yaml's routing.fi_routing afterward to anything you want — "
                "just know that different agent combinations change HydraPoT's "
                "behavior and performance characteristics.",
                style="yellow",
            )

    return {
        "honeypot": {
            "hostname":      honeypot["hostname"],
            "instance_name": honeypot.get("instance_name", "default"),
            "os":            honeypot["os"],
            "host":          deployment["host"],
            "port":          honeypot["port"],
        },
        "agents": {
            "cowrie":    cowrie,
            "on_device": on_device,
            "cloud":     cloud,
        },
        "routing": {
            "fallback": existing_fallback or "cowrie",
            "fi_routing": fi_routing,
        },
        "static_commands": existing_static_commands or DEFAULT_STATIC_COMMANDS,
        "logging": existing_logging or DEFAULT_LOGGING,
        # PRESERVE existing system_state; only fall back to the default template
        # for a brand-new config. Never overwrite hand-edited base_tools.
        "system_state": existing_system_state or DEFAULT_SYSTEM_STATE,
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
                from dashboard import app as dash_app
                dash_app.run(host="127.0.0.1", port=8050, debug=False)
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


def review_and_edit(config: dict) -> dict:
    """Show the config, let the user edit any field, then return the final dict."""
    while True:
        hp = config["honeypot"]
        cw = config["agents"]["cowrie"]
        od = config["agents"]["on_device"]
        cl = config["agents"]["cloud"]

        # build the editable list. each entry: (label, current_value, edit_fn)
        items = [
            ("Hostname",            hp["hostname"],
                lambda c: c["honeypot"].update({"hostname": _prompt("New hostname", c["honeypot"]["hostname"])})),
            ("OS",                  hp["os"],
                lambda c: c["honeypot"].update({"os": _edit_os(c["honeypot"]["os"])})),
            ("Bind address",        f"{hp['host']}:{hp['port']}",
                lambda c: _edit_bind(c)),
            ("Cowrie host:port",    f"{cw['host']}:{cw['port']}",
                lambda c: _edit_cowrie_addr(c)),
            ("Cowrie credentials",  f"{cw['username']} / {cw['password']}",
                lambda c: _edit_cowrie_creds(c)),
            ("On-device model",     od["model"] if od["enabled"] else "disabled",
                lambda c: _edit_ondevice_model(c)),
            ("On-device quant",     od["quantization"] if od["enabled"] else "—",
                lambda c: _edit_ondevice_quant(c)),
            ("On-device temp",      str(od["temperature"]) if od["enabled"] else "—",
                lambda c: c["agents"]["on_device"].update(
                    {"temperature": float(_prompt("Temperature", str(c["agents"]["on_device"]["temperature"])))})),
            ("On-device max_tok",   str(od["max_tokens"]) if od["enabled"] else "—",
                lambda c: c["agents"]["on_device"].update(
                    {"max_tokens": int(_prompt("Max tokens", str(c["agents"]["on_device"]["max_tokens"])))})),
            ("Cloud LLM",           f"{cl['provider']} / {cl['model']}" if cl["enabled"] else "disabled",
                lambda c: _edit_cloud(c)),
            ("Cloud base_url",      cl.get("base_url", "(default)") if cl["enabled"] else "—",
                lambda c: c["agents"]["cloud"].update(
                    {"base_url": _prompt("Cloud base URL",
                        c["agents"]["cloud"].get("base_url", "https://ai.psu.blue/v1"))})),
            ("Cloud temperature",   str(cl["temperature"]) if cl["enabled"] else "—",
                lambda c: c["agents"]["cloud"].update(
                    {"temperature": float(_prompt("Cloud temperature",
                        str(c["agents"]["cloud"]["temperature"])))})),
            ("Cloud max_tokens",    str(cl["max_tokens"]) if cl["enabled"] else "—",
                lambda c: c["agents"]["cloud"].update(
                    {"max_tokens": int(_prompt("Cloud max tokens",
                        str(c["agents"]["cloud"]["max_tokens"])))})),
        ]

        # render
        if console:
            table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
            table.add_column("#",     style="bold cyan", width=3)
            table.add_column("Setting", style="white")
            table.add_column("Value", style="yellow")
            for i, (label, value, _) in enumerate(items, 1):
                table.add_row(str(i), label, str(value))
            console.print(Panel(table, title="[bold]Review Configuration[/bold]",
                                border_style="cyan", width=70))
            # show plugin summary
            plugin_dir = "plugins/rules"
            if os.path.isdir(plugin_dir):
                rule_files = [f for f in os.listdir(plugin_dir) if f.endswith((".yaml", ".yml"))]
                if rule_files:
                    names = [f.replace(".yaml", "").replace(".yml", "").replace("_", " ") for f in rule_files]
                    _print(f"  📦 Plugins: {len(rule_files)} rule(s) loaded ({', '.join(names)})", style="dim")
            export_dir = "plugins/export"
            if os.path.isdir(export_dir):
                export_files = [f for f in os.listdir(export_dir) if f.endswith((".yaml", ".yml"))]
                if export_files:
                    _print(f"  📤 Exporters: {len(export_files)} configured (edit in plugins/export/)", style="dim")

            _print("  Type a number to edit, or 's' to save and continue.\n", style="dim")
        else:
            print("\n── Review Configuration ──")
            for i, (label, value, _) in enumerate(items, 1):
                print(f"  {i:>2}) {label:<22} {value}")
            print("\n  Type a number to edit, or 's' to save and continue.\n")

        choice = input("  > ").strip().lower()

        if choice in ("s", "save", ""):
            return config

        try:
            idx = int(choice)
            if 1 <= idx <= len(items):
                _, _, edit_fn = items[idx - 1]

                # ── NEW: catch GoBack so it cancels just this edit ───────
                try:
                    edit_fn(config)
                except GoBack:
                    _print("  ← Edit cancelled.", style="dim")
                    continue   # back to the review screen

                # also re-run build_config to make sure routing/etc stays
                # consistent — PRESERVING system_state/logging/fallback/
                # static_commands/base_tools from the in-progress config.
                config = build_config(
                    honeypot   = {**config["honeypot"]},
                    deployment = {"host": config["honeypot"]["host"]},
                    cowrie     = config["agents"]["cowrie"],
                    on_device  = config["agents"]["on_device"],
                    cloud      = config["agents"]["cloud"],
                    existing_system_state    = config.get("system_state"),
                    existing_logging          = config.get("logging"),
                    existing_fallback         = config.get("routing", {}).get("fallback"),
                    existing_static_commands  = config.get("static_commands"),
                    existing_fi_routing       = config.get("routing", {}).get("fi_routing"),
                )
                continue
        except ValueError:
            pass

        _print("  Invalid choice. Type a number or 's'.", style="red")

def _edit_os(current: str) -> str:
    os_choices = [
        ("Ubuntu 12.04 LTS", "(CVE-rich, attacker-attractive)"),
        ("Ubuntu 22.04 LTS", "(modern)"),
        ("Debian 11",        "(stable)"),
        ("CentOS 7",         "(enterprise)"),
    ]
    default = next((i for i, (l, _) in enumerate(os_choices, 1) if l == current), 1)
    idx = _choice("Pick OS", os_choices, default=default)
    return os_choices[idx - 1][0]


def _edit_bind(c: dict):
    deploy_choices = [
        ("Localhost (127.0.0.1)", "(safest)"),
        ("LAN (0.0.0.0)",         "(network-exposed)"),
        ("Custom IP",             ""),
    ]
    idx = _choice("Bind address", deploy_choices, default=1)
    if idx == 1:
        c["honeypot"]["host"] = "127.0.0.1"
    elif idx == 2:
        c["honeypot"]["host"] = "0.0.0.0"
    else:
        c["honeypot"]["host"] = _prompt("Custom IP", c["honeypot"]["host"])
    c["honeypot"]["port"] = int(_prompt("Honeypot port", str(c["honeypot"]["port"])))


def _edit_cowrie_addr(c: dict):
    c["agents"]["cowrie"]["host"] = _prompt("Cowrie host", c["agents"]["cowrie"]["host"])
    c["agents"]["cowrie"]["port"] = int(_prompt("Cowrie port", str(c["agents"]["cowrie"]["port"])))


def _edit_cowrie_creds(c: dict):
    c["agents"]["cowrie"]["username"] = _prompt("Cowrie username", c["agents"]["cowrie"]["username"])
    c["agents"]["cowrie"]["password"] = _prompt("Cowrie password", c["agents"]["cowrie"]["password"])


def _edit_ondevice_model(c: dict):
    cached = _scan_cached_models()
    model_choices = [(m, "(cached ✓)") for m in cached]
    model_choices.append(("Custom", "(enter HuggingFace name)"))
    model_choices.append(("Disable", ""))

    custom_idx  = len(cached) + 1
    disable_idx = len(cached) + 2

    idx = _choice("On-device model", model_choices, default=1)
    od  = c["agents"]["on_device"]

    if idx == disable_idx:
        od["enabled"]   = False
        od["gguf_file"] = ""
    elif idx == custom_idx:
        od["enabled"] = True
        while True:
            model = _prompt("HuggingFace model", od.get("model", ""))
            if _is_cached(model):
                _print("  ✓ Already cached — no download needed.", style="green")
                od["model"] = model
                break
            else:
                _print("  Model not found in cache.", style="yellow")
                if _confirm(f"  Download {model} now?", default=True):
                    if _download_model(model):
                        od["model"] = model
                        break
                    if not _confirm("  Try a different model name?", default=True):
                        raise GoBack()
                else:
                    if not _confirm("  Pick a different model?", default=True):
                        raise GoBack()
        od["gguf_file"] = _resolve_gguf_file(od["model"], od.get("gguf_file", ""))
    else:
        od["enabled"] = True
        od["model"]   = cached[idx - 1]
        od["gguf_file"] = _resolve_gguf_file(od["model"], od.get("gguf_file", ""))


def _edit_ondevice_quant(c: dict):
    quant_choices = [("4-bit", "(fastest)"), ("8-bit", "(balanced)"), ("None", "(full precision)")]
    quant_map = {1: "4bit", 2: "8bit", 3: "none"}
    idx = _choice("Quantization", quant_choices, default=1)
    c["agents"]["on_device"]["quantization"] = quant_map[idx]


def _edit_cloud(c: dict):
    cl = c["agents"]["cloud"]
    if not _confirm("Enable cloud LLM?", default=cl["enabled"]):
        cl["enabled"] = False
        return
    cl["enabled"]     = True
    cl["provider"]    = _prompt("Provider",     cl["provider"])
    cl["model"]       = _prompt("Model",        cl["model"])
    cl["api_key_env"] = _prompt("API key env",  cl["api_key_env"])

# ─── Main wizard flow ────────────────────────────────────────────────────────
def run_wizard():
    while True:
        show_welcome()
        existing = load_existing()

        # mode selection — back from here just re-shows welcome
        mode_choices = [
            ("Quick setup",  "(use defaults template)"),
            ("Custom setup", "(answer each question)"),
        ]
        try:
            mode = _choice("How would you like to configure?", mode_choices,
                           default=1, allow_back=False)
        except GoBack:
            continue   # shouldn't happen since allow_back=False, but safe

        if mode == 1:
            config_dict = build_default_config(existing)
        else:
            # custom mode: walk through sections, allow GoBack to step back
            steps = [
                ("honeypot",   ask_honeypot),
                ("deployment", ask_deployment),
                ("cowrie",     ask_cowrie),
                ("on_device",  ask_on_device),
                ("cloud",      ask_cloud),
            ]

            answers = {}
            i = 0
            while i < len(steps):
                name, fn = steps[i]
                try:
                    answers[name] = fn(existing)
                    i += 1
                except GoBack:
                    if i == 0:
                        _print("  ← Already at the first section.", style="yellow")
                    else:
                        i -= 1
                        _print(f"  ← Going back to '{steps[i][0]}'", style="yellow")

            config_dict = build_config(
                answers["honeypot"], answers["deployment"], answers["cowrie"],
                answers["on_device"], answers["cloud"],
                # PRESERVE existing system_state/logging/routing.fallback/
                # static_commands/fi_routing across re-runs — never silently reset
                existing_system_state    = existing.get("system_state"),
                existing_logging          = existing.get("logging"),
                existing_fallback         = existing.get("routing", {}).get("fallback"),
                existing_static_commands  = existing.get("static_commands"),
                existing_fi_routing       = existing.get("routing", {}).get("fi_routing"),
            )

        # review screen catches GoBack too — just loops back into review
        try:
            config_dict = review_and_edit(config_dict)
        except GoBack:
            pass

        # final safety net: carry over any top-level key build_config() doesn't
        # know about at all (a future custom section, a plugin's own config
        # block, etc.) so hp init can never silently drop something it has no
        # idea exists — only the keys build_config() explicitly produces get
        # regenerated; everything else passes through untouched.
        for key, value in existing.items():
            config_dict.setdefault(key, value)

        save_config(config_dict)
        show_summary(config_dict)

        result = what_now_menu()
        if result == "rerun":
            print("\n" * 2)
            continue
        break
# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        run_wizard()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled. No changes written.")
        sys.exit(1)