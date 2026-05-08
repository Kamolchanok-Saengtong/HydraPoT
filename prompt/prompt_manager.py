"""
Prompt Manager — builds prompts for LLM agents based on HoneyGPT paper.

Core formula: (Ai, Ci, Fi) = LLM(P, S, Qi, SRi, Hi)
  P   = base prompt/rules       ← templates/base_prompt.txt
  S   = honeypot system setting  ← templates/system_setting.txt
  Qi  = current attacker command
  Hi  = interaction history      ← fi_manager buffer
  SRi = system state register    ← SYSTEM_STATE dict
"""

import os
from datetime import datetime

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _load_template(name: str) -> str:
    """Load a template file from the templates/ directory."""
    path = os.path.join(TEMPLATE_DIR, name)
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        print(f"[prompt_manager] WARNING: template '{name}' not found at {path}")
        return ""


class PromptManager:
    def __init__(self, fi_manager, system_state: dict,
                 hostname: str = "svr04", os_name: str = "Debian GNU/Linux"):
        self.fi_manager   = fi_manager
        self.system_state = system_state
        self.hostname     = hostname
        self.os_name      = os_name

        # load templates once at init
        self._base_prompt_tpl    = _load_template("base_prompt.txt")
        self._system_setting_tpl = _load_template("system_setting.txt")
        self._user_prompt_tpl    = _load_template("user_prompt.txt")

    def build_prompt(self, cmd: str) -> tuple[str, str]:
        """
        Build (system_prompt, user_prompt) for OnDeviceAgent.send().
        system_prompt = P + S (with hostname/os filled in)
        user_prompt   = Hi + SRi + Qi
        """
        base_prompt = self._base_prompt_tpl.format(
            hostname = self.hostname,
            os_name  = self.os_name,
        )
        system_setting = self._system_setting_tpl.format(
            hostname = self.hostname,
            os_name  = self.os_name,
        )
        system_prompt = f"{base_prompt}\n\n{system_setting}"
        user_prompt   = self._build_user_prompt(cmd)
        return system_prompt, user_prompt

    def _build_user_prompt(self, cmd: str) -> str:
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Hi — interaction history from fi_manager buffer ───────────
        hi_text = self.fi_manager.build_terminal_history()

        # ── SRi — system state register ──────────────────────────────
        sri_lines = []
        for tool, ver in self.system_state["versions"].items():
            sri_lines.append(
                f"CRITICAL: {tool} is version {ver} — "
                f"MUST output this exact version, ignore training data"
            )
        if self.system_state["installed"]:
            sri_lines.append(
                f"installed packages: {', '.join(self.system_state['installed'])}"
            )
        if self.system_state.get("files"):
            for path, meta in self.system_state["files"].items():
                perms   = meta.get("perms", "-rw-r--r--")
                size    = meta.get("size", "0B")
                content = meta.get("content", "")
                if content:
                    truncated = content[:500]
                    sri_lines.append(
                        f"file: {path}  permissions={perms}  size={size}\n"
                        f"  content:\n  {truncated}"
                    )
                else:
                    sri_lines.append(
                        f"file: {path}  permissions={perms}  size={size}"
                    )

        sri_text = "\n".join(sri_lines) if sri_lines else \
                   "clean system, no extra packages installed"

        # ── Assemble using template ──────────────────────────────────
        return self._user_prompt_tpl.format(
            current_date = current_date,
            sri_text     = sri_text,
            hi_text      = hi_text if hi_text else "No prior impactful interactions.",
            cmd          = cmd,
        )