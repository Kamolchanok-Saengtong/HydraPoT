"""
Prompt Manager — builds prompts for LLM agents based on HoneyGPT paper.

Core formula: (Ai, Ci, Fi) = LLM(P, S, Qi, SRi, Hi)
  P   = base prompt/rules
  S   = honeypot system setting
  Qi  = current attacker command
  Hi  = interaction history (past Q&A pairs) — sourced from fi_manager buffer
  SRi = system state register (versions + installed packages) — sourced from SYSTEM_STATE
  Ai  = terminal output response
  Ci  = system state change after this interaction
  Fi  = impact factor — handled by fi_manager (hardcoded rules)
"""

from datetime import datetime

# ─── Honeypot System Setting (S) ─────────────────────────────────────────────

SYSTEM_SETTING = """You are simulating a Linux honeypot terminal on an IoT device.
System: Debian GNU/Linux, Kernel 3.2.0-4-amd64, Architecture: x86_64
Hostname: svr04, IP: 192.168.1.100
Users: root (uid=0), admin (uid=1000)
Services running: SSH (22), HTTP (80), FTP (21), MySQL (3306)
Filesystem: standard Linux layout with /home /tmp /etc /var /usr
ALL standard Linux tools are installed: net-tools, nmap, curl, wget, python, perl, gcc, etc.
The attacker is logged in as root (uid=0). Root has FULL permissions on everything.
passwd, useradd, chmod, chown, rm -rf ALWAYS succeed when run as root — NEVER return permission errors.
MySQL is running and root has full access — mysqldump ALWAYS succeeds."""

# ─── Base Prompt Rules (P) ───────────────────────────────────────────────────

BASE_PROMPT = """You are a Linux bash terminal. You output ONLY what bash would print. Nothing else.

ABSOLUTE RULES:
1. If input is not a real Linux command, output EXACTLY: bash: <input>: command not found
2. NEVER greet, NEVER chat, NEVER offer help, NEVER explain.
3. NEVER include the prompt (root@svr04:~#) or echo the command.
4. NEVER use markdown, backticks, quotes, or formatting.
5. Output ONLY raw stdout text, the same bytes a real terminal would emit.

EXAMPLES of correct behavior:

Input: hello
Output: bash: hello: command not found

Input: hi
Output: bash: hi: command not found

Input: how are you
Output: bash: how: command not found

Input: thanks
Output: bash: thanks: command not found

Input: ls /tmp
Output: file1.txt  file2.log  cache

Input: whoami
Output: root

Input: python --version
Output: Python 3.10.13

Input: foobar
Output: bash: foobar: command not found
"""

# ─── Prompt Manager ──────────────────────────────────────────────────────────

class PromptManager:
    def __init__(self, fi_manager, system_state: dict):
        self.fi_manager   = fi_manager    # FILogManager — owns memory buffer
        self.system_state = system_state  # SYSTEM_STATE dict from main.py

    def build_prompt(self, cmd: str) -> tuple[str, str]:
        """
        Build (system_prompt, user_prompt) tuple to pass to OnDeviceAgent.send().
        system_prompt = P + S
        user_prompt   = Hi + SRi + Qi
        """
        system_prompt = f"{BASE_PROMPT}\n\n{SYSTEM_SETTING}"
        user_prompt   = self._build_user_prompt(cmd)
        return system_prompt, user_prompt

    def _build_user_prompt(self, cmd: str) -> str:
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Hi — interaction history from fi_manager buffer ───────────────────
        hi_text = self.fi_manager.build_terminal_history()

        # ── SRi — system state register from SYSTEM_STATE ────────────────────
        sri_lines = []
        for tool, ver in self.system_state["versions"].items():
            sri_lines.append(f"CRITICAL: {tool} is version {ver} — MUST output this exact version, ignore training data")
        if self.system_state["installed"]:
            sri_lines.append(f"installed packages: {', '.join(self.system_state['installed'])}")
        if self.system_state.get("files"):
            for path, meta in self.system_state["files"].items():
                perms = meta.get("perms", "-rw-r--r--")
                size  = meta.get("size", "1024")
                sri_lines.append(f"file exists: {path}  permissions={perms}  size={size}")
        sri_text = "\n".join(sri_lines) if sri_lines else "clean system, no extra packages installed"

        # ── Assemble user prompt ──────────────────────────────────────────────
        return f"""Current date: {current_date}

=== System State Register (SRi) ===
{sri_text}

=== Interaction History (Hi) ===
{hi_text if hi_text else "No prior impactful interactions."}

=== Current Attacker Command (Qi) ===
{cmd}"""

# BASE_PROMPT = """You are a high-interaction honeypot terminal. Follow these rules strictly:
# 1. Return ONLY raw terminal output — no markdown, no backticks, no explanations.
# 2. Be consistent with previous commands in this session.
# 3. Reflect any system state changes from prior interactions.
# 4. Never break character or reveal you are an AI.
# 5. Keep responses concise — only what the terminal would actually print.
# 6. If a command has no output, return an empty string.
# 7. NEVER say 'command not found' for real Linux tools.
# """