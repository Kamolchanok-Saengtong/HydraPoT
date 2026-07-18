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
import re
from datetime import datetime

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Malware-fingerprint sessions (e.g. `echo -ne '\x7f\x45\x4c\x46...' > file`)
# get tracked with "content" literally holding the raw, undecoded capture of
# the echo argument (main.py never decodes it). Bash's `echo` only decodes
# \xHH sequences when invoked with a flag containing 'e' (-e/-ne/-en) — a
# bare `echo` leaves them as literal backslash-x text. So whether \xHH means
# "hex byte" or "literal text" depends on that flag, and only decoding tells
# us whether the actual bytes are printable text (e.g. `\x47\x72\x6f\x70` ->
# "Grop") or genuine binary (e.g. a fake ELF header). Detected structurally
# (decode, then check printability of the result) — not tied to any one
# payload/signature, so it generalizes to any tracked file content.
_HEX_BYTE_RE     = re.compile(r"\\x([0-9a-fA-F]{2})")
_ECHO_E_FLAG_RE  = re.compile(r"^-[a-zA-Z]*e[a-zA-Z]*\s+")


def _decode_echo_payload(raw: str) -> bytes:
    """Best-effort reconstruction of the bytes real `echo` would have written,
    given the raw captured argument to `echo ... > file`."""
    s = raw.strip()
    m = _ECHO_E_FLAG_RE.match(s)
    has_e_flag = bool(m)
    if m:
        s = s[m.end():]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1]
    if not has_e_flag:
        return s.encode("utf-8", errors="ignore")
    out = bytearray()
    i = 0
    while i < len(s):
        hm = _HEX_BYTE_RE.match(s, i)
        if hm:
            out.append(int(hm.group(1), 16))
            i = hm.end()
        else:
            out.extend(s[i].encode("utf-8", errors="ignore"))
            i += 1
    return bytes(out)


def _looks_binary(content: str) -> bool:
    """True if `content`, once decoded, is not mostly printable text."""
    if not content:
        return False
    decoded = _decode_echo_payload(content)
    if not decoded:
        return False
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return True
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text) < 0.9


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
             hostname: str = "svr04", os_name: str = "Debian GNU/Linux",
             builtins=None, sync_state: bool = True):
        self.fi_manager   = fi_manager
        self.system_state = system_state
        self.hostname     = hostname
        self.os_name      = os_name

        # load templates once at init
        self._base_prompt_tpl    = _load_template("base_prompt.txt")
        self._system_setting_tpl = _load_template("system_setting.txt")
        self._user_prompt_tpl    = _load_template("user_prompt.txt")
        self.builtins     = builtins or set()  
        self.sync_state   = sync_state

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
        
    def build_cloud_prompt(self, cmd: str) -> tuple[str, str]:
        """
        Like build_prompt() but adds obfuscation-aware instruction for cloud LLM.
        """
        base_prompt = self._base_prompt_tpl.format(
            hostname = self.hostname,
            os_name  = self.os_name,
        )
        system_setting = self._system_setting_tpl.format(
            hostname = self.hostname,
            os_name  = self.os_name,
        )
        obfuscation_note = (
            "\nIMPORTANT: The attacker may use obfuscated commands (base64, hex, "
            "variable splitting, eval, subshell substitution, pipe to shell, etc.). "
            "Mentally decode the full command first, then simulate ONLY the final "
            "terminal output of the fully executed decoded command. "
            "NEVER print the decoded command itself — only print what the decoded "
            "command would output. "
            "Example: 'echo d2hvYW1p | base64 -d | bash' decodes to 'whoami' "
            "and executes it, so output is 'root', NOT 'whoami'.\n"
            "WRONG output for that example: whoami  (this just echoes the decoded "
            "command back, which is incorrect)\n"
            "CORRECT output for that example: root  (this is what whoami actually prints)\n"
            "base64, xxd, od, tr, echo, bash, sh are ALWAYS available as coreutils."
            )
        system_prompt = f"{base_prompt}\n\n{system_setting}{obfuscation_note}"
        user_prompt   = self._build_user_prompt(cmd)
        return system_prompt, user_prompt

    def _build_user_prompt(self, cmd: str) -> str:
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Hi — interaction history from fi_manager buffer ───────────
        hi_text = self.fi_manager.build_terminal_history() if self.sync_state else ""

        sri_lines = []

        # ── SRi — system state register (gated by sync_state) ─────────
        if self.sync_state:
            if self.builtins:
                sri_lines.append(
                    "AVAILABLE TOOLS — pre-installed and always usable, never say "
                    "'command not found' or 'No such file or directory' for these "
                    "regardless of how they're invoked (bare name, or full path like "
                    "/bin/<tool> or /usr/bin/<tool>): "
                    + ", ".join(sorted(self.builtins))
                )

            # general ls -d clarification — injected ONCE, not per file
            sri_lines.append(
                "CRITICAL: 'ls -d <path>' without -l prints ONLY the path itself "
                "(e.g. 'ls -d /tmp' outputs '/tmp'), NOT permission bits. "
                "Only 'ls -ld' or 'ls -la' includes permission strings like drwxr-xr-x."
            )

            # bare `ls` was consistently hallucinating an `ls -la`-style
            # listing (permissions, dotfiles, a 'total N' line) regardless
            # of the flags actually given — found via real losses against
            # Cowrie in testing (54 cases). This is purely a
            # formatting/syntax rule, not a state-dependent judgment call
            # (unlike the earlier chmod fix, which needed to be resolved in
            # code instead of the prompt because it required reasoning
            # about file existence) — so a clear instruction should be
            # reliable here the same way the ls -d note above already is.
            sri_lines.append(
                "CRITICAL: bare 'ls' or 'ls <path>' with NO '-l'/'-a' flags "
                "prints ONLY filenames in simple space-separated columns — "
                "no permission bits, no owner/size/date, no 'total N' line, "
                "and no dotfiles (hidden entries starting with '.') unless "
                "-a is given. Only 'ls -l'/'ls -la'/'ls -al' show the long "
                "format with permissions and a 'total' line."
            )

            # `sh`/`bash` were losing to Cowrie by hallucinating "command not
            # found" even though both are always in AVAILABLE TOOLS above —
            # being buried in that long comma list wasn't a strong enough
            # signal on its own. Same fix pattern as ls: a standalone
            # CRITICAL callout, since this is a formatting/knowledge rule,
            # not a state-dependent judgment call.
            sri_lines.append(
                "CRITICAL: 'sh' and 'bash' are ALWAYS available — they are "
                "the shells this very terminal already runs on. NEVER output "
                "'command not found' for bare 'sh'/'bash', or for 'sh "
                "<script>'/'bash <script>'. Bare 'sh' or 'bash' with no "
                "arguments just starts a nested interactive shell (respond "
                "with a minimal shell prompt, not an error)."
            )

            # `w` (logged-in users) was losing to Cowrie by being answered
            # with `ps`-style process-list output, or by just echoing the
            # command text back instead of producing output.
            sri_lines.append(
                "CRITICAL: 'w' shows currently logged-in users — a header "
                "line (USER, TTY, LOGIN@, IDLE, JCPU, PCPU, WHAT) followed by "
                "one row per logged-in session (e.g. 'root  pts/0  10:02  "
                "0.00s  0.04s  0.01s  -bash'). It is NOT 'ps' and must NOT "
                "be answered with a process list, and must NOT just echo "
                "the command text back."
            )

            # `busybox`/`/bin/busybox` was the single biggest FI4 loss against
            # Cowrie (77% of meaningful losses in a real 109-session
            # comparison) — hallucinating "command not found" despite being
            # in AVAILABLE TOOLS above, the same "buried in a long list"
            # reliability problem already fixed for sh/bash and w. Real FI4
            # traffic is dominated by IoT-botnet-style commands that self-
            # invoke via busybox (self-copy, chmod 777, rm -rf droppers),
            # so this one tool covers a disproportionate share of real losses.
            sri_lines.append(
                "CRITICAL: 'busybox' and '/bin/busybox' are ALWAYS available "
                "— NEVER output 'command not found' for either form. "
                "'busybox <applet> <args>' (e.g. 'busybox chmod 777 x', "
                "'/bin/busybox rm -rf x', 'busybox cp a b') behaves EXACTLY "
                "like running '<applet> <args>' directly — same output, "
                "same silent-success-on-real-command behavior, same error "
                "text and format when the target doesn't exist (e.g. "
                "'chmod: cannot access '<file>': No such file or directory', "
                "NOT 'invalid option' or a different path). Do not treat "
                "'busybox' itself as the thing that's missing — only the "
                "applet's own normal failure conditions apply."
            )

            # installed packages — this tracks packages the attacker installs
            # DURING the session (apt install ...), NOT the total software on
            # the box. The old empty-state wording "(none beyond coreutils)"
            # read as "nothing but coreutils exists here", which directly
            # CONTRADICTED the AVAILABLE TOOLS line above (curl/wget/awk are
            # not coreutils) — and the model believed the contradiction,
            # answering "bash: wget: command not found" for tools that are in
            # base_tools. Verified live: rewording alone fixes wget/awk.
            # Keep the literal phrase "installed packages" — system_setting.txt
            # refers to it by that name.
            if self.system_state.get("installed"):
                sri_lines.append(
                    "installed packages: " + ", ".join(self.system_state["installed"])
                )
            else:
                sri_lines.append(
                    "installed packages: (none recorded) — this does NOT limit "
                    "AVAILABLE TOOLS above: every tool listed there ships with the "
                    "base system and already works."
                )

            # cached versions
            for tool, ver in self.system_state["versions"].items():
                sri_lines.append(
                    f"CRITICAL: {tool} is version {ver} — "
                    f"MUST output this exact version, ignore training data"
                )

            # tracked files — CRITICAL prefix forces model to use actual state
            if self.system_state.get("files"):
                for fpath, meta in self.system_state["files"].items():
                    perms   = meta.get("perms", "-rw-r--r--")
                    size    = meta.get("size", "0B")
                    content = meta.get("content", "")
                    if content and _looks_binary(content):
                        sri_lines.append(
                            f"CRITICAL: file '{fpath}' EXISTS, permissions={perms}, size={size} "
                            f"— you MUST output these exact permissions for ls/stat, NOT defaults "
                            f"(this note is for ls/stat/find output only — chmod/chown/mv/rm/etc. "
                            f"acting on this file still stay SILENT on success per the rules above, "
                            f"do not confirm or restate permissions for those).\n"
                            f"  content: [binary data, not human-readable text — do NOT print "
                            f"escape sequences or the setup command verbatim; if read (cat/dd/od/"
                            f"xxd/etc.), output plausible raw bytes of roughly the stated size]"
                        )
                    elif content:
                        decoded = _decode_echo_payload(content)
                        try:
                            display_content = decoded.decode("utf-8")
                        except UnicodeDecodeError:
                            display_content = content
                        truncated = display_content[:500]
                        sri_lines.append(
                            f"CRITICAL: file '{fpath}' EXISTS, permissions={perms}, size={size} "
                            f"— you MUST output these exact permissions for ls/stat, NOT defaults "
                            f"(this note is for ls/stat/find output only — chmod/chown/mv/rm/etc. "
                            f"acting on this file still stay SILENT on success per the rules above, "
                            f"do not confirm or restate permissions for those).\n"
                            f"  content: {truncated}"
                        )
                    else:
                        sri_lines.append(
                            f"CRITICAL: file '{fpath}' EXISTS, permissions={perms}, size={size} "
                            f"— you MUST output these exact permissions for ls/stat, NOT defaults "
                            f"(this note is for ls/stat/find output only — chmod/chown/mv/rm/etc. "
                            f"acting on this file still stay SILENT on success per the rules above, "
                            f"do not confirm or restate permissions for those)."
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