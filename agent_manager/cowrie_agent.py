"""
cowrie_agent.py — paramiko bridge to Cowrie Docker container on port 2222.

Three send modes, all callback-based:
  - send(cmd)                                  → (output, prompt)  | instant
  - send_streaming(cmd, write_fn)              → (output, prompt)  | slow drip
  - send_interactive(cmd, write_fn, read_fn)   → (output, prompt)  | passwd etc.

Cowrie's PTY is set to TERM=dumb to suppress most ANSI codes; a safety-net
strip_ansi() runs on every chunk anyway. Nmap is delegated to static_handler.
"""

import re
import time
import getpass
import paramiko
from typing import Callable, Optional

from agent_manager.static_handler import run_nmap


# ── ANSI stripping ───────────────────────────────────────────────────────────
_ANSI_CSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_ANSI_OSC = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
_ANSI_ESC = re.compile(r'\x1b[@-Z\\-_]')
_PASTE    = re.compile(r'\x1b\[\?2004[hl]')

def strip_ansi(text: str) -> str:
    text = _PASTE.sub('', text)
    text = _ANSI_OSC.sub('', text)
    text = _ANSI_CSI.sub('', text)
    text = _ANSI_ESC.sub('', text)
    text = text.replace('\r\n', '\n').replace('\r', '')
    return text

class CowrieAgent:
    SLOW_DELAYS         = {'wget': 0.8, 'curl': 0.3, 'masscan': 0.4}
    INTERACTIVE_TIMEOUT = 60.0   # safety hard-stop for interactive cmds
    def __init__(self, host="127.0.0.1", port=2222, username="root", password="root"):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.client   = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell    = None
        self._original_prompt = ""
        
    # ── connection ───────────────────────────────────────────────────────────
    def _connect(self):
        self._connect()
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, port=self.port,
                            username=self.username, password=self.password)
        
        # term='dumb' tells cowrie not to emit colors / cursor codes
        self.shell = self.client.invoke_shell(term='dumb')
        time.sleep(0.5)
        banner = ""
        if self.shell.recv_ready():
            banner = self.shell.recv(9999).decode(errors='ignore')
        # last non-empty line of the banner is the initial prompt
        cleaned_lines = [l for l in strip_ansi(banner).split('\n') if l.strip()]
        if cleaned_lines:
            self._original_prompt = cleaned_lines[-1].strip()
        print(f"[cowrie_agent] Connected. Original prompt: {self._original_prompt!r}")

    def send(self, cmd: str) -> tuple[str, str]:
        """Instant commands. Returns full (output, prompt)."""
        if not self.shell:
            return "", ""
        cmd_base = cmd.strip().split()[0] if cmd.strip() else ""

        if cmd_base == 'nmap':
            return run_nmap(cmd), ""

        if cmd_base == 'clear':
            try:
                self.shell.send(cmd + '\n')
            except (OSError, EOFError, paramiko.SSHException):
                self._connect()
                self.shell.send(cmd + '\n')
            time.sleep(0.2)
            if self.shell.recv_ready():
                self.shell.recv(9999)
            return "", "CLEAR"

        try:
            self.shell.send(cmd + '\n')
        except (OSError, EOFError, paramiko.SSHException):
            print("[cowrie_agent] Socket closed — reconnecting...")
            self._connect()
            self.shell.send(cmd + '\n')

        return self._collect_until_prompt(cmd)

    def send_streaming(self, cmd: str, write_fn: Callable[[str], None],
                       delay: Optional[float] = None) -> tuple[str, str]:
        """Slow commands (wget, curl, masscan). Streams line-by-line."""
        if not self.shell:
            return "", ""
        cmd_base = cmd.strip().split()[0] if cmd.strip() else ""
        if delay is None:
            delay = self.SLOW_DELAYS.get(cmd_base, 0.5)

        self.shell.send(cmd + '\n')
        return self._collect_streaming(cmd, write_fn, delay)

    def send_interactive(self, cmd: str,
                         write_fn: Callable[[str], None],
                         read_fn:  Callable[[], Optional[str]]
                         ) -> tuple[str, str]:
        """
        passwd / adduser / useradd / userdel.

        write_fn(text)  — called when cowrie produces output (push to attacker)
        read_fn()       — non-blocking poll for attacker input; returns
                          string or None.
        """
        if not self.shell:
            return "", ""
        self.shell.send(cmd + '\n')
        return self._collect_interactive(cmd, write_fn, read_fn)

    # ── internal: instant ────────────────────────────────────────────────────
    def _collect_until_prompt(self, cmd: str, timeout: float = 2.0) -> tuple[str, str]:
        raw = ""
        last = time.time()
        while True:
            if self.shell.recv_ready():
                raw  += self.shell.recv(4096).decode(errors='ignore')
                last  = time.time()
                if self._has_prompt(strip_ansi(raw)):
                    time.sleep(0.1)
                    if not self.shell.recv_ready():
                        break
            elif time.time() - last > timeout:
                break
            else:
                time.sleep(0.01)
        return self._split(raw, cmd)

    # ── internal: streaming ──────────────────────────────────────────────────
    def _collect_streaming(self, cmd: str,
                           write_fn: Callable[[str], None],
                           delay: float,
                           timeout: float = 30.0) -> tuple[str, str]:
        raw = ""
        last = time.time()
        emitted_chars = 0    # how many chars of cleaned `raw` we've already pushed

        while True:
            if self.shell.recv_ready():
                chunk = self.shell.recv(4096).decode(errors='ignore')
                raw  += chunk
                last  = time.time()
            elif time.time() - last > timeout:
                break
            else:
                time.sleep(0.02)

            cleaned = strip_ansi(raw)
            if len(cleaned) > emitted_chars:
                new_text = cleaned[emitted_chars:]
                last_nl  = new_text.rfind('\n')
                if last_nl >= 0:
                    flush = new_text[:last_nl + 1]
                    emitted_chars += len(flush)
                    for line in flush.split('\n'):
                        if not line:
                            continue
                        if line.strip() == cmd.strip():
                            continue
                        if self._is_prompt_line(line):
                            continue
                        write_fn(line + "\r\n")
                        time.sleep(delay)

            if self._has_prompt(cleaned):
                time.sleep(0.1)
                if not self.shell.recv_ready():
                    break

        return self._split(raw, cmd)

    # ── internal: interactive ────────────────────────────────────────────────
    def _collect_interactive(self, cmd: str,
                             write_fn: Callable[[str], None],
                             read_fn:  Callable[[], Optional[str]]
                             ) -> tuple[str, str]:
        raw = ""
        emitted_chars = 0
        start = time.time()

        while True:
            # 1. relay any cowrie output to the attacker immediately
            if self.shell.recv_ready():
                chunk = self.shell.recv(4096).decode(errors='ignore')
                raw  += chunk
                cleaned = strip_ansi(raw)
                if len(cleaned) > emitted_chars:
                    new_text = cleaned[emitted_chars:]
                    emitted_chars = len(cleaned)
                    # skip the echoed cmd if it appears at the very start
                    if emitted_chars == len(new_text) and cmd.strip() in new_text:
                        new_text = new_text.replace(cmd.strip(), '', 1).lstrip('\n')
                    if new_text:
                        write_fn(new_text.replace('\n', '\r\n'))

            # 2. forward attacker keystrokes/lines to cowrie
            try:
                user_input = read_fn()
            except Exception:
                user_input = None
            if user_input:
                if not user_input.endswith('\n'):
                    user_input += '\n'
                self.shell.send(user_input)

            # 3. done? original prompt is back
            cleaned = strip_ansi(raw)
            if self._original_prompt and cleaned.rstrip().endswith(self._original_prompt):
                break
            if self._has_prompt(cleaned) and not self.shell.recv_ready():
                time.sleep(0.2)
                if not self.shell.recv_ready():
                    break

            # 4. safety timeout
            if time.time() - start > self.INTERACTIVE_TIMEOUT:
                write_fn("\r\n[interactive command timed out]\r\n")
                self.shell.send('\x03')
                time.sleep(0.3)
                if self.shell.recv_ready():
                    self.shell.recv(9999)
                break

            time.sleep(0.02)

        return self._split(raw, cmd)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _has_prompt(self, cleaned: str) -> bool:
        if self._original_prompt and cleaned.rstrip().endswith(self._original_prompt):
            return True
        return bool(re.search(r'[#$]\s*$', cleaned.rstrip()))

    def _is_prompt_line(self, line: str) -> bool:
        s = line.strip()
        if self._original_prompt and s == self._original_prompt:
            return True
        return bool(re.fullmatch(r'.*[#$]', s))

    def _split(self, raw: str, cmd: str = "") -> tuple[str, str]:
        cleaned = strip_ansi(raw)
        lines   = [l for l in cleaned.split('\n') if l.strip() != '']

        # drop the echoed command — cowrie's PTY repeats whatever we sent
        if cmd and lines:
            cmd_stripped = cmd.strip()
            # check first 2 lines (sometimes a leading blank / prompt fragment)
            for i in range(min(2, len(lines))):
                if lines[i].strip() == cmd_stripped or lines[i].strip().endswith(cmd_stripped):
                    lines.pop(i)
                    break

        prompt = ""
        if lines and self._is_prompt_line(lines[-1]):
            prompt = lines[-1].strip()
            lines  = lines[:-1]
        return '\n'.join(lines).strip(), prompt

    def disconnect(self):
        if self.client:
            self.client.close()
        print("[cowrie_agent] Disconnected")