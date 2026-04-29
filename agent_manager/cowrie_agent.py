import re, time, sys, paramiko, getpass
import tty, termios, select
from agent_manager.static_handler import run_nmap

class CowrieAgent:
    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell = None

    def connect(self):
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        self.client.connect(
            hostname='127.0.0.1',
            port=2222,
            username=username,
            password=password,
        )
        self.shell = self.client.invoke_shell()
        time.sleep(0.5)
        self.shell.recv(9999)
        # print("✓ Connected to Cowrie")

    CONTINUOUS_CMDS   = ('ping', 'traceroute', 'top', 'watch')
    SLOW_CMDS         = ('wget', 'curl', 'masscan')
    SLOW_DELAYS       = {'wget': 0.8, 'curl': 0.3, 'masscan': 0.4}
    INTERACTIVE_CMDS  = ('adduser', 'useradd', 'passwd', 'userdel')

    def send(self, cmd: str) -> tuple[str, str]:
        if not self.shell:
            return "", ""

        cmd_base = cmd.strip().split()[0]

        # ── nmap: handled locally ─────────────────────────────────────────────
        if cmd_base == 'nmap':
            output = run_nmap(cmd)
            return output, ""

        # ── clear ─────────────────────────────────────────────────────────────
        if cmd_base == 'clear':
            sys.stdout.write('\033[2J\033[H')
            sys.stdout.flush()
            self.shell.send(cmd + '\n')
            time.sleep(0.2)
            self.shell.recv(9999)
            return "", "CLEAR"

        self.shell.send(cmd + '\n')

        # ── interactive: raw mode, user types freely ──────────────────────────
        if cmd_base in self.INTERACTIVE_CMDS:
            return self._stream_interactive(cmd)

        # ── continuous: stream until Ctrl+C ───────────────────────────────────
        if cmd_base in self.CONTINUOUS_CMDS:
            return self._stream_continuous(cmd)

        # ── slow: collect then print line by line ─────────────────────────────
        if cmd_base in self.SLOW_CMDS:
            output, prompt = self._collect(cmd)
            delay = self.SLOW_DELAYS.get(cmd_base, 0.5)
            self._print_slow(output, delay)
            return output, prompt

        # ── normal: collect and print instantly ───────────────────────────────
        output, prompt = self._collect(cmd)
        if output:
            print(output)
        return output, prompt

    def _stream_interactive(self, cmd: str) -> tuple[str, str]:
        """Raw terminal mode — pipe directly to Cowrie. Passwords hidden by Cowrie itself."""
        full_output = ""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(fd)
            while True:
                r, _, _ = select.select([self.shell, sys.stdin], [], [], 0.1)

                if self.shell in r:
                    chunk = self.shell.recv(1024).decode(errors='ignore')
                    if not chunk:
                        break
                    cleaned = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', chunk)
                    full_output += cleaned
                    sys.stdout.write(chunk)
                    sys.stdout.flush()

                    # stop when prompt appears and no more data
                    if re.search(r'[$#]\s*$', cleaned.strip()):
                        time.sleep(0.2)
                        if not self.shell.recv_ready():
                            break

                if sys.stdin in r:
                    key = sys.stdin.read(1)
                    self.shell.send(key)

        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        print()
        return full_output.strip(), ""

    def _stream_continuous(self, cmd: str) -> tuple[str, str]:
        """Stream output until Ctrl+C."""
        full_output = ""
        print()

        try:
            while True:
                if self.shell.recv_ready():
                    chunk = self.shell.recv(256).decode(errors='ignore')
                    cleaned = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', chunk)
                    cleaned = cleaned.replace('\r\n', '\n').replace('\r', '\n')
                    full_output += cleaned
                    sys.stdout.write(cleaned)
                    sys.stdout.flush()
                else:
                    time.sleep(0.05)

        except KeyboardInterrupt:
            self.shell.send('\x03')
            time.sleep(0.3)
            if self.shell.recv_ready():
                leftover = self.shell.recv(9999).decode(errors='ignore')
                leftover = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', leftover)
                sys.stdout.write(leftover)
            print()

        return full_output.strip(), ""

    def _collect(self, cmd: str) -> tuple[str, str]:
        """Collect full output then return."""
        full_output = ""
        last_recv = time.time()
        timeout = 2.0

        while True:
            if self.shell.recv_ready():
                chunk = self.shell.recv(4096).decode(errors='ignore')
                full_output += chunk
                last_recv = time.time()

                cleaned = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', chunk)

                # stop when prompt appears
                if re.search(r'[$#]\s*$', cleaned.strip()):
                    time.sleep(0.1)
                    if not self.shell.recv_ready():
                        break

            elif time.time() - last_recv > timeout:
                break
            else:
                time.sleep(0.01)

        return self._clean(full_output, cmd)

    def _print_slow(self, output: str, delay: float = 0.5):
        for line in output.splitlines():
            print(line)
            sys.stdout.flush()
            time.sleep(delay)

    def _clean(self, raw: str, cmd: str) -> tuple[str, str]:
        raw = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', raw)
        lines = raw.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        lines = [l for l in lines if l.strip()]

        if lines and cmd.strip() in lines[0]:
            lines = lines[1:]

        prompt = ''
        if lines and ('$' in lines[-1] or '#' in lines[-1]):
            prompt = lines[-1].strip()
            lines = lines[:-1]

        return '\n'.join(lines).strip(), prompt

    def disconnect(self):
        if self.client:
            self.client.close()