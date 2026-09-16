"""
shell/responders.py — answers produced WITHOUT asking a model.

Every one of these exists for the same reason, and it is worth stating once
because it is the whole argument for the module: A COMPUTED ANSWER CANNOT
CONTRADICT ITSELF. A model asked the same question twice may answer twice
differently, and an attacker probing for exactly that is how a honeypot gets
found out. Each case below was a real observed contradiction:

    cd       a model that wrongly accepts `cd .ssh` has no way to un-believe it,
             and echoed a fake `root@host:~/.ssh#` prompt for the rest of the
             session
    chmod    the prompt says "chmod always succeeds as root" (true -- root is
             never denied by PERMISSION), which is not the same as the file
             existing. 20/20 loss on that pattern before this was computed
    uname    FI 0 routed it to Cowrie, which answered with COWRIE's identity
             ("Linux svr04 3.2.0-4-amd64 ... Debian") while the banner said
             Ubuntu 22.04 and the prompt said `psu`. Three machines, one
             session, and `uname -a` is usually an attacker's second command
    systemctl  `stop` then `status` used to still report "active (running)"

ONE CONTRACT, so an unrecognised form falls through to normal routing instead
of being answered wrongly here:

    -> (True,  output)  handled; this is the answer (may be "" for silence)
    -> (False, None)    not ours; let the router decide

WHY cd AND chmod LIVE HERE AND NOT IN fakefs.py. They WRITE -- cwd, permissions
-- and cd asks Cowrie. fakefs.py is strictly read-only so its answers can be
computed twice with no side effects. These are responders that USE the
filesystem, not part of it.
"""
import random
import re
from datetime import datetime


class Responders:
    """One session's deterministic answers.

        r = Responders(SYSTEM_STATE, fs, tracker, host=config.honeypot,
                       probe=cowrie_probe)
        r.cd("cd /tmp")          -> (True, None)
        r.uname("uname -a")      -> (True, "Linux psu 5.15...")

    `probe` is an optional callable taking a path and returning True when
    Cowrie says the directory really exists. Passed in rather than importing an
    agent, so this module never depends on the transport -- and the tests need
    no container.
    """

    def __init__(self, state: dict, fs, tracker, host=None, probe=None):
        self.state = state
        self.fs = fs
        self.tracker = tracker
        self.host = host                 # config.honeypot -- hostname/kernel/arch
        self.probe = probe

    # ── cd ──────────────────────────────────────────────────────────────────

    def _move_to(self, path: str) -> None:
        """Change directory, remembering where we came from so `cd -` works."""
        self.state["oldpwd"] = self.state["cwd"]
        self.state["cwd"] = path

    def cd(self, cmd: str):
        """-> (handled, error_or_None). Silence on success, like real cd."""
        handled, new_cwd, error = self.fs.compute_cd(cmd)
        if not handled:
            return False, None
        if new_cwd is not None:
            self._move_to(new_cwd)
            return True, error

        # Before telling the attacker a directory does not exist, ask Cowrie --
        # it owns the real tree and knows ~26,000 paths we never declared. This
        # is how `cd coc-student-portal` failed for a directory `ls` had just
        # listed.
        if error and error.endswith("No such file or directory") and self.probe:
            target = self.fs.last_resolved
            if target and self.probe(target):
                self._move_to(target)
                # Remember it, so the next cd here answers without asking again.
                self.state["files"].setdefault(
                    target, {"perms": "drwxr-xr-x", "size": "4.0K"})
                return True, None
        return True, error

    # ── chmod ───────────────────────────────────────────────────────────────

    def chmod(self, cmd: str):
        """-> (handled, error_or_None). Silence on success."""
        if re.search(r'--version\b|-V\b', cmd):
            return False, None            # version query, not a mode change
        parts = cmd.split()
        if len(parts) < 3:
            return False, None            # bare `chmod` or ambiguous
        target = parts[-1]
        if target.startswith("-") or "*" in target or "?" in target:
            return False, None            # flag-only or wildcard -- too ambiguous

        target = self.fs.resolve(target)
        rec = self.state["files"].get(target)
        if rec and rec.get("backend") == "cowrie":
            # Cowrie owns this file. Answering here wrote our state only, so
            # `chmod +x f` reported success while the next `ls -la f` still
            # showed -rw-r--r-- straight from Cowrie. Let Cowrie do it.
            return False, None
        if target in self.state["files"]:
            self.tracker.record(cmd, "")  # the +x / numeric bookkeeping
            return True, None
        if self.fs.is_virtual(target):
            return True, None
        return True, f"chmod: cannot access '{target}': No such file or directory"

    # ── uname ───────────────────────────────────────────────────────────────

    _LONG_FLAGS = {"--all": "a", "--kernel-name": "s", "--nodename": "n",
                   "--kernel-release": "r", "--kernel-version": "v",
                   "--machine": "m", "--processor": "p",
                   "--hardware-platform": "i", "--operating-system": "o"}

    def uname(self, cmd: str):
        """-> (handled, output). Identity comes from config, never from Cowrie."""
        parts = cmd.split()
        if not parts or parts[0] != "uname":
            return False, None
        if re.search(r'--version\b|--help\b', cmd):
            return False, None            # not an identity question

        hostname = self.host.hostname
        kernel = self.host.kernel
        build = self.host.kernel_build
        arch = self.host.arch

        flags = set()
        for p in parts[1:]:
            if p in self._LONG_FLAGS:
                flags.add(self._LONG_FLAGS[p])
            elif p.startswith("-") and len(p) > 1 and not p.startswith("--"):
                flags.update(p[1:])
            else:
                return False, None        # operand or unknown long flag -- don't guess

        if "a" in flags:
            # Real order: kernel-name nodename release version machine
            #             processor hardware-platform operating-system
            return True, f"Linux {hostname} {kernel} {build} {arch} {arch} {arch} GNU/Linux"
        if not flags:
            return True, "Linux"          # bare `uname` == `uname -s`

        order = [("s", "Linux"), ("n", hostname), ("r", kernel), ("v", build),
                 ("m", arch), ("p", arch), ("i", arch), ("o", "GNU/Linux")]
        out = [value for flag, value in order if flag in flags]
        return (True, " ".join(out)) if out else (False, None)

    # ── systemctl / service ─────────────────────────────────────────────────

    def systemctl(self, cmd: str) -> str:
        """`systemctl`/`service`. Always handled -- the caller gates on the verb.

        State is remembered so `stop` then `status` does not still claim
        "active (running)"; an attacker probes exactly that pair.
        """
        parts = cmd.strip().split()
        if len(parts) < 3:
            return "Usage: systemctl [OPTIONS...] COMMAND ..."
        if parts[0] == "service":
            service, action = parts[1], parts[2]
        else:
            action, service = parts[1], parts[2]

        # A never-touched service defaults to running, like a real fresh box
        # where sshd is up without anyone starting it.
        svc = self.state["services"].setdefault(
            service, {"active": True, "enabled": True})

        if action == "status":
            return self._status(service, svc)
        if action in ("start", "restart"):
            svc["active"] = True
            return ""
        if action == "stop":
            svc["active"] = False
            return ""
        if action == "reload":
            return ""
        if action == "enable":
            svc["enabled"] = True
            return f"Created symlink /etc/systemd/system/multi-user.target.wants/{service}.service"
        if action == "disable":
            svc["enabled"] = False
            return f"Removed /etc/systemd/system/multi-user.target.wants/{service}.service"
        return f"systemctl: unknown command '{action}'"

    @staticmethod
    def _status(service: str, svc: dict) -> str:
        # Derived from the NAME, not random: the same service must report the
        # same PID and memory every time it is asked.
        enabled = "enabled" if svc["enabled"] else "disabled"
        head = (f"● {service}.service - {service.upper()} Service\n"
                f"     Loaded: loaded (/lib/systemd/system/{service}.service; {enabled})\n")
        if not svc["active"]:
            return head + "     Active: inactive (dead)"
        return head + (
            f"     Active: active (running) since Mon 2026-05-05 03:22:11 UTC; 3 days ago\n"
            f"   Main PID: {1000 + hash(service) % 9000} ({service})\n"
            f"      Tasks: {2 + hash(service) % 8}\n"
            f"     Memory: {4 + hash(service) % 60}.{hash(service) % 10}M\n"
            f"        CPU: {hash(service) % 500}ms\n"
            f"     CGroup: /system.slice/{service}.service")

    # ── passwd ──────────────────────────────────────────────────────────────

    @staticmethod
    def passwd() -> str:
        """Always "succeeds" -- root is never refused a password change.

        The caller supplies the interactive prompts and the pauses; the pause
        is deliberate, since an instant password change reads as scripted.
        """
        return "passwd: password updated successfully"

    # ── wget / curl transcripts ─────────────────────────────────────────────

    def download_output(self, cmd: str, tool: str) -> str:
        """The progress transcript wget/curl prints.

        Cosmetic only -- the real transfer is Cowrie's, and shell/state.py
        records who holds the bytes.
        """
        url_m = re.search(r'https?://\S+', cmd)
        url = url_m.group(0) if url_m else "http://unknown"
        dest_m = re.search(r'-o\s+(\S+)', cmd)
        dest = (dest_m.group(1) if dest_m
                else f"/root/{url.rstrip('/').split('/')[-1] or 'index.html'}")

        size_kb = random.randint(4, 800)
        speed_kb = random.randint(100, 1200)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if tool == "wget":
            return (
                f"--{now}--  {url}\n"
                f"Connecting to {url.split('/')[2]}:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size_kb * 1024} ({size_kb}K) [application/octet-stream]\n"
                f"Saving to: '{dest}'\n\n"
                f"{size_kb}K [======================================>] "
                f"{size_kb * 1024}  {speed_kb}.{random.randint(10, 99)}KB/s   "
                f"in 0.{random.randint(1, 9)}s\n\n"
                f"{now} ({speed_kb}.{random.randint(10, 99)} KB/s) - "
                f"'{dest}' saved [{size_kb * 1024}/{size_kb * 1024}]")
        return (
            "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
            "                                 Dload  Upload   Total   Spent    Left  Speed\n"
            f"100 {size_kb}K  100 {size_kb}K    0     0  {speed_kb}k      0  "
            f"0:00:01  0:00:01 --:--:-- {speed_kb}k")
