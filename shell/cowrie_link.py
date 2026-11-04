"""
shell/cowrie_link.py — talking to the Cowrie container.

Three things, all about the same fact: Cowrie is a separate process that can
die, and an attacker must never be able to tell.

    send()          run a command there, degrade to the model if it is gone
    sync()          replay a state change there, best effort
    sync_history()  keep .bash_history in step

THE DEGRADATION IS THE POINT. Cowrie is a hard dependency for FI 0-1 traffic
and for wget/curl. When the container died, those commands returned "" and the
attacker got silence on nearly everything -- the loudest possible tell that the
box is fake. Falling back to the on-device model keeps the session believable,
and send() returns WHICH agent actually answered so the log records the truth
rather than crediting Cowrie for the model's output.

THESE USED TO BE REBUILT ON EVERY KEYSTROKE. All four lived as closures inside
main.py's handle(), so Python re-created them for every command an attacker
typed. Constructed once per session now.

NO LLM DEPENDENCY. The fallback arrives as a callable, so this module never
imports an agent and its tests need neither a container nor a model.
"""


import base64
import shlex

from prompt.prompt_manager import _decode_echo_payload


def _write_cmd(q: str, rec: dict) -> str:
    """Command to recreate a file's CONTENT in Cowrie (base64 = injection-safe).

    Downloads already hold their real bytes on Cowrie (it ran the wget), and
    empty files need no content — both just get `touch`.
    """
    if rec.get("backend") == "cowrie" or not rec.get("content"):
        return f"touch {q}"
    data = _decode_echo_payload(rec["content"])
    if not data:
        return f"touch {q}"
    b64 = base64.b64encode(data).decode()
    return f"echo '{b64}' | base64 -d > {q}"


def _perms_to_octal(perms: str):
    """'-rwxr-xr-x' → '755'; None if it can't be parsed."""
    if not perms or len(perms) < 10:
        return None
    bits, out = perms[1:10], ""
    for i in range(0, 9, 3):
        r, w, x = bits[i:i + 3]
        out += str((4 if r == "r" else 0) + (2 if w == "w" else 0) + (1 if x == "x" else 0))
    return out


class CowrieLink:
    """One session's connection to Cowrie.

        link = CowrieLink(cowrie_agent, fallback=answer_with_model)
        out, agent = link.send("ls -la")        -> ("...", "cowrie")
        link.sync("mkdir /tmp/x")               -> best effort, no answer
        link.sync_history("wget http://...")

    `fallback` is called as fallback(cmd) -> (output, agent_name) when Cowrie is
    unavailable. Omit it and an outage yields ("", "cowrie") rather than
    raising -- a dead container must never kill the session.
    """

    def __init__(self, cowrie, fallback=None, log=print, on_degrade=None,
                 sync_state: bool = True):
        self.cowrie = cowrie
        self.fallback = fallback
        self.log = log
        # Replay is the OTHER synchronisation channel: stateless agents get
        # state through the prompt, the container gets it replayed as commands.
        # sync_state used to gate only the prompt, so a "sync off" measurement
        # still replayed into Cowrie and every Cowrie reader scored 100% -- it
        # was not a withheld-state condition at all. Production never sets this.
        self.sync_state = sync_state
        # Called with no arguments every time Cowrie is unreachable and the
        # model answers instead. A callback, not an import: this module stays
        # free of storage for the same reason it stays free of agents.
        self.on_degrade = on_degrade
        self.cowrie_ckpt = 0    # last delta version Cowrie is synced to
        self._synced_gen = 0    # cowrie.generation we synced against
        self.tracker = None     # set by session.py; source of state + deltas

    @property
    def available(self) -> bool:
        return getattr(self.cowrie, "available", True)

    # ── running commands ────────────────────────────────────────────────────

    def send(self, cmd: str, write_fn=None, fallback_cmd: str = None):
        """-> (output, agent_that_actually_answered).

        `write_fn` streams output as it arrives, for commands where the pauses
        are part of the illusion (apt, wget).

        `fallback_cmd` is the text to hand the fallback when it differs from
        what Cowrie was asked. It does, and deliberately: callers pass the RAW
        command here (`sudo ls`) because that is what Cowrie should run, while
        the model should be prompted with the normalised form (`ls`) that every
        other path uses. The old closure achieved this by ignoring its own
        argument and reading handle()'s `actual_cmd` from the enclosing scope --
        same result, but invisible.
        """
        self.catch_up()                 # make Cowrie current before it runs
        try:
            gen = self.cowrie.generation
            if write_fn is not None:
                out, _ = self.cowrie.send_streaming(cmd, write_fn)
            else:
                out, _ = self.cowrie.send(cmd)
            if self.cowrie.generation != gen:   # reconnected mid-command → shell wiped
                self.catch_up()                 # rebuild, then run against real state
                if write_fn is not None:
                    out, _ = self.cowrie.send_streaming(cmd, write_fn)
                else:
                    out, _ = self.cowrie.send(cmd)
        except Exception as e:
            if self.log:
                self.log(f"[cowrie] call raised {type(e).__name__}: {e}")
            self.cowrie.available = False
            out = ""
        if not self.available:
            return self._degrade(fallback_cmd or cmd)
        return out, "cowrie"

    def _degrade(self, cmd: str):
        if self.on_degrade is not None:
            try:
                self.on_degrade()
            except Exception:
                pass            # a counter must never cost a response
        if self.fallback is None:
            return "", "cowrie"
        try:
            return self.fallback(cmd)
        except Exception as e:
            if self.log:
                self.log(f"[cowrie] fallback failed: {type(e).__name__}: {e}")
            return "", "on_device"

    # ── keeping the two filesystems in step ─────────────────────────────────

    def catch_up(self) -> None:
        """Bring Cowrie up to the latest state before it runs a command.

        Walks the tracker's deltas past our checkpoint; for each, reads the
        CURRENT value from the shared state and makes Cowrie match. Skipped
        while Cowrie is down, so the checkpoint stays behind and retries later.
        """
        if self.tracker is None or not self.available or not self.sync_state:
            return
        # A reconnect (or a new session on this shared connection) gives a fresh
        # shell at /root with no files, so rebuild from scratch when the shell
        # changed. Loop in case a replayed command triggers its own reconnect.
        state = self.tracker.state
        for _ in range(4):
            start_gen = self.cowrie.generation
            rebuild = start_gen != self._synced_gen
            if rebuild:
                self.cowrie_ckpt = 0
                # Realign cwd: a session that never ran `cd` has no delta to fix it
                self.sync(f"cd {shlex.quote(state['cwd'])}")
            for v, key, path, on_cowrie in self.tracker.deltas:
                if v <= self.cowrie_ckpt:
                    continue
                if rebuild or not on_cowrie:        # Cowrie didn't run it → replay
                    for cmd in self._delta_cmds(state, key, path):
                        self.sync(cmd)
                self.cowrie_ckpt = v
            # Shell held still → sync is trustworthy; else loop and rebuild
            if self.cowrie.generation == start_gen:
                self._synced_gen = start_gen
                break

    @staticmethod
    def _delta_cmds(state, key, path):
        """One pointer-delta → idempotent Cowrie commands (existence + perms).

        Paths are attacker-controlled, so every one is shell-quoted — otherwise
        a path like `/tmp/x;reboot` would inject a command into Cowrie's shell.
        """
        if key == "cwd":
            return [f"cd {shlex.quote(state['cwd'])}"]
        if key == "files":
            q = shlex.quote(path)
            rec = state["files"].get(path)
            if rec is None:
                return [f"rm -rf {q}"]
            perms = str(rec.get("perms", ""))
            cmds = [f"mkdir -p {q}"] if perms.startswith("d") else [_write_cmd(q, rec)]
            octal = _perms_to_octal(perms)
            if octal:
                cmds.append(f"chmod {octal} {q}")
            return cmds
        return []   # versions/installed/services/users/shadow: synced later

    def sync(self, cmd: str) -> None:
        """Replay a state change into Cowrie's real shell.

        For commands answered deterministically on our side (touch, mkdir,
        chmod) whose effect must ALSO exist in Cowrie's filesystem, because a
        later command may be routed there and would otherwise see a different
        machine. Output is discarded -- the answer was already produced.

        Best effort by design: Cowrie being down costs filesystem consistency,
        never the session.
        """
        if not self.sync_state:
            return
        try:
            self.cowrie.send(cmd)
        except Exception:
            pass

    def sync_history(self, cmd: str) -> None:
        """Append the command to Cowrie's .bash_history.

        Skipped entirely while Cowrie is known down: every command otherwise
        attempted its own reconnect and printed its own failure -- one line per
        keystroke, which buries real events and fills the disk on a busy
        sensor. send() clears the flag when it comes back.
        """
        if not self.available or not self.sync_state:
            return
        safe = cmd.replace("'", "'\\''")
        housekeeping = f"HISTFILE=~/.bash_history; history -s '{safe}'; history -w"
        try:
            self._write_history(housekeeping)
        except Exception:
            # Socket died (idle timeout, container hiccup) -- same
            # reconnect-and-retry-once pattern cowrie_agent.send() uses.
            try:
                self.cowrie._connect()
                self._write_history(housekeeping)
            except Exception as e:
                # Once per outage, not once per command. Reset when Cowrie
                # reconnects so a later outage is still reported.
                if not getattr(self.cowrie, "_history_warned", False):
                    self.cowrie._history_warned = True
                    if self.log:
                        self.log(f"[cowrie] unreachable ({type(e).__name__}) "
                                 f"— history sync paused until it returns")

    def _write_history(self, housekeeping: str) -> None:
        self.cowrie.shell.send(housekeeping + "\n")
        # Drain fully until the prompt reappears, the same way send() does,
        # instead of a fixed sleep and one recv: under load that one-shot drain
        # can miss trailing output, leaving this command's own echo in the
        # channel to bleed into a LATER, unrelated command's response.
        self.cowrie._collect_until_prompt(housekeeping)
