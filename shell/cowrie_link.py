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

    def __init__(self, cowrie, fallback=None, log=print):
        self.cowrie = cowrie
        self.fallback = fallback
        self.log = log

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
        try:
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
        if self.fallback is None:
            return "", "cowrie"
        try:
            return self.fallback(cmd)
        except Exception as e:
            if self.log:
                self.log(f"[cowrie] fallback failed: {type(e).__name__}: {e}")
            return "", "on_device"

    # ── keeping the two filesystems in step ─────────────────────────────────

    def sync(self, cmd: str) -> None:
        """Replay a state change into Cowrie's real shell.

        For commands answered deterministically on our side (touch, mkdir,
        chmod) whose effect must ALSO exist in Cowrie's filesystem, because a
        later command may be routed there and would otherwise see a different
        machine. Output is discarded -- the answer was already produced.

        Best effort by design: Cowrie being down costs filesystem consistency,
        never the session.
        """
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
        if not self.available:
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
