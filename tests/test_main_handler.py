"""
tests/test_main_handler.py — CHARACTERIZATION tests for main.make_command_handler.

These pin what the handler does TODAY. They are not a spec: where the current
behaviour looks wrong, the test records the wrong answer and says so. That is
the point -- main.py is about to be split into modules, and a refactor is only
safe if "nothing changed" is something you can check.

Run:  python3 -m unittest discover -s tests -p "test_main_handler.py" -v

Grouped by JOB, in the same grouping the split will use, so each class moves
with the code it covers:

    TestParse          sudo / busybox / argv[0]
    TestCwd            cd + working-directory tracking
    TestFiles          echo > / >> / touch / chmod state
    TestSoftware       what is installed, apt install
    TestResponders     answers produced without an LLM
    TestRouting        which agent gets the command
    TestLogging        one row per command

NOTHING REAL IS TOUCHED. Agents are fakes (no model loads, no container), and
store="json" + a temp dir keeps every write out of hydrapot.db.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main                                    # noqa: E402
from config_loader import load_config          # noqa: E402


# ── fakes ───────────────────────────────────────────────────────────────────

class FakeShell:
    def send(self, data):
        pass


class FakeCowrie:
    """Records what it was asked. Returns a marker, so "who answered" is
    visible in the output itself."""
    available = True

    def __init__(self, replies=None):
        self.sent = []
        self.replies = replies or {}
        self.shell = FakeShell()

    def _connect(self):
        pass

    def _collect_until_prompt(self, cmd, timeout=2.0):
        return ("", "")

    def send(self, cmd):
        self.sent.append(cmd)
        return self.replies.get(cmd.strip(), "<cowrie>"), "cowrie"

    def send_streaming(self, cmd, write_fn):
        out, _ = self.send(cmd)
        write_fn(out)
        return out, "cowrie"

    def send_interactive(self, cmd, write_fn, read_fn):
        return self.send(cmd)


class FakeLLM:
    def __init__(self, marker):
        self.marker = marker
        self.prompts = []

    def send(self, system_prompt, user_prompt):
        self.prompts.append(user_prompt)
        return self.marker

    def send_with_usage(self, system_prompt, user_prompt):
        return self.send(system_prompt, user_prompt), None


def setUpModule():
    """main.config/ondevice/cloud are module globals set by main(). Tests never
    call main(), so they are wired here once."""
    main.config = load_config()
    main.ondevice = FakeLLM("<ondevice>")
    main.cloud = FakeLLM("<cloud>")


class HandlerCase(unittest.TestCase):
    """One fresh session per test -- SYSTEM_STATE is per-session by design, and
    sharing it between tests would let one test's `cd` change another's answer."""

    def setUp(self):
        # main.ondevice/cloud are module globals, so a fake left in place would
        # carry one test's prompts into the next. Replaced per test.
        main.ondevice = FakeLLM("<ondevice>")
        main.cloud = FakeLLM("<cloud>")
        self.cowrie = FakeCowrie()
        self.logdir = tempfile.mkdtemp(prefix="hp_test_")
        self.h = main.make_command_handler(
            self.cowrie, src_ip="10.0.0.9", username="root",
            store="json", store_dir=self.logdir, sync_state=False)

    def run_cmd(self, cmd):
        """-> whatever the attacker would see (streamed output included)."""
        buf = []
        out, _ = self.h(cmd, write_fn=buf.append, read_fn=lambda: "")
        return out or "".join(buf)

    def agent(self):
        return self.h.last_agent

    def log_rows(self):
        path = os.path.join(self.logdir, "10.0.0.9.jsonl")
        if not os.path.exists(path):
            return []
        return [json.loads(l) for l in open(path, encoding="utf-8")]


# ── parse ───────────────────────────────────────────────────────────────────

class TestParse(HandlerCase):

    def test_sudo_prefix_does_not_change_the_answer(self):
        """REGRESSION. Routing used to read the FULL command, so `_base_cmd`
        saw "sudo", missed COWRIE_AUTHORITATIVE, and fell through to the FI band
        where a leading `sudo` scores as elevation. Every `sudo <anything>` went
        to the model -- walking straight past the command-not-found guard, which
        is the only thing that stops a prompt being built at all.

        The attacker is already root, so `sudo X` IS `X` (base_prompt rule 2b).
        Same command, same answerer, same output."""
        for bare in ("notarealcmd", "ls", "nginx -v"):
            with self.subTest(cmd=bare):
                out_bare = self.run_cmd(bare)
                agent_bare = self.agent()
                out_sudo = self.run_cmd(f"sudo {bare}")
                self.assertEqual(self.agent(), agent_bare)
                self.assertEqual(out_sudo, out_bare)

    def test_sudo_unknown_command_never_reaches_a_model(self):
        """The hole this closed: no prompt may be built for `sudo <gibberish>`."""
        self.assertEqual(self.run_cmd("sudo notarealcmd"),
                         "bash: notarealcmd: command not found")
        self.assertEqual(main.ondevice.prompts, [])
        self.assertEqual(main.cloud.prompts, [])

    def test_busybox_rewrite_changes_routing_not_what_cowrie_receives(self):
        """`busybox X` routes as `X`, but Cowrie still gets the original text --
        it runs a real busybox and handles the wrapper itself."""
        self.run_cmd("busybox whoami")
        self.assertEqual(self.cowrie.sent[-1], "busybox whoami")

    def test_bare_busybox_is_left_alone(self):
        self.run_cmd("busybox")
        self.assertEqual(self.cowrie.sent[-1], "busybox")

    def test_unknown_busybox_applet_uses_the_busybox_error(self):
        """REGRESSION. busybox is a dispatcher, so an unknown applet is
        "X: applet not found" (base_prompt.txt rule 3). The wrapper rewrite used
        to erase how the command was invoked, and bash answered for it."""
        for form in ("/bin/busybox XKQPL", "busybox XKQPL"):
            with self.subTest(cmd=form):
                self.assertEqual(self.run_cmd(form), "XKQPL: applet not found")

    def test_a_bare_unknown_command_still_answers_as_bash(self):
        """The busybox message must not leak onto the ordinary path."""
        self.assertEqual(self.run_cmd("XKQPL"),
                         "bash: XKQPL: command not found")


# ── cwd ─────────────────────────────────────────────────────────────────────

class TestCwd(HandlerCase):

    def test_successful_cd_is_silent(self):
        self.assertEqual(self.run_cmd("cd /tmp"), "")

    def test_cd_to_unknown_directory_is_a_real_bash_error(self):
        self.assertEqual(self.run_cmd("cd /nope"),
                         "bash: cd: /nope: No such file or directory")

    def test_cd_rejects_two_paths_like_bash_does(self):
        self.assertEqual(self.run_cmd("cd /etc /var"),
                         "bash: cd: too many arguments")

    def test_bare_cd_and_tilde_both_go_home_silently(self):
        self.assertEqual(self.run_cmd("cd"), "")
        self.assertEqual(self.run_cmd("cd ~"), "")

    def test_cwd_survives_and_relative_paths_resolve_against_it(self):
        """`cd /tmp` then `touch x` must track /tmp/x, not /root/x -- one key
        per real file."""
        self.run_cmd("cd /tmp")
        self.run_cmd("touch x")
        self.run_cmd("cd /root")
        self.assertEqual(self.run_cmd("cat /tmp/x"), "<ondevice>")

    def test_cd_is_never_answered_by_a_model(self):
        """A model that wrongly accepts `cd .ssh` answers every later command
        from a directory that does not exist."""
        for target in ("/tmp", "/nope", "/etc /var"):
            self.run_cmd(f"cd {target}")
            self.assertEqual(self.agent(), "cowrie")


# ── files ───────────────────────────────────────────────────────────────────

class TestFiles(HandlerCase):

    def test_echo_redirect_makes_the_file_readable(self):
        self.run_cmd("echo hello > a.txt")
        self.run_cmd("cat a.txt")
        self.assertEqual(self.agent(), "on_device",
                         "a tracked file must be read by the side that owns it")

    def test_append_keeps_the_file_tracked(self):
        self.run_cmd("echo one > a.txt")
        self.run_cmd("echo two >> a.txt")
        self.run_cmd("cat a.txt")
        self.assertEqual(self.agent(), "on_device")

    def test_touch_then_chmod_is_silent(self):
        self.run_cmd("touch b.sh")
        self.assertEqual(self.run_cmd("chmod 755 b.sh"), "")

    def test_untracked_file_is_not_claimed(self):
        self.run_cmd("cat /does/not/exist")
        self.assertEqual(self.agent(), "cowrie")


# ── software ────────────────────────────────────────────────────────────────

class TestSoftware(HandlerCase):

    def test_unknown_command_never_reaches_a_model(self):
        """The cheapest guard there is: no prompt is built, so there is nothing
        to inject into."""
        self.assertEqual(self.run_cmd("notarealcmd"),
                         "bash: notarealcmd: command not found")
        self.assertEqual(self.agent(), "cowrie")
        self.assertEqual(main.ondevice.prompts, [])

    def test_install_gated_tool_is_absent_until_installed(self):
        self.assertEqual(self.run_cmd("nginx -v"), "bash: nginx: command not found")

    def test_apt_install_registers_the_package(self):
        out = self.run_cmd("apt install nmap")
        self.assertIn("Setting up nmap", out)

    def test_every_missing_command_spells_the_error_the_same_way(self):
        """REGRESSION. The editor path printed `-bash:` (what a LOGIN shell
        prints) while every other path printed `bash:`. Two spellings in one
        session is a fingerprint. CRLF stays -- that path streams to the
        terminal, where \\r\\n is the correct line ending."""
        self.assertEqual(self.run_cmd("vim"), "bash: vim: command not found\r\n")
        self.assertEqual(self.run_cmd("notarealcmd"),
                         "bash: notarealcmd: command not found")


# ── responders ──────────────────────────────────────────────────────────────

class TestResponders(HandlerCase):

    def test_version_queries_are_answered_from_config_not_a_model(self):
        self.assertEqual(self.run_cmd("python3 --version"), "Python 3.10.12")
        self.assertEqual(main.ondevice.prompts, [])

    def test_dash_v_is_treated_as_a_version_query(self):
        self.assertEqual(self.run_cmd("curl -V"),
                         "curl 7.81.0 (x86_64-pc-linux-gnu)")

    def test_systemctl_remembers_what_the_attacker_did(self):
        """stop then status must not still claim 'active (running)' -- an
        attacker probes exactly that."""
        self.assertIn("active (running)", self.run_cmd("systemctl status ssh"))
        self.run_cmd("systemctl stop ssh")
        self.assertIn("inactive (dead)", self.run_cmd("systemctl status ssh"))

    def test_uname_flags_answer_from_configured_identity(self):
        self.assertEqual(self.run_cmd("uname"), "Linux")
        self.assertEqual(self.run_cmd("uname -r"), "5.15.0-91-generic")
        self.assertIn("5.15.0-91-generic", self.run_cmd("uname -a"))

    def test_bare_assignment_produces_no_output(self):
        self.assertEqual(self.run_cmd("FOO=1"), "")
        self.assertEqual(self.run_cmd("unset FOO"), "")


# ── routing ─────────────────────────────────────────────────────────────────

class TestRouting(HandlerCase):
    """The routing table as it stands. A refactor that moves _needs_llm or the
    override chain must leave every one of these unchanged."""

    CASES = [
        ("ls",                             "cowrie"),
        ("ps aux",                         "cowrie"),
        ("wget http://x/y.sh",             "cowrie"),
        ("nmap -sV 10.0.0.1",              "cowrie"),
        ("find / -perm -4000 2>/dev/null", "cowrie"),
        ("cat /etc/passwd",                "on_device"),
        ("cat /etc/shadow",                "on_device"),
        ("gcc x.c",                        "on_device"),
        ("hostname",                       "on_device"),
    ]

    def test_routing_table(self):
        for cmd, expected in self.CASES:
            with self.subTest(cmd=cmd):
                self.run_cmd(cmd)
                self.assertEqual(self.agent(), expected)

    def test_cowrie_being_down_moves_traffic_to_the_model(self):
        self.cowrie.available = False
        self.run_cmd("ls")
        self.assertEqual(self.agent(), "on_device")


# ── logging ─────────────────────────────────────────────────────────────────

class TestOneLlmSeam(unittest.TestCase):
    """Every model call goes through _llm_send().

    Structural, not behavioural, and deliberately so: the guardrail hooks this
    one function, and a ninth call site added inline later would bypass input
    checks and the output validator silently -- nothing would fail, the honeypot
    would just stop being guarded. This test is what makes that a build error.
    """

    SEAM_FILE = os.path.join("shell", "session.py")

    def _source(self):
        """shell/session.py, which is where the handler lives now -- main.py is
        the entry point and holds no honeypot behaviour."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return open(os.path.join(root, self.SEAM_FILE),
                    encoding="utf-8").read().split("\n")

    def test_no_raw_model_call_outside_the_seam(self):
        import re
        raw = re.compile(r"\b(ondevice|cloud|agent_obj)\.send(_with_usage)?\s*\(")
        lines = self._source()
        seam = [i for i, l in enumerate(lines) if "def _llm_send(" in l]
        self.assertEqual(len(seam), 1, "expected exactly one _llm_send definition")
        start = seam[0]
        end = next(i for i in range(start + 1, len(lines))
                   if lines[i].strip() and not lines[i].startswith("        ")
                   and not lines[i].strip().startswith("#"))

        offenders = [f"{self.SEAM_FILE}:{i+1}: {l.strip()}"
                     for i, l in enumerate(lines)
                     if raw.search(l) and not (start <= i < end)]
        self.assertEqual(offenders, [],
                         "call _llm_send() instead -- it is the only seam the "
                         "guardrail can hook:\n  " + "\n  ".join(offenders))

    def test_the_seam_owns_the_missing_agent_check(self):
        """Three callers used to each re-check `is not None` before sending.
        Those guards were dropped because _llm_send returns "" for a missing
        agent -- so the early return has to still be there."""
        lines = self._source()
        start = next(i for i, l in enumerate(lines) if "def _llm_send(" in l)
        body = "\n".join(lines[start:start + 30])
        self.assertIn("if agent_obj is None:", body)
        self.assertIn('return ""', body)


class TestLogging(HandlerCase):

    REQUIRED = {"session_id", "src_ip", "public_ip", "timestamp", "cmd",
                "agent", "response", "fi_score", "latency_ms", "instance"}

    def test_one_row_per_command(self):
        for c in ("whoami", "pwd", "notarealcmd"):
            self.run_cmd(c)
        self.assertEqual(len(self.log_rows()), 3)

    def test_every_row_carries_the_fields_the_siem_reads(self):
        self.run_cmd("whoami")
        self.assertTrue(self.REQUIRED.issubset(self.log_rows()[0]))

    def test_the_logged_agent_is_the_one_that_actually_answered(self):
        self.run_cmd("notarealcmd")
        self.assertEqual(self.log_rows()[-1]["agent"], "cowrie")

    def test_fi_and_routing_score_the_same_string(self):
        """REGRESSION. FI was scored from the raw command and routing from the
        sudo-stripped one, so `sudo X` logged the elevation band (FI_RULES has
        `^(sudo|su\\s)`) while being routed as plain X. The number that decides
        routing and the number the SIEM stores have to come from one string."""
        for bare in ("whoami", "ls", "cat /etc/shadow"):
            with self.subTest(cmd=bare):
                self.run_cmd(bare)
                fi_bare = self.log_rows()[-1]["fi_score"]
                self.run_cmd(f"sudo {bare}")
                row = self.log_rows()[-1]
                self.assertEqual(row["fi_score"], fi_bare)
                self.assertEqual(row["cmd"], f"sudo {bare}",
                                 "the logged TEXT stays what the attacker typed")

    def test_fi_is_recorded_but_is_not_a_severity(self):
        """FI is the routing metric. It belongs in the row; it must never be
        read as how dangerous the command was."""
        self.run_cmd("cat /etc/shadow")
        row = self.log_rows()[-1]
        self.assertIn("fi_score", row)
        self.assertNotIn("severity", row)


if __name__ == "__main__":
    unittest.main(verbosity=2)
