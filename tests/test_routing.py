"""
tests/test_routing.py — does this command need a model at all?

Not the same question as router.py's (which agent, from the FI band). This one
depends on SESSION STATE, so the answer changes as the session runs.

Run:  python3 -m unittest discover -s tests -p "test_routing.py" -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.fakefs import FakeFS                  # noqa: E402
from shell.routing import Routing                # noqa: E402
from shell.software import Software              # noqa: E402


def routing(files=None, installed=None, cwd="/root"):
    state = {
        "cwd": cwd, "files": files or {}, "installed": installed or {},
        "versions": {}, "services": {},
        "users": {"root": {"uid": 0, "home": "/root"}}, "shadow": {},
    }
    fs = FakeFS(state, "root", {"/", "/etc", "/tmp"})
    sw = Software(state, base_tools=["ls", "cat", "sed", "wget"],
                  tool_packages={"nc": "netcat"},
                  default_versions={"wget": "GNU Wget 1.21.2"},
                  pre_installed=["wget"])
    sw.seed_pre_installed()
    return Routing(state, fs, sw), state


class TestAlwaysLocal(unittest.TestCase):
    """Answered from our own state, never from the container."""

    def test_service_and_identity_commands_need_a_model(self):
        r, _ = routing()
        for base in ("systemctl", "service", "journalctl", "hostname",
                     "gcc", "g++", "make", "gdb", "strace", "ltrace"):
            with self.subTest(base=base):
                self.assertTrue(r.needs_llm(base, base))

    def test_an_ordinary_coreutil_does_not(self):
        r, _ = routing()
        for cmd, base in (("ls -la", "ls"), ("whoami", "whoami"), ("ps aux", "ps")):
            with self.subTest(cmd=cmd):
                self.assertFalse(r.needs_llm(cmd, base))


class TestVersionQueries(unittest.TestCase):

    def test_a_version_is_answerable_only_for_a_tool_that_exists_here(self):
        r, _ = routing()
        self.assertTrue(r.needs_llm("wget --version", "wget"))
        self.assertFalse(r.needs_llm("nginx --version", "nginx"))

    def test_installing_makes_the_version_answerable(self):
        r, st = routing()
        self.assertFalse(r.needs_llm("nginx --version", "nginx"))
        st["installed"]["nginx"] = {"version": "1.0"}
        self.assertTrue(r.needs_llm("nginx --version", "nginx"))

    def test_lowercase_dash_v_counts_for_the_tools_that_spell_it_that_way(self):
        """REGRESSION. The shared pattern is `--version|-V`, right for
        coreutils but wrong for nginx, node and php, which use -v. Widening the
        regex is NOT the fix: -v means invert for grep and verbose for rm, ssh
        and curl. Per-tool."""
        r, st = routing()
        st["installed"]["nginx"] = {"version": "1.0"}
        for form in ("nginx -v", "nginx -V", "nginx --version"):
            with self.subTest(cmd=form):
                self.assertTrue(r.needs_llm(form, "nginx"))

    def test_dash_v_still_means_invert_or_verbose_everywhere_else(self):
        r, _ = routing()
        for cmd, base in (("grep -v x f", "grep"), ("rm -v f", "rm"),
                          ("curl -v http://x", "curl"), ("ls -v", "ls")):
            with self.subTest(cmd=cmd):
                self.assertFalse(Routing.is_version_query(cmd, base))


class TestAttackerInstalled(unittest.TestCase):

    def test_what_the_attacker_installed_is_worth_a_model(self):
        r, st = routing()
        st["installed"]["nmap"] = {"version": "1.0"}
        self.assertTrue(r.needs_llm("nmap -sV 1.1.1.1", "nmap"))

    def test_what_the_box_shipped_with_is_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("wget http://x/y", "wget"))


class TestCat(unittest.TestCase):
    """The rule: a model is needed when only THIS session knows the answer."""

    def test_a_file_only_we_hold_needs_a_model(self):
        r, _ = routing(files={"/root/n.txt": {"content": "hi"}})
        self.assertTrue(r.needs_llm("cat n.txt", "cat"))

    def test_every_spelling_of_that_path_agrees(self):
        r, _ = routing(files={"/root/n.txt": {"content": "hi"}})
        for spelling in ("n.txt", "./n.txt", "/root/n.txt", "~/n.txt"):
            with self.subTest(spelling=spelling):
                self.assertTrue(r.needs_llm(f"cat {spelling}", "cat"))

    def test_generated_files_always_need_a_model(self):
        r, _ = routing()
        self.assertTrue(r.needs_llm("cat /etc/passwd", "cat"))
        self.assertTrue(r.needs_llm("cat /etc/shadow", "cat"))

    def test_a_file_cowrie_downloaded_does_not(self):
        """Cowrie holds the true bytes; ours is a placeholder. Claiming it sent
        `cat` to on_device, which answered "No such file or directory" for a
        file `ls` had just listed at 5,278 bytes."""
        r, _ = routing(files={"/root/r.sh": {"content": "[downloaded from x]",
                                             "backend": "cowrie"}})
        self.assertFalse(r.needs_llm("cat r.sh", "cat"))

    def test_a_tracked_but_empty_file_does_not(self):
        r, _ = routing(files={"/root/e.txt": {"content": ""}})
        self.assertFalse(r.needs_llm("cat e.txt", "cat"))

    def test_an_untracked_file_does_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("cat /etc/hosts", "cat"))

    def test_flags_are_skipped_when_looking_at_the_arguments(self):
        r, _ = routing(files={"/root/n.txt": {"content": "hi"}})
        self.assertTrue(r.needs_llm("cat -n n.txt", "cat"))

    def test_bare_cat_does_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("cat", "cat"))

    def test_one_qualifying_argument_is_enough(self):
        r, _ = routing(files={"/root/n.txt": {"content": "hi"}})
        self.assertTrue(r.needs_llm("cat /etc/hosts n.txt", "cat"))


class TestScripts(unittest.TestCase):

    def test_an_interpreter_given_a_script_we_hold_needs_a_model(self):
        r, _ = routing(files={"s.sh": {"content": "#!/bin/sh"}})
        for base in ("bash", "sh", "python3", "perl", "ruby"):
            with self.subTest(base=base):
                self.assertTrue(r.needs_llm(f"{base} s.sh", base))

    def test_an_interpreter_with_no_script_does_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("bash", "bash"))
        self.assertFalse(r.needs_llm("bash ghost.sh", "bash"))

    def test_running_a_tracked_script_directly_needs_a_model(self):
        r, _ = routing(files={"s.sh": {"content": "#!/bin/sh"}})
        self.assertTrue(r.needs_llm("./s.sh", "./s.sh"))

    def test_running_an_untracked_one_does_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("./ghost.sh", "./ghost.sh"))


class TestSed(unittest.TestCase):

    def test_editing_a_file_we_hold_needs_a_model(self):
        r, _ = routing(files={"n.txt": {"content": "hi"}})
        self.assertTrue(r.needs_llm("sed -i 's/a/b/' n.txt", "sed"))

    def test_editing_an_unknown_file_does_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("sed -i 's/a/b/' ghost", "sed"))

    def test_bare_sed_does_not(self):
        r, _ = routing()
        self.assertFalse(r.needs_llm("sed", "sed"))


class TestStateChangesTheAnswer(unittest.TestCase):
    """The whole reason this is per-session and not a static rule."""

    def test_the_same_command_flips_once_the_file_exists(self):
        r, st = routing()
        self.assertFalse(r.needs_llm("cat n.txt", "cat"))
        st["files"]["/root/n.txt"] = {"content": "hi"}
        self.assertTrue(r.needs_llm("cat n.txt", "cat"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
