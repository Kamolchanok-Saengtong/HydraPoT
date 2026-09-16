"""
tests/test_fakefs.py — the pretend filesystem, on its own.

These need no config.yaml, no agents, no database and no Cowrie: FakeFS holds a
plain dict and reads it. That is the point of pulling it out of main.py -- the
same logic used to be reachable only by starting a whole session.

Run:  python3 -m unittest discover -s tests -p "test_fakefs.py" -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.fakefs import FakeFS, mode_to_perms   # noqa: E402


def state(cwd="/root", files=None, users=None, shadow=None):
    return {
        "cwd": cwd,
        "files": files if files is not None else {},
        "users": users if users is not None else {
            "root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
            "cocadmin": {"uid": 1000, "gid": 1000, "home": "/home/cocadmin",
                         "shell": "/bin/bash"},
        },
        "shadow": shadow if shadow is not None else {"root": "$6$abc$def"},
    }


def fs(**kw):
    user = kw.pop("username", "root")
    dirs = kw.pop("known_dirs", {"/", "/etc", "/tmp", "/var", "/usr", "/home"})
    return FakeFS(state(**kw), username=user, known_dirs=dirs)


class TestResolve(unittest.TestCase):
    """One key per real file. Every spelling of a path must collapse to one."""

    def test_every_spelling_of_one_file_is_one_key(self):
        f = fs(cwd="/root")
        for spelling in ("x", "./x", "/root/x", "~/x", "/root/./x", "/root/../root/x"):
            with self.subTest(spelling=spelling):
                self.assertEqual(f.resolve(spelling), "/root/x")

    def test_relative_paths_follow_the_current_directory(self):
        self.assertEqual(fs(cwd="/tmp").resolve("bar"), "/tmp/bar")
        self.assertEqual(fs(cwd="/var/log").resolve("../run/x"), "/var/run/x")

    def test_tilde_is_the_logged_in_users_home_not_always_root(self):
        self.assertEqual(fs(username="cocadmin").resolve("~/k"), "/home/cocadmin/k")

    def test_quotes_and_whitespace_are_stripped(self):
        f = fs(cwd="/tmp")
        for spelling in ('"a"', "'a'", "  a  "):
            with self.subTest(spelling=spelling):
                self.assertEqual(f.resolve(spelling), "/tmp/a")

    def test_empty_path_is_returned_unchanged(self):
        self.assertEqual(fs().resolve(""), "")

    def test_interior_and_trailing_slashes_collapse(self):
        self.assertEqual(fs().resolve("/tmp//x//"), "/tmp/x")

    def test_a_leading_double_slash_makes_a_second_key_for_one_file(self):
        """PINNED BUG, pre-existing.

        POSIX leaves a LEADING "//" implementation-defined, and posixpath keeps
        exactly two, so these are different dict keys for the same file:

            resolve("/tmp/x")    -> /tmp/x
            resolve("//tmp/x")   -> //tmp/x

        Which breaks the one-key-per-file rule this module exists to enforce:
        `touch //tmp/a` then `cat /tmp/a` looks like two unrelated files.
        Obscure, but it is exactly the kind of inconsistency an attacker
        probes for. Fix is one lstrip; separate change."""
        self.assertEqual(fs().resolve("//tmp//x//"), "//tmp/x")
        self.assertNotEqual(fs().resolve("//tmp/x"), fs().resolve("/tmp/x"))


class TestComputeCd(unittest.TestCase):
    """Pure: it decides, it never writes. update_state() and the responder both
    call it and must get the same answer."""

    def test_known_directory_succeeds(self):
        self.assertEqual(fs().compute_cd("cd /tmp"), (True, "/tmp", None))

    def test_bare_cd_and_tilde_go_home(self):
        for cmd in ("cd", "cd ~"):
            with self.subTest(cmd=cmd):
                self.assertEqual(fs().compute_cd(cmd), (True, "/root", None))

    def test_two_paths_is_the_bash_error(self):
        self.assertEqual(fs().compute_cd("cd /etc /var"),
                         (True, None, "bash: cd: too many arguments"))

    def test_cd_dash_silently_goes_home(self):
        """PINNED BUG, pre-existing -- verified identical before this module was
        split out of main.py.

        compute_cd filters flags first:

            positional = [a for a in args if not a.startswith("-")]

        "-" starts with "-", so it is dropped, positional comes back empty and
        target defaults to "~". The `if target == "-"` branch below it can
        therefore never run -- it is dead code, and the docstring's
        "(False, None, None) -> not handled here (e.g. `cd -`)" is not what
        happens.

        Real bash goes to $OLDPWD and prints it. Here `cd /tmp; cd -` lands in
        /root silently, so an attacker who uses `cd -` is somewhere other than
        where the honeypot thinks. Fix needs $OLDPWD tracking; separate change."""
        self.assertEqual(fs().compute_cd("cd -"), (True, "/root", None))

    def test_a_tracked_file_is_not_a_directory(self):
        f = fs(files={"/root/note.txt": {"perms": "-rw-r--r--"}})
        self.assertEqual(f.compute_cd("cd note.txt"),
                         (True, None, "bash: cd: note.txt: Not a directory"))

    def test_a_tracked_directory_is_enterable(self):
        f = fs(files={"/root/sub": {"perms": "drwxr-xr-x"}})
        self.assertEqual(f.compute_cd("cd sub"), (True, "/root/sub", None))

    def test_every_users_home_is_reachable(self):
        self.assertEqual(fs().compute_cd("cd /home/cocadmin"),
                         (True, "/home/cocadmin", None))

    def test_unknown_directory_publishes_the_resolved_path_for_the_cowrie_probe(self):
        """The caller asks Cowrie about this path before the error is shown --
        Cowrie's tree holds ~26,000 entries we never declared."""
        f = fs(cwd="/root")
        handled, cwd, err = f.compute_cd("cd portal")
        self.assertEqual((handled, cwd), (True, None))
        self.assertIn("No such file or directory", err)
        self.assertEqual(f.last_resolved, "/root/portal")

    def test_it_never_writes_to_state(self):
        f = fs()
        before = {k: repr(v) for k, v in f.state.items()}
        for cmd in ("cd /tmp", "cd nope", "cd /etc /var", "cd -", "cd ~"):
            f.compute_cd(cmd)
        self.assertEqual({k: repr(v) for k, v in f.state.items()}, before)

    def test_flags_are_ignored_when_counting_arguments(self):
        self.assertEqual(fs().compute_cd("cd -P /tmp"), (True, "/tmp", None))


class TestVirtualFiles(unittest.TestCase):

    def test_passwd_is_generated_from_the_configured_persona(self):
        out = fs().passwd()
        self.assertIn("root:x:0:0:root:/root:/bin/bash", out)
        self.assertIn("cocadmin:x:1000:1000:cocadmin:/home/cocadmin:/bin/bash", out)

    def test_shadow_covers_every_user_and_stars_the_ones_with_no_hash(self):
        out = fs().shadow().splitlines()
        self.assertEqual(len(out), 2)
        self.assertTrue(out[0].startswith("root:$6$abc$def:"))
        self.assertTrue(out[1].startswith("cocadmin:*:"))

    def test_virtual_files_are_generated_on_read_not_stored(self):
        """Editing the persona must show up immediately; two stored copies
        would drift."""
        f = fs()
        f.state["users"]["newguy"] = {"uid": 1500, "home": "/home/newguy"}
        self.assertIn("newguy", f.passwd())
        self.assertIn("newguy", f.shadow())

    def test_is_virtual_only_claims_the_generated_pair(self):
        f = fs()
        self.assertTrue(f.is_virtual("/etc/passwd"))
        self.assertTrue(f.is_virtual("/etc/shadow"))
        self.assertFalse(f.is_virtual("/etc/hosts"))

    def test_tracked_file_content_comes_back_through_the_same_call(self):
        f = fs(cwd="/tmp", files={"/tmp/a": {"content": "hello"}})
        self.assertEqual(f.virtual_file("a"), "hello")

    def test_unknown_path_is_none(self):
        self.assertIsNone(fs().virtual_file("/nope/x"))


class TestModeToPerms(unittest.TestCase):

    def test_known_modes(self):
        for mode, expected in (("777", "-rwxrwxrwx"), ("644", "-rw-r--r--"),
                               ("600", "-rw-------"), ("755", "-rwxr-xr-x"),
                               ("000", "----------")):
            with self.subTest(mode=mode):
                self.assertEqual(mode_to_perms(mode), expected)

    def test_a_four_digit_mode_uses_the_last_three(self):
        self.assertEqual(mode_to_perms("0644"), "-rw-r--r--")


class TestSessionIsolation(unittest.TestCase):
    """Two sessions must never see each other's files -- the reason this is a
    class holding one state dict rather than functions over a global."""

    def test_two_sessions_do_not_share_state(self):
        a, b = fs(cwd="/root"), fs(cwd="/root")
        a.state["files"]["/root/secret"] = {"content": "x"}
        self.assertEqual(a.virtual_file("/root/secret"), "x")
        self.assertIsNone(b.virtual_file("/root/secret"))

    def test_state_is_held_by_reference_so_live_mutations_are_visible(self):
        f = fs(cwd="/root")
        f.state["cwd"] = "/tmp"
        self.assertEqual(f.resolve("x"), "/tmp/x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
