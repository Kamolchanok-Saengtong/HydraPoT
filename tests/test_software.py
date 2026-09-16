"""
tests/test_software.py — what is installed on the fake box, on its own.

No config.yaml, no agents, no database. Software holds a plain dict.

Run:  python3 -m unittest discover -s tests -p "test_software.py" -v
"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.software import (Software, canonical_package, parse_base_tools,   # noqa: E402
                            random_version)


def sw(installed=None, versions=None, **kw):
    state = {"installed": installed or {}, "versions": versions or {}}
    kw.setdefault("base_tools", ["ls, cat, echo", "grep"])
    kw.setdefault("tool_packages", {"nc": "netcat", "vi": "vim"})
    kw.setdefault("default_versions", {"wget": "GNU Wget 1.21.2"})
    kw.setdefault("pre_installed", ["wget"])
    return Software(state, **kw)


class TestParseBaseTools(unittest.TestCase):
    """config.yaml writes these comma-per-line for readability."""

    def test_one_line_may_list_several_tools(self):
        self.assertEqual(parse_base_tools(["ls, cat,echo"]), {"ls", "cat", "echo"})

    def test_blanks_and_padding_are_dropped(self):
        self.assertEqual(parse_base_tools(["  ls  ,, ", "", "cat"]), {"ls", "cat"})

    def test_missing_config_is_not_an_error(self):
        self.assertEqual(parse_base_tools(None), set())


class TestAvailability(unittest.TestCase):

    def test_base_tools_are_always_present(self):
        s = sw()
        for tool in ("ls", "cat", "echo", "grep"):
            with self.subTest(tool=tool):
                self.assertTrue(s.available(tool))

    def test_shell_builtins_count_as_present(self):
        """`cd --version` used to report command-not-found for something bash
        itself provides."""
        self.assertTrue(sw().available("cd"))

    def test_an_uninstalled_tool_is_absent(self):
        self.assertFalse(sw().available("nmap"))

    def test_a_command_provided_by_an_installed_package_is_present(self):
        """`nc` comes from `netcat` -- installing the package must make the
        command work, not just the package name."""
        s = sw(installed={"netcat": {"version": "1.0"}})
        self.assertTrue(s.available("nc"))


class TestInstalledByAttacker(unittest.TestCase):
    """Routing cares about the difference: a tool they installed themselves is
    worth a better agent than a coreutil."""

    def test_base_tools_are_never_attacker_installed(self):
        self.assertFalse(sw().available("ls") and sw().installed_by_attacker("ls"))

    def test_pre_installed_is_not_attacker_installed(self):
        s = sw()
        s.seed_pre_installed()
        self.assertTrue(s.available("wget"))
        self.assertFalse(s.installed_by_attacker("wget"))

    def test_what_the_attacker_installed_is_flagged(self):
        s = sw()
        s.install(["nmap"], log=None)
        self.assertTrue(s.installed_by_attacker("nmap"))

    def test_it_also_sees_through_the_package_mapping(self):
        s = sw()
        s.install(["netcat"], log=None)
        self.assertTrue(s.installed_by_attacker("nc"))


class TestVersions(unittest.TestCase):

    def test_configured_versions_win(self):
        s = sw()
        self.assertEqual(s.version("wget"), "GNU Wget 1.21.2")

    def test_a_version_is_decided_once_and_remembered(self):
        """Two identical commands must not report two versions -- that is a
        contradiction an attacker can probe for."""
        s = sw()
        first = s.version("mystery")
        self.assertEqual(s.version("mystery"), first)
        self.assertEqual(s.state["versions"]["mystery"], first)

    def test_an_installed_package_reports_its_registered_version(self):
        s = sw()
        s.install(["nmap"], log=None)
        self.assertIn(s.state["installed"]["nmap"]["version"], s.version("nmap"))


class TestCanonicalPackage(unittest.TestCase):
    """`apt install python3.11` must make `python3` work, not a command called
    python3.11 that nothing would ever run."""

    def test_versioned_names_map_to_the_command_they_provide(self):
        for pkg, command in (("python3.11", "python3"), ("python2.7", "python2"),
                             ("gcc-12", "gcc"), ("g++-12", "g++"),
                             ("ruby2.7", "ruby"), ("php8.1", "php"),
                             ("nodejs18", "node")):
            with self.subTest(pkg=pkg):
                self.assertEqual(canonical_package(pkg), command)

    def test_an_ordinary_name_is_unchanged(self):
        self.assertEqual(canonical_package("nmap"), "nmap")

    def test_installing_a_versioned_package_registers_the_command(self):
        s = sw()
        s.install(["python3.11"], log=None)
        self.assertTrue(s.available("python3"))
        self.assertNotIn("python3.11", s.state["installed"])


class TestInstallAndRemove(unittest.TestCase):

    def test_install_makes_the_tool_available(self):
        s = sw()
        self.assertFalse(s.available("nmap"))
        s.install(["nmap"], log=None)
        self.assertTrue(s.available("nmap"))

    def test_installing_twice_does_not_change_the_version(self):
        s = sw()
        s.install(["nmap"], log=None)
        first = s.state["installed"]["nmap"]["version"]
        s.install(["nmap"], log=None)
        self.assertEqual(s.state["installed"]["nmap"]["version"], first)

    def test_remove_drops_the_package_and_its_cached_version(self):
        s = sw()
        s.install(["nmap"], log=None)
        s.version("nmap")
        s.remove(["nmap"])
        self.assertFalse(s.available("nmap"))
        self.assertNotIn("nmap", s.state["versions"])

    def test_seed_parses_the_version_number_out_of_the_display_string(self):
        """The apt transcript and `--version` were two independent strings
        before, and disagreed."""
        s = sw()
        s.seed_pre_installed()
        self.assertEqual(s.state["installed"]["wget"]["version"], "1.21.2")
        self.assertEqual(s.state["installed"]["wget"]["version_str"], "GNU Wget 1.21.2")


class TestAptOutput(unittest.TestCase):

    def test_the_transcript_matches_the_state_it_registered(self):
        random.seed(7)
        s = sw()
        s.install(["nmap"], log=None)
        out = s.apt_output(["nmap"])
        ver = s.state["installed"]["nmap"]["version"]
        self.assertIn(f"Setting up nmap ({ver})", out)
        self.assertIn(f"Unpacking nmap ({ver})", out)
        self.assertIn("Reading package lists... Done", out)

    def test_it_counts_the_packages_it_was_given(self):
        random.seed(7)
        s = sw()
        s.install(["nmap", "socat"], log=None)
        self.assertIn("2 newly installed", s.apt_output(["nmap", "socat"]))


class TestSessionIsolation(unittest.TestCase):

    def test_one_sessions_install_is_invisible_to_another(self):
        a, b = sw(), sw()
        a.install(["nmap"], log=None)
        self.assertTrue(a.available("nmap"))
        self.assertFalse(b.available("nmap"))


class TestRandomVersion(unittest.TestCase):

    def test_it_looks_like_a_version(self):
        random.seed(3)
        for _ in range(20):
            parts = random_version().split(".")
            self.assertEqual(len(parts), 3)
            self.assertTrue(all(p.isdigit() for p in parts))


if __name__ == "__main__":
    unittest.main(verbosity=2)
