"""
tests/test_telemetry.py — writing down what happened.

The DB writer, the MITRE tagger and the SIEM exporter are all injected, so
nothing here touches hydrapot.db or loads the ATT&CK catalog.

Run:  python3 -m unittest discover -s tests -p "test_telemetry.py" -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shell.telemetry import Telemetry           # noqa: E402


def tel(**kw):
    rows, events, logged = [], [], []
    kw.setdefault("tag", lambda cmd: ({"technique_id": "T1033"}
                                      if cmd == "whoami" else None))
    t = Telemetry("sid-1", src_ip="10.0.0.9", public_ip="203.0.113.5",
                  instance="sensor-a", writer=rows.append,
                  export=events.append, log=logged.append, **kw)
    return t, rows, events, logged


class TestTheRow(unittest.TestCase):

    def test_it_carries_what_the_siem_pipeline_reads(self):
        t, rows, _, _ = tel()
        t.record("whoami", "cowrie", "root", fi_score=2, latency_ms=12.345)
        row = rows[0]
        self.assertEqual(row["session_id"], "sid-1")
        self.assertEqual(row["src_ip"], "10.0.0.9")
        self.assertEqual(row["public_ip"], "203.0.113.5")
        self.assertEqual(row["instance"], "sensor-a")
        self.assertEqual(row["cmd"], "whoami")
        self.assertEqual(row["agent"], "cowrie")
        self.assertEqual(row["response"], "root")

    def test_latency_is_rounded_to_two_places(self):
        t, rows, _, _ = tel()
        t.record("ls", "cowrie", "", latency_ms=12.3456)
        self.assertEqual(rows[0]["latency_ms"], 12.35)

    def test_a_mapped_command_carries_its_technique(self):
        t, rows, _, _ = tel()
        t.record("whoami", "cowrie", "root")
        self.assertEqual(rows[0]["technique_id"], "T1033")

    def test_an_unmapped_command_stays_untagged_rather_than_forced(self):
        t, rows, _, _ = tel()
        t.record("qqq", "cowrie", "")
        self.assertNotIn("technique_id", rows[0])

    def test_fi_is_recorded_and_is_not_a_severity(self):
        """FI is an operational fact. SOC severity comes from the severity
        layer, nowhere near here."""
        t, rows, _, _ = tel()
        t.record("cat /etc/shadow", "on_device", "...", fi_score=1)
        self.assertEqual(rows[0]["fi_score"], 1)
        self.assertNotIn("severity", rows[0])


class TestTheEvent(unittest.TestCase):
    """Same facts, no response body -- a forwarded stream does not need every
    byte a model generated."""

    def test_the_event_omits_the_response(self):
        t, _, events, _ = tel()
        t.record("whoami", "cowrie", "root" * 500)
        self.assertNotIn("response", events[0])

    def test_the_event_carries_the_same_identity_and_tag(self):
        t, rows, events, _ = tel()
        t.record("whoami", "cowrie", "root", fi_score=2)
        for key in ("session_id", "src_ip", "cmd", "agent", "fi_score",
                    "instance", "technique_id"):
            with self.subTest(key=key):
                self.assertEqual(events[0][key], rows[0][key])

    def test_the_command_is_tagged_once_and_shared(self):
        """Two calls invited two answers for one command."""
        calls = []
        t, _, _, _ = tel(tag=lambda c: calls.append(c) or {"technique_id": "T1"})
        t.record("whoami", "cowrie", "root")
        self.assertEqual(calls, ["whoami"])

    def test_no_exporter_is_not_an_error(self):
        t = Telemetry("sid", writer=lambda r: None, export=None, tag=None)
        t.record("ls", "cowrie", "")        # must not raise


class TestFailuresNeverReachTheSession(unittest.TestCase):
    """A logging problem costs one row. It must not take the honeypot down."""

    def test_a_transient_db_lock_is_retried_once(self):
        attempts = []

        def flaky(row):
            attempts.append(row)
            if len(attempts) == 1:
                raise RuntimeError("database is locked")

        t = Telemetry("sid", writer=flaky, tag=None, log=lambda m: None)
        t.record("ls", "cowrie", "")
        self.assertEqual(len(attempts), 2)

    def test_a_permanent_db_failure_is_reported_not_raised(self):
        logged = []

        def dead(row):
            raise RuntimeError("disk full")

        t = Telemetry("sid-9", writer=dead, tag=None, log=logged.append)
        t.record("ls", "cowrie", "")        # must not raise
        self.assertTrue(any("LOST command for sid-9" in m for m in logged))

    def test_a_broken_exporter_does_not_stop_the_row_being_written(self):
        rows, logged = [], []

        def boom(event):
            raise RuntimeError("siem down")

        t = Telemetry("sid", writer=rows.append, export=boom, tag=None,
                      log=logged.append)
        t.record("ls", "cowrie", "")
        self.assertEqual(len(rows), 1)
        self.assertTrue(any("export failed" in m for m in logged))


class TestJsonLinesStore(unittest.TestCase):
    """store='json' is what the experiment harness and the tests use, so it
    never writes to the production database."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="hp_tel_")

    def rows(self):
        path = os.path.join(self.dir, "10.0.0.9.jsonl")
        return [json.loads(l) for l in open(path, encoding="utf-8")]

    def test_one_line_appended_per_command(self):
        t = Telemetry("sid", src_ip="10.0.0.9", store="json",
                      store_dir=self.dir, tag=None)
        for cmd in ("a", "b", "c"):
            t.record(cmd, "cowrie", "")
        self.assertEqual([r["cmd"] for r in self.rows()], ["a", "b", "c"])

    def test_the_directory_is_created_if_missing(self):
        nested = os.path.join(self.dir, "deep", "deeper")
        t = Telemetry("sid", src_ip="10.0.0.9", store="json",
                      store_dir=nested, tag=None)
        t.record("ls", "cowrie", "")
        self.assertTrue(os.path.exists(os.path.join(nested, "10.0.0.9.jsonl")))

    def test_non_ascii_survives_the_round_trip(self):
        t = Telemetry("sid", src_ip="10.0.0.9", store="json",
                      store_dir=self.dir, tag=None)
        t.record("echo 日本語", "cowrie", "日本語")
        self.assertEqual(self.rows()[0]["response"], "日本語")

    def test_an_unwritable_directory_is_reported_not_raised(self):
        logged = []
        t = Telemetry("sid", src_ip="10.0.0.9", store="json",
                      store_dir="/proc/nope/nope", tag=None, log=logged.append)
        t.record("ls", "cowrie", "")        # must not raise
        self.assertTrue(any("LOST command" in m for m in logged))


class TestKnownBug(unittest.TestCase):

    def test_the_passwd_branch_logs_a_timestamp_as_latency(self):
        """PINNED BUG, pre-existing, in main.py not here.

        The interactive `passwd` branch calls

            telemetry.record(cmd, "on_device", "", fi_score, t_start)

        and t_start is time.time(), not a duration -- so that one command
        records latency_ms of ~1.7e12 instead of a few hundred. Everything else
        passes a real elapsed time. Nothing here can prevent it; record() is
        given a number and rounds it. Pinned so the fix is deliberate."""
        t, rows, _, _ = tel()
        t.record("passwd", "on_device", "", 0, 1_758_000_000.0)
        self.assertEqual(rows[0]["latency_ms"], 1_758_000_000.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
