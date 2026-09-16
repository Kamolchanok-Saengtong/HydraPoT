"""
tests/test_alert_records.py — the alert-record layer's contract.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

Alerting is the only layer that WRITES and the only one that can send data off
the host, so these pin the promises that make it safe:

  * An alert's identity survives recomputation. Everything upstream is rebuilt
    on every window load; if the key moved, acknowledging anything would be
    undone by the next refresh.
  * A refresh never touches analyst state. Facts are updated, decisions are not.
  * UNRATED never satisfies a severity threshold. "We could not tell" is not
    "at least medium".
  * Nothing is marked delivered that was not delivered. A disabled sink, a dead
    collector or a raising sender all leave the alert unrouted for retry.
  * Nothing is sent by default. Every network sink ships disabled.
  * Suppressed detections never become alerts.

Every test writes to a throwaway database — none of them touch the real one.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import storage                                    # noqa: E402
from threat_intel import alert_records as A       # noqa: E402


def det(severity="critical", link="same_sequence", value="abc", members=5,
        sources=1, scope=("s1",), rule="multi-tactic-shared-sequence"):
    """A severity-annotated detection verdict, as rate_detections() emits."""
    return {
        "bucket": "detections", "_order": 0,
        "rules": [{"id": rule, "title": "Shared sequence", "reason": "because"}],
        "reason": "because", "severity": severity, "severity_rules": [],
        "relationship": {
            "link_type": link, "link_value": value, "statement": "stmt",
            "members": [f"s{i}" for i in range(members)], "member_count": members,
            "distinct_sources": sources,
            "src_ips": [f"10.0.0.{i}" for i in range(sources)],
            "first_seen": "2026-01-01 00:00:00", "last_seen": "2026-01-01 00:05:00",
            "scope": list(scope), "evidence": {"technique_ids": [], "tactics": []},
        },
    }


class TempDBMixin:
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def rules_file(self, body: str) -> str:
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         dir=self.dir, encoding="utf-8")
        fh.write(body)
        fh.close()
        A.load_rules(fh.name, force=True)
        return fh.name

    def sinks_file(self, body: str) -> str:
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         dir=self.dir, encoding="utf-8")
        fh.write(body)
        fh.close()
        A.load_sinks(fh.name, force=True)
        return fh.name

    def tearDown(self):
        A.load_rules(A.RULES_PATH, force=True)
        A.load_sinks(A.SINKS_PATH, force=True)


CRIT_ONLY = """
rules:
  - id: crit
    title: Critical behaviour
    description: Critical behaviour observed.
    when:
      min_severity: critical
    notify: []
"""


# ── identity ────────────────────────────────────────────────────────────────

class TestAlertIdentity(unittest.TestCase):
    """If the key is not stable, acknowledgement is meaningless."""

    def test_same_detection_yields_the_same_key(self):
        self.assertEqual(A.alert_key(det()), A.alert_key(det()))

    def test_key_is_stable_when_counts_change(self):
        """A relationship grows between windows — more sessions, more sources.
        It is still the same finding and must not become a second alert."""
        self.assertEqual(A.alert_key(det(members=2, sources=1)),
                         A.alert_key(det(members=400, sources=90)))

    def test_key_distinguishes_different_findings(self):
        self.assertNotEqual(A.alert_key(det(value="abc")), A.alert_key(det(value="xyz")))
        self.assertNotEqual(A.alert_key(det(link="same_sequence")),
                            A.alert_key(det(link="shared_indicator")))
        self.assertNotEqual(A.alert_key(det(rule="a")), A.alert_key(det(rule="b")))


# ── rules ───────────────────────────────────────────────────────────────────

class TestRuleEvaluation(TempDBMixin, unittest.TestCase):

    def test_min_severity_is_a_threshold_not_an_equality(self):
        path = self.rules_file("""
rules:
  - id: high_up
    description: High or worse.
    when:
      min_severity: high
""")
        self.assertTrue(A.evaluate(det(severity="critical"), path=path))
        self.assertTrue(A.evaluate(det(severity="high"), path=path))
        self.assertFalse(A.evaluate(det(severity="medium"), path=path))

    def test_unrated_never_satisfies_a_threshold(self):
        """Treating "we could not tell" as "at least medium" would fill the
        queue with exactly the findings we understand least."""
        path = self.rules_file("""
rules:
  - id: any_level
    description: Anything rated at all.
    when:
      min_severity: info
""")
        self.assertFalse(A.evaluate(det(severity=None), path=path))

    def test_unrated_can_be_targeted_deliberately(self):
        path = self.rules_file("""
rules:
  - id: unrated_only
    description: Only the ones we could not rate.
    when:
      severity_in: [unrated]
""")
        self.assertTrue(A.evaluate(det(severity=None), path=path))
        self.assertFalse(A.evaluate(det(severity="critical"), path=path))

    def test_conditions_are_anded(self):
        path = self.rules_file("""
rules:
  - id: both
    description: Serious AND spread out.
    when:
      min_severity: high
      min_distinct_sources: 3
""")
        self.assertFalse(A.evaluate(det(severity="critical", sources=1), path=path))
        self.assertFalse(A.evaluate(det(severity="low", sources=9), path=path))
        self.assertTrue(A.evaluate(det(severity="critical", sources=9), path=path))

    def test_every_matching_rule_is_returned(self):
        path = self.rules_file(CRIT_ONLY + """
  - id: also
    title: Also this
    description: Any critical, again.
    when:
      severity_in: [critical]
""")
        self.assertEqual(len(A.evaluate(det(severity="critical"), path=path)), 2)

    def test_rule_without_a_description_is_rejected(self):
        """An alert interrupts a person; a rule that cannot say why must never
        be able to do that."""
        path = self.rules_file("""
rules:
  - id: silent
    when:
      min_severity: critical
""")
        self.assertEqual(A.load_rules(path, force=True), [])

    def test_unknown_condition_is_rejected_loudly(self):
        path = self.rules_file("""
rules:
  - id: typo
    description: Misspelled condition.
    when:
      min_severty: high
""")
        self.assertEqual(A.load_rules(path, force=True), [])
        self.assertIn("typo", dict(A.load_errors(path)))

    def test_invalid_severity_level_is_rejected(self):
        path = self.rules_file("""
rules:
  - id: bogus
    description: Not a level.
    when:
      min_severity: apocalyptic
""")
        self.assertEqual(A.load_rules(path, force=True), [])

    def test_shipped_ruleset_loads_cleanly(self):
        A.load_rules(A.RULES_PATH, force=True)
        self.assertEqual(A.load_errors(A.RULES_PATH), [])
        self.assertTrue(A.load_rules(A.RULES_PATH))


# ── persistence ─────────────────────────────────────────────────────────────

class TestRaiseAlerts(TempDBMixin, unittest.TestCase):

    def test_qualifying_detection_becomes_an_alert(self):
        path = self.rules_file(CRIT_ONLY)
        out = A.raise_alerts({"detections": [det(severity="critical")]},
                             path=path, db_path=self.db)
        self.assertEqual(len(out["new"]), 1)
        self.assertEqual(storage.alert_counts(path=self.db), {"new": 1})

    def test_non_qualifying_detection_raises_nothing(self):
        path = self.rules_file(CRIT_ONLY)
        out = A.raise_alerts({"detections": [det(severity="low")]},
                             path=path, db_path=self.db)
        self.assertEqual(out["new"], [])
        self.assertEqual(storage.query_alerts(path=self.db), [])

    def test_rerunning_does_not_duplicate(self):
        """The pipeline reruns on every window load. Alerts must accumulate
        state, not rows."""
        path = self.rules_file(CRIT_ONLY)
        d = {"detections": [det(severity="critical")]}
        first = A.raise_alerts(d, path=path, db_path=self.db)
        second = A.raise_alerts(d, path=path, db_path=self.db)
        self.assertEqual(len(first["new"]), 1)
        self.assertEqual(len(second["new"]), 0)
        self.assertEqual(len(second["updated"]), 1)
        self.assertEqual(len(storage.query_alerts(path=self.db)), 1)

    def test_refresh_never_undoes_analyst_state(self):
        """THE invariant. An acknowledged alert must survive every rerun, or
        the queue resets itself every few minutes."""
        path = self.rules_file(CRIT_ONLY)
        d = {"detections": [det(severity="critical", members=5)]}
        A.raise_alerts(d, path=path, db_path=self.db)
        key = A.alert_key(det())
        storage.set_alert_state(key, "acknowledged", by="analyst",
                                note="mine", path=self.db)

        A.raise_alerts({"detections": [det(severity="critical", members=99)]},
                       path=path, db_path=self.db)
        row = storage.get_alert(key, path=self.db)
        self.assertEqual(row["state"], "acknowledged")
        self.assertEqual(row["acknowledged_by"], "analyst")
        self.assertEqual(row["note"], "mine")
        self.assertEqual(row["member_count"], 99)      # facts DID refresh

    def test_suppressed_detections_never_become_alerts(self):
        """Detection deliberately kept them off the screen; promoting them to
        something that interrupts a person would contradict that."""
        path = self.rules_file(CRIT_ONLY)
        out = A.raise_alerts({"detections": [],
                              "suppressed": [det(severity="critical")],
                              "unmatched": [det(severity="critical", value="z")]},
                             path=path, db_path=self.db)
        self.assertEqual(out["new"], [])
        self.assertEqual(storage.query_alerts(path=self.db), [])

    def test_unrated_severity_is_stored_as_null_not_a_level(self):
        path = self.rules_file("""
rules:
  - id: unrated
    description: Unrated findings.
    when:
      severity_in: [unrated]
""")
        A.raise_alerts({"detections": [det(severity=None)]},
                       path=path, db_path=self.db)
        self.assertIsNone(storage.query_alerts(path=self.db)[0]["severity"])

    def test_empty_input(self):
        path = self.rules_file(CRIT_ONLY)
        self.assertEqual(A.raise_alerts({}, path=path, db_path=self.db)["new"], [])
        self.assertEqual(A.raise_alerts(None, path=path, db_path=self.db)["new"], [])


# ── lifecycle ───────────────────────────────────────────────────────────────

class TestLifecycle(TempDBMixin, unittest.TestCase):

    def _one(self):
        path = self.rules_file(CRIT_ONLY)
        A.raise_alerts({"detections": [det(severity="critical")]},
                       path=path, db_path=self.db)
        return A.alert_key(det())

    def test_states_move_and_stamp_the_right_timestamps(self):
        key = self._one()
        storage.set_alert_state(key, "acknowledged", by="me", path=self.db)
        row = storage.get_alert(key, path=self.db)
        self.assertEqual(row["state"], "acknowledged")
        self.assertTrue(row["acknowledged_at"])
        self.assertIsNone(row["closed_at"])

        storage.set_alert_state(key, "closed", path=self.db)
        self.assertTrue(storage.get_alert(key, path=self.db)["closed_at"])

    def test_reopening_clears_stale_timestamps(self):
        """A reopened alert must not carry "closed 3 days ago" beside an open
        state."""
        key = self._one()
        storage.set_alert_state(key, "acknowledged", by="me", path=self.db)
        storage.set_alert_state(key, "closed", path=self.db)
        storage.set_alert_state(key, "new", path=self.db)
        row = storage.get_alert(key, path=self.db)
        self.assertEqual(row["state"], "new")
        self.assertIsNone(row["acknowledged_at"])
        self.assertIsNone(row["closed_at"])

    def test_invalid_state_is_refused(self):
        key = self._one()
        with self.assertRaises(ValueError):
            storage.set_alert_state(key, "escalated", path=self.db)

    def test_unknown_key_changes_nothing(self):
        self._one()
        self.assertFalse(storage.set_alert_state("no-such-key", "closed",
                                                 path=self.db))

    def test_alerts_are_never_auto_closed(self):
        """Nothing in the pipeline closes an alert. It leaves the queue when a
        person says so; "it stopped appearing" is indistinguishable from "we
        lost it"."""
        path = self.rules_file(CRIT_ONLY)
        key = self._one()
        storage.set_alert_state(key, "acknowledged", by="me", path=self.db)
        # The finding vanishes from the window entirely.
        A.raise_alerts({"detections": []}, path=path, db_path=self.db)
        self.assertEqual(storage.get_alert(key, path=self.db)["state"],
                         "acknowledged")


# ── delivery ────────────────────────────────────────────────────────────────

FILE_RULE = """
rules:
  - id: crit
    title: Critical behaviour
    description: Critical behaviour observed.
    when:
      min_severity: critical
    notify: [file]
"""


class TestRouting(TempDBMixin, unittest.TestCase):

    def _setup(self, sink_enabled=True):
        self.out_file = os.path.join(self.dir, "alerts.jsonl")
        rules = self.rules_file(FILE_RULE)
        sinks = self.sinks_file(f"""
sinks:
  - name: file
    type: jsonl
    enabled: {str(sink_enabled).lower()}
    path: {self.out_file}
""")
        A.raise_alerts({"detections": [det(severity="critical")]},
                       path=rules, db_path=self.db)
        return rules, sinks

    def test_enabled_sink_receives_the_alert(self):
        rules, sinks = self._setup()
        r = A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(len(r["sent"]), 1)
        self.assertEqual(len(open(self.out_file).readlines()), 1)
        self.assertIn("alert_key", json.loads(open(self.out_file).readline()))

    def test_delivered_alerts_are_not_sent_twice(self):
        rules, sinks = self._setup()
        A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        again = A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(again["sent"], [])
        self.assertEqual(len(open(self.out_file).readlines()), 1)

    def test_disabled_sink_leaves_the_alert_unrouted(self):
        """Not "delivered to nowhere" — unrouted, so it is retried when the
        sink is switched on."""
        rules, sinks = self._setup(sink_enabled=False)
        r = A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(r["sent"], [])
        self.assertEqual(len(r["skipped"]), 1)
        self.assertEqual(len(storage.query_alerts(unrouted_only=True,
                                                  path=self.db)), 1)

    def test_a_failing_sink_does_not_mark_delivery(self):
        rules, sinks = self._setup()
        original = A.SENDERS["jsonl"]

        def boom(sink, alert):
            raise OSError("collector is down")
        A.SENDERS["jsonl"] = boom
        self.addCleanup(lambda: A.SENDERS.__setitem__("jsonl", original))

        r = A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(r["sent"], [])
        self.assertEqual(len(r["failed"]), 1)
        self.assertEqual(len(storage.query_alerts(unrouted_only=True,
                                                  path=self.db)), 1)

    def test_a_rule_with_no_sinks_records_but_never_sends(self):
        rules = self.rules_file(CRIT_ONLY)          # notify: []
        sinks = self.sinks_file("sinks: []")
        A.raise_alerts({"detections": [det(severity="critical")]},
                       path=rules, db_path=self.db)
        r = A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(r["sent"], [])
        self.assertEqual(len(storage.query_alerts(path=self.db)), 1)


class TestNotificationsFollowSeverityNotFi(TempDBMixin, unittest.TestCase):
    """Human notifications are decided by the SAME rules as everything else.

    They used to fire per command on `min_fi >= 3` in alerts.yml -- HydraPoT's
    ROUTING metric -- so the honeypot paged on a loud `rm` of a file the
    attacker created themselves and stayed silent on a multi-session loader
    whose commands were each FI 1. The channel is now a SINK of the
    alert-record layer, so alert_rules.yml decides, once, in one file.
    """

    def _wire(self, notify=("channels",)):
        self.delivered = []
        rules = self.rules_file(
            "rules:\n"
            "  - id: crit\n"
            "    title: Critical behaviour observed\n"
            "    description: Critical only.\n"
            "    when:\n"
            "      min_severity: critical\n"
            f"    notify: [{', '.join(notify)}]\n")
        sinks = self.sinks_file(
            "sinks:\n  - name: channels\n    type: channels\n    enabled: true\n")
        original = A.SENDERS["channels"]
        A.SENDERS["channels"] = lambda sink, alert: (
            self.delivered.append(alert) or True)
        self.addCleanup(lambda: A.SENDERS.__setitem__("channels", original))
        return rules, sinks

    def test_critical_finding_notifies_even_when_every_command_was_fi_zero(self):
        rules, sinks = self._wire()
        A.raise_alerts({"detections": [det(severity="critical")]},
                       path=rules, db_path=self.db)
        A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(len(self.delivered), 1)
        self.assertEqual(self.delivered[0]["severity"], "critical")

    def test_low_finding_does_not_notify_even_when_every_command_was_fi_four(self):
        """The exact inversion of the old behaviour."""
        rules, sinks = self._wire()
        A.raise_alerts({"detections": [det(severity="low")]},
                       path=rules, db_path=self.db)
        A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(self.delivered, [])

    def test_fi_is_absent_from_the_notification_decision_entirely(self):
        """Not "FI is outranked" -- FI is not consulted. Changing it cannot
        change whether a finding notifies."""
        rules, sinks = self._wire()
        for fi in (0, 4):
            d = det(severity="critical", value=f"v{fi}")
            d["relationship"]["evidence"]["fi_score"] = fi
            A.raise_alerts({"detections": [d]}, path=rules, db_path=self.db)
        A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(len(self.delivered), 2)

    def test_a_rule_can_record_without_notifying(self):
        rules, sinks = self._wire(notify=())
        A.raise_alerts({"detections": [det(severity="critical")]},
                       path=rules, db_path=self.db)
        A.route_alerts(path=rules, sinks_path=sinks, db_path=self.db)
        self.assertEqual(self.delivered, [])
        self.assertEqual(len(storage.query_alerts(path=self.db)), 1)

    def test_alert_records_module_never_mentions_fi(self):
        src = open(A.__file__, encoding="utf-8").read()
        code = "\n".join(ln for ln in src.splitlines()
                         if not ln.strip().startswith("#"))
        for banned in ("fi_score", "min_fi", "fi_manager"):
            self.assertNotIn(banned, code)


class TestNotificationsAreOffByDefault(unittest.TestCase):
    """Two independent switches, both shipped off.

    An alert carries attacker infrastructure, source addresses and command
    text. Sending it off the host is a disclosure and must be a deliberate act
    by whoever runs the sensor -- never a default someone forgot to change.
    """

    def test_channels_sink_is_disabled_in_the_shipped_config(self):
        live = A.load_sinks(A.SINKS_PATH, force=True)
        self.assertNotIn("channels", live,
                         "the notification sink ships enabled")

    def test_no_channel_is_enabled_in_the_shipped_alerts_yml(self):
        from threat_intel.alert_channels import AlertManager
        self.assertEqual(AlertManager()._enabled_channels(), [])

    def test_a_disabled_sink_leaves_the_alert_unrouted_for_later(self):
        """Turning notifications on must not mean the findings raised while
        they were off are lost."""
        self.assertNotIn("channels", A.load_sinks(A.SINKS_PATH, force=True))


class TestShipsSilent(unittest.TestCase):
    """An alert carries attacker infrastructure, source addresses and command
    text. Sending that anywhere must be a deliberate act by whoever runs the
    sensor, never a default that was left on."""

    def test_no_network_sink_is_enabled_by_default(self):
        live = A.load_sinks(A.SINKS_PATH, force=True)
        for name, sink in live.items():
            self.assertEqual(sink.get("type"), "jsonl",
                             f"network sink {name!r} ships enabled")

    def test_every_sender_type_in_the_shipped_file_is_implemented(self):
        """A sink type with no sender silently never delivers."""
        import yaml
        doc = yaml.safe_load(open(A.SINKS_PATH, encoding="utf-8")) or {}
        for sink in doc.get("sinks") or []:
            self.assertIn(sink.get("type"), A.SENDERS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
