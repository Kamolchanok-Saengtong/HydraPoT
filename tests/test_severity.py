"""
tests/test_severity.py — the Severity layer's contract.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

Severity is the only layer allowed to say how BAD something is, so these pin
the promises that keep that judgement auditable:

  * A rating is always the HIGHEST rule that fired — never a sum, average or
    composite, and always accompanied by the rules that produced it.
  * Severity reads BEHAVIOUR only. How many sessions, sources or sensors a
    relationship spans must not move it; folding spread into severity is how a
    risk score gets built by accident.
  * FI is never an input. FI decides which agent answers a command; it says
    nothing about attacker intent.
  * No evidence means UNRATED, not "low". Absence of a rating is not a
    judgement of harmlessness.
  * Detection's output is annotated, never mutated.

Rules come from temporary YAML so these test the ENGINE, not the policy in
session_severity.yml, which is meant to change without breaking tests.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel import severity as S  # noqa: E402


def rel(techs=("T1105",), tactics=("Execution",), members=2, sources=1,
        scope=("sensor-a",), link="same_sequence"):
    """A correlation-shaped relationship carrying sequence evidence."""
    return {
        "link_type": link, "link_value": "k",
        "statement": "these sessions share an identical observed command sequence",
        "members": [f"s{i}" for i in range(members)], "member_count": members,
        "distinct_sources": sources, "src_ips": [f"10.0.0.{i}" for i in range(sources)],
        "first_seen": "2026-01-01 00:00:00", "last_seen": "2026-01-01 00:01:00",
        "scope": list(scope),
        "evidence": {"sequence_length": 4, "distinct_commands": 4,
                     "technique_ids": list(techs), "tactics": list(tactics),
                     "sample": ["cmd"]},
    }


def verdict(relationship, bucket="detections"):
    return {"bucket": bucket, "_order": 0,
            "rules": [{"id": "r", "title": "T", "reason": "because"}],
            "reason": "because", "relationship": relationship}


LADDER = """
rules:
  - id: crit
    title: Critical thing
    severity: critical
    description: A critical behaviour.
    when:
      any_techniques: [T1531]
  - id: hi
    title: High thing
    severity: high
    description: A high behaviour.
    when:
      any_tactics: [Persistence]
  - id: med
    title: Medium thing
    severity: medium
    description: A medium behaviour.
    when:
      any_techniques: [T1105]
"""


class RuleFileMixin:
    def rules_file(self, body: str) -> str:
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         encoding="utf-8")
        fh.write(body)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        S.load_rules(fh.name, force=True)
        return fh.name

    def tearDown(self):
        S.load_rules(S.RULES_PATH, force=True)


# ── the ladder ──────────────────────────────────────────────────────────────

class TestHighestRuleWins(RuleFileMixin, unittest.TestCase):

    def test_rating_is_the_highest_rule_not_a_sum(self):
        """Three mediums must not add up to a critical — severity is a ladder,
        not an accumulator."""
        path = self.rules_file(LADDER)
        out = S.evaluate(technique_ids=["T1105", "T1531"],
                         tactics=["Persistence"], path=path)
        self.assertEqual(out["severity"], "critical")
        self.assertEqual(len(out["matched"]), 3)

    def test_matched_rules_are_returned_highest_first(self):
        path = self.rules_file(LADDER)
        out = S.evaluate(technique_ids=["T1105", "T1531"],
                         tactics=["Persistence"], path=path)
        self.assertEqual([r["severity"] for r in out["matched"]],
                         ["critical", "high", "medium"])

    def test_nothing_firing_is_unrated_not_info(self):
        """A command chain the ruleset cannot read is UNRATED. Defaulting it to
        the bottom of the ladder would assert it is mild, which nobody
        measured."""
        path = self.rules_file(LADDER)
        out = S.evaluate(technique_ids=["T9999"], tactics=["Nonsense"], path=path)
        self.assertIsNone(out["severity"])
        self.assertEqual(out["matched"], [])

    def test_every_rating_carries_its_justification(self):
        path = self.rules_file(LADDER)
        out = S.evaluate(technique_ids=["T1531"], path=path)
        self.assertTrue(out["matched"])
        for r in out["matched"]:
            self.assertTrue(r["title"])
            self.assertTrue(r["description"])


# ── conditions ──────────────────────────────────────────────────────────────

class TestConditions(RuleFileMixin, unittest.TestCase):

    def test_all_techniques_requires_every_one(self):
        path = self.rules_file("""
rules:
  - id: loader
    severity: critical
    description: Retrieved AND executed.
    when:
      all_techniques: [T1105, T1059.004]
""")
        self.assertIsNone(S.evaluate(technique_ids=["T1105"], path=path)["severity"])
        self.assertEqual(S.evaluate(technique_ids=["T1105", "T1059.004"],
                                    path=path)["severity"], "critical")

    def test_any_techniques_requires_only_one(self):
        path = self.rules_file(LADDER)
        self.assertEqual(S.evaluate(technique_ids=["T1105"], path=path)["severity"],
                         "medium")

    def test_min_distinct_tactics(self):
        path = self.rules_file("""
rules:
  - id: multistage
    severity: high
    description: Four or more tactics.
    when:
      min_distinct_tactics: 4
""")
        self.assertIsNone(S.evaluate(tactics=["a", "b", "c"], path=path)["severity"])
        self.assertEqual(S.evaluate(tactics=["a", "b", "c", "d"],
                                    path=path)["severity"], "high")

    def test_conditions_within_a_rule_are_anded(self):
        path = self.rules_file("""
rules:
  - id: both
    severity: high
    description: Needs the technique AND the tactic.
    when:
      any_techniques: [T1105]
      any_tactics: [Impact]
""")
        self.assertIsNone(S.evaluate(technique_ids=["T1105"], path=path)["severity"])
        self.assertIsNone(S.evaluate(tactics=["Impact"], path=path)["severity"])
        self.assertEqual(S.evaluate(technique_ids=["T1105"], tactics=["Impact"],
                                    path=path)["severity"], "high")

    def test_pacing_rule_is_skipped_when_rate_is_unknown(self):
        """None means the session was too short to have a meaningful rate.
        Pacing cannot be judged from an instant, so the rule is skipped rather
        than treated as zero."""
        path = self.rules_file("""
rules:
  - id: automated
    severity: info
    description: Faster than a human types.
    when:
      min_commands_per_minute: 60
""")
        self.assertIsNone(S.evaluate(commands_per_minute=None, path=path)["severity"])
        self.assertIsNone(S.evaluate(commands_per_minute=10, path=path)["severity"])
        self.assertEqual(S.evaluate(commands_per_minute=600,
                                    path=path)["severity"], "info")


# ── malformed rules ─────────────────────────────────────────────────────────

class TestMalformedRulesAreSkippedLoudly(RuleFileMixin, unittest.TestCase):

    def test_invalid_severity_level_is_rejected(self):
        path = self.rules_file("""
rules:
  - id: bogus
    severity: catastrophic
    description: Not a level on the ladder.
    when:
      any_tactics: [Impact]
""")
        self.assertEqual(S.load_rules(path, force=True), [])
        self.assertIn("bogus", dict(S.load_errors(path)))

    def test_unknown_condition_is_rejected(self):
        """A typo'd condition matches nothing, which is indistinguishable from
        'this behaviour is not severe' unless the load says so."""
        path = self.rules_file("""
rules:
  - id: typo
    severity: high
    description: Misspelled condition.
    when:
      any_tactic: [Impact]
""")
        self.assertEqual(S.load_rules(path, force=True), [])
        self.assertIn("typo", dict(S.load_errors(path)))

    def test_rule_with_no_conditions_is_rejected(self):
        """A rule with no `when` would fire on everything."""
        path = self.rules_file("""
rules:
  - id: always
    severity: critical
    description: No conditions at all.
""")
        self.assertEqual(S.load_rules(path, force=True), [])

    def test_unreadable_file_yields_no_rules_and_an_error(self):
        missing = os.path.join(tempfile.gettempdir(), "no_such_severity.yml")
        self.assertEqual(S.load_rules(missing, force=True), [])
        self.assertTrue(S.load_errors(missing))

    def test_cache_is_keyed_by_path(self):
        """Regression: one global slot made `path` silently ignored once any
        ruleset had loaded."""
        a = self.rules_file(LADDER)
        b = self.rules_file("""
rules:
  - id: solo
    severity: low
    description: Only rule.
    when:
      any_tactics: [Discovery]
""")
        self.assertEqual(len(S.load_rules(a)), 3)
        self.assertEqual([r["id"] for r in S.load_rules(b)], ["solo"])
        self.assertEqual(len(S.load_rules(a)), 3)

    def test_shipped_ruleset_loads_cleanly(self):
        S.load_rules(S.RULES_PATH, force=True)
        self.assertEqual(S.load_errors(S.RULES_PATH), [])
        self.assertTrue(S.load_rules(S.RULES_PATH))


# ── rating a relationship ───────────────────────────────────────────────────

class TestRateRelationship(RuleFileMixin, unittest.TestCase):

    def test_reads_the_shared_sequence_evidence(self):
        path = self.rules_file(LADDER)
        out = S.rate_relationship(rel(techs=["T1531"]), path=path)
        self.assertEqual(out["severity"], "critical")

    def test_no_evidence_is_unrated(self):
        """Indicator and source-address links share a value, not a command
        sequence, so a behaviour ruleset has nothing to read."""
        path = self.rules_file(LADDER)
        for r in ({"evidence": None}, {"evidence": {}}, {}, None):
            out = S.rate_relationship(r, path=path)
            self.assertIsNone(out["severity"])
            self.assertEqual(out["matched"], [])

    def test_spread_does_not_change_severity(self):
        """THE invariant that keeps this from becoming a risk score: the same
        behaviour across 2 sessions and across 500 sessions from 90 sources on
        4 sensors must rate identically. Spread is a detection concern."""
        path = self.rules_file(LADDER)
        small = S.rate_relationship(rel(techs=["T1105"], members=2, sources=1,
                                        scope=("s1",)), path=path)
        huge = S.rate_relationship(rel(techs=["T1105"], members=500, sources=90,
                                       scope=("s1", "s2", "s3", "s4")), path=path)
        self.assertEqual(small["severity"], huge["severity"])
        self.assertEqual([r["id"] for r in small["matched"]],
                         [r["id"] for r in huge["matched"]])

    def test_link_type_does_not_change_severity(self):
        path = self.rules_file(LADDER)
        a = S.rate_relationship(rel(techs=["T1105"], link="same_sequence"), path=path)
        b = S.rate_relationship(rel(techs=["T1105"], link="shared_indicator"), path=path)
        self.assertEqual(a["severity"], b["severity"])


# ── annotating detection output ─────────────────────────────────────────────

class TestRateDetections(RuleFileMixin, unittest.TestCase):

    def test_all_three_buckets_are_rated(self):
        """A suppressed-but-critical finding is exactly what a reviewer needs
        to be able to find, so suppression must not skip rating."""
        path = self.rules_file(LADDER)
        out = S.rate_detections({
            "detections": [verdict(rel(techs=["T1531"]))],
            "suppressed": [verdict(rel(techs=["T1531"]), "suppressed")],
            "unmatched": [verdict(rel(techs=["T1105"]), "unmatched")],
            "evaluated": 3}, path=path)
        self.assertEqual(out["detections"][0]["severity"], "critical")
        self.assertEqual(out["suppressed"][0]["severity"], "critical")
        self.assertEqual(out["unmatched"][0]["severity"], "medium")

    def test_input_is_not_mutated(self):
        path = self.rules_file(LADDER)
        original = {"detections": [verdict(rel())], "suppressed": [],
                    "unmatched": [], "evaluated": 1}
        S.rate_detections(original, path=path)
        self.assertNotIn("severity", original["detections"][0])

    def test_relationship_passes_through_untouched(self):
        """Correlation's output must still reach the UI byte-for-byte."""
        path = self.rules_file(LADDER)
        r = rel()
        snapshot = {k: v for k, v in r.items() if k != "evidence"}
        out = S.rate_detections({"detections": [verdict(r)], "evaluated": 1},
                                path=path)
        got = out["detections"][0]["relationship"]
        self.assertEqual({k: v for k, v in got.items() if k != "evidence"},
                         snapshot)

    def test_counts_are_preserved(self):
        path = self.rules_file(LADDER)
        out = S.rate_detections({"detections": [], "suppressed": [],
                                 "unmatched": [], "evaluated": 7}, path=path)
        self.assertEqual(out["evaluated"], 7)

    def test_empty_and_none_input(self):
        self.assertEqual(S.rate_detections({})["detections"], [])
        self.assertEqual(S.rate_detections(None)["detections"], [])


# ── layer separation ────────────────────────────────────────────────────────

class TestLayerSeparation(unittest.TestCase):

    def test_fi_is_never_an_input(self):
        """FI decides which agent answers a command. It is an operational
        routing metric and says nothing about attacker intent."""
        src = open(S.__file__, encoding="utf-8").read()
        code = "\n".join(ln for ln in src.splitlines()
                         if not ln.strip().startswith("#"))
        for banned in ("fi_score", "fi_manager", "FI_LABEL"):
            self.assertNotIn(banned, code)

    def test_shipped_ruleset_never_conditions_on_spread(self):
        """No rule may read member_count, distinct_sources or scope — that is
        the seam between severity and detection."""
        allowed = {"any_techniques", "all_techniques", "any_tactics",
                   "min_distinct_tactics", "min_commands_per_minute"}
        for r in S.load_rules(S.RULES_PATH, force=True):
            self.assertTrue(set(r["when"]) <= allowed,
                            f"{r['id']} reads something outside behaviour")

    def test_severity_module_does_not_reach_for_data(self):
        src = open(S.__file__, encoding="utf-8").read()
        for banned in ("import storage", "import sqlite3", "query_range",
                       "tag_all", "tag("):
            self.assertNotIn(banned, src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
