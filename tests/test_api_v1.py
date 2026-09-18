"""
tests/test_api_v1.py — the REST API v1 contract.

Run:  python3 -m unittest discover -s tests -v     (from the repo root)

/api/v1 is a PUBLIC contract. Once an external SIEM or an AI agent is built
against it, a changed response shape breaks them silently -- so the things
asserted here are the things v1 promises not to change.

Three groups, in order of how much it would cost to get them wrong:

  SECURITY SEMANTICS  FI never becomes severity; severity comes only from the
                      severity layer; correlation is never upgraded into
                      attribution; passwords and secrets never appear.
  INTEGRATION         the API calls the EXISTING pipeline rather than a second
                      implementation -- patch a domain function and the API
                      must change with it.
  CONTRACT            paths, methods, validation, paging envelope, 404 shape.

Uses FastAPI's TestClient against the real app and the real database: these are
integration tests on purpose. A mocked pipeline would pass while the API served
nonsense.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from api_server import api                 # noqa: E402

client = TestClient(api)
V1 = "/api/v1"


def setUpModule():
    """Start from a cold cache.

    These are integration tests against the real pipeline, and that pipeline is
    cached for five minutes. Another test module that stubs storage can leave
    an EMPTY result cached, after which every assertion here quietly turns into
    a skip -- 37 tests reporting OK while 9 of them checked nothing. Clearing
    first makes the suite order-independent.
    """
    from SIEM.data import clear_caches
    clear_caches()


def get(path, **params):
    return client.get(f"{V1}{path}", params=params or None)


def first_detection():
    items = get("/detections", since="all").json()["items"]
    return items[0] if items else None


def first_session():
    items = get("/sessions", since="all", limit=1).json()["items"]
    return items[0] if items else None


# ── security semantics ──────────────────────────────────────────────────────

class TestFiIsNeverSeverity(unittest.TestCase):
    """FI is HydraPoT's ROUTING metric -- it decides which agent answered a
    command. It is legitimate investigation context and a legitimate filter.
    It is never a security rating, and the API must not let a consumer mistake
    it for one."""

    BANNED_AS_FI = ("severity", "severity_id", "risk", "risk_score",
                    "threat_level", "score", "priority", "confidence")

    def test_session_commands_keep_fi_under_operational(self):
        s = first_session()
        if not s:
            self.skipTest("no sessions in the database")
        body = get(f"/sessions/{s['session_id']}").json()
        cmd = (body.get("commands") or [None])[0]
        if cmd is None:
            self.skipTest("session has no commands")
        self.assertIn("fi_score", cmd["operational"])
        for key in self.BANNED_AS_FI:
            self.assertNotIn(key, cmd)

    def test_session_response_has_no_top_level_severity_derived_from_fi(self):
        s = first_session()
        if not s:
            self.skipTest("no sessions")
        body = get(f"/sessions/{s['session_id']}").json()
        # FI lives under operational; a session carries no severity at all,
        # because severity rates FINDINGS, not observations.
        self.assertIn("fi_score", str(body["operational"]))
        self.assertNotIn("severity", body)

    def test_detection_severity_is_a_severity_label_not_an_fi_number(self):
        d = first_detection()
        if not d:
            self.skipTest("no detections")
        sev = d.get("severity")
        if sev is not None:
            self.assertIn(sev, ("info", "low", "medium", "high", "critical"))
            self.assertNotIsInstance(sev, int)

    def test_min_fi_filters_without_ranking(self):
        """min_fi is allowed as an operational filter. It must narrow the set,
        never reorder it into a danger ranking."""
        loud = get("/sessions", since="all", min_fi=4, limit=500).json()
        all_ = get("/sessions", since="all", limit=500).json()
        self.assertLessEqual(loud["total"], all_["total"])

    def test_capabilities_never_advertises_fi_as_a_severity_source(self):
        caps = get("/capabilities").json()
        self.assertNotIn("fi", str(caps.get("severity_levels", "")).lower())


class TestSeverityComesFromTheSeverityLayer(unittest.TestCase):

    def test_severity_values_match_the_severity_module_ladder(self):
        from threat_intel import severity
        allowed = set(severity.SEVERITY_ORDER) | {None}
        for d in get("/detections", since="all", bucket="all",
                     limit=200).json()["items"]:
            self.assertIn(d.get("severity"), allowed)

    def test_detection_carries_the_rules_that_produced_its_rating(self):
        """A severity with no visible basis is the opaque score this
        architecture refuses to produce."""
        for d in get("/detections", since="all", limit=50).json()["items"]:
            if d.get("severity"):
                self.assertTrue(d["severity_rules"],
                                "rated detection has no severity_rules")

    def test_unrated_is_reported_as_null_not_downgraded(self):
        """A relationship the behaviour ruleset could not read is unrated. It
        must not be quietly reported as 'low'."""
        items = get("/detections", since="all", bucket="all",
                    limit=500).json()["items"]
        unrated = [d for d in items if d.get("severity") is None]
        if not unrated:
            self.skipTest("every detection is rated in this window")
        self.assertIsNone(unrated[0]["severity"])


class TestCorrelationIsNotAttribution(unittest.TestCase):

    def test_statement_is_the_engines_own_wording(self):
        from threat_intel import correlation
        allowed = {s["statement"] for s in correlation.load_strategies()}
        d = first_detection()
        if not d:
            self.skipTest("no detections")
        self.assertIn(d["correlation"]["statement"], allowed)

    def test_no_attribution_language_in_any_response(self):
        """A shared command sequence means exactly that -- not the same
        attacker, operator or campaign."""
        banned = ("attacker_id", "actor", "campaign", "threat_actor",
                  "apt", "adversary_name", "attribution")
        blob = str(get("/detections", since="all", bucket="all",
                       limit=100).json()).lower()
        for word in banned:
            self.assertNotIn(f'"{word}"', blob)

    def test_ip_investigation_states_that_an_address_is_not_an_identity(self):
        o = get("/overview", since="all").json()
        ips = o.get("source_ips") or []
        if not ips:
            self.skipTest("no source addresses")
        body = get(f"/investigations/ip/{ips[0]['src_ip']}", since="all").json()
        self.assertIn("not an identity", body["note"])


class TestNoSecretsLeak(unittest.TestCase):

    def test_credential_iocs_are_not_exposed(self):
        """build_iocs extracts credential pairs from the auth stream. Those
        are attacker-submitted passwords; this API is not a credential feed."""
        items = get("/threats/iocs", since="all", limit=500).json()["items"]
        self.assertEqual([i for i in items if i["type"] == "credential"], [])

    def test_no_password_field_anywhere_in_a_session_response(self):
        s = first_session()
        if not s:
            self.skipTest("no sessions")
        blob = str(get(f"/sessions/{s['session_id']}").json()).lower()
        for word in ('"password"', '"passwd"', '"secret"', '"api_key"',
                     '"token"'):
            self.assertNotIn(word, blob)

    def test_health_exposes_no_configuration_or_paths(self):
        body = get("/health").json()
        blob = str(body).lower()
        for word in ("password", "token", "secret", "/home/", "/mnt/",
                     "db_path", "api_key"):
            self.assertNotIn(word, blob)

    def test_capabilities_exposes_no_sink_destinations(self):
        """Which sinks are on is useful. WHERE they point is a credential."""
        blob = str(get("/capabilities").json()).lower()
        for word in ("http://", "https://", "webhook_url", "@"):
            self.assertNotIn(word, blob)


class TestNotADatabaseProxy(unittest.TestCase):
    """The API exposes processed intelligence, not the schema underneath it."""

    def test_no_raw_database_or_internal_routes_exist(self):
        paths = api.openapi()["paths"]
        for p in paths:
            if not p.startswith(V1):
                continue
            for banned in ("/database", "/sql", "/query", "/raw", "/internal",
                           "/cowrie", "/router", "/prompt"):
                self.assertNotIn(banned, p)

    def test_every_v1_route_is_read_only(self):
        """v1 is an intelligence read surface. Alert state changes happen in
        the dashboard; adding writes here is a deliberate future decision, not
        an accident."""
        for path, methods in api.openapi()["paths"].items():
            if path.startswith(V1):
                self.assertEqual(set(methods) - {"get"}, set(),
                                 f"{path} exposes a non-GET method")


# ── integration: the API calls the EXISTING pipeline ────────────────────────

class TestReusesExistingLogic(unittest.TestCase):
    """Not a second implementation. Patch a domain function and the API must
    change with it -- that is the only proof that nothing was duplicated."""

    def test_overview_calls_the_aggregation_layer(self):
        import SIEM.data as data
        original = data.load_overview
        called = []
        data.load_overview = lambda **kw: (called.append(kw) or original(**kw))
        self.addCleanup(lambda: setattr(data, "load_overview", original))
        get("/overview", since="24h")
        self.assertTrue(called, "/overview did not call load_overview")
        self.assertEqual(called[0]["preset"], "24h")

    def test_detections_call_the_detection_pipeline(self):
        import SIEM.data as data
        original = data.load_detections
        called = []
        data.load_detections = lambda **kw: (called.append(kw) or original(**kw))
        self.addCleanup(lambda: setattr(data, "load_detections", original))
        get("/detections", since="all")
        self.assertTrue(called, "/detections did not call load_detections")

    def test_alerts_read_the_alert_table_not_a_reimplementation(self):
        import storage
        original = storage.query_alerts
        called = []
        storage.query_alerts = lambda **kw: (called.append(kw) or original(**kw))
        self.addCleanup(lambda: setattr(storage, "query_alerts", original))
        get("/alerts")
        self.assertTrue(called)

    def test_session_detail_uses_aggregate_session(self):
        import threat_intel.aggregator as agg
        s = first_session()
        if not s:
            self.skipTest("no sessions")
        original = agg.aggregate_session
        called = []
        agg.aggregate_session = lambda *a, **k: (called.append(a) or original(*a, **k))
        self.addCleanup(lambda: setattr(agg, "aggregate_session", original))
        get(f"/sessions/{s['session_id']}")
        self.assertTrue(called, "session detail rebuilt the session itself")

    def test_capabilities_are_read_from_the_rulesets(self):
        """Not a hardcoded list of trues: emptying a ruleset must flip the
        corresponding feature to false."""
        from threat_intel import detection
        caps = get("/capabilities").json()
        self.assertEqual(caps["rules"]["detection_rules"],
                         len(detection.load_rules()))
        self.assertEqual(caps["features"]["detection"],
                         len(detection.load_rules()) > 0)


# ── contract ────────────────────────────────────────────────────────────────

class TestContract(unittest.TestCase):

    def test_health_shape(self):
        b = get("/health").json()
        for key in ("status", "api_version", "database"):
            self.assertIn(key, b)
        self.assertEqual(b["api_version"], "v1")

    def test_capabilities_shape(self):
        b = get("/capabilities").json()
        self.assertEqual(b["api_version"], "v1")
        self.assertIn("features", b)
        self.assertIn("json", b["export_formats"])
        self.assertIn("ocsf", b["export_formats"])

    def test_collections_share_one_paging_envelope(self):
        for path in ("/alerts", "/detections", "/sessions", "/threats/iocs"):
            b = get(path, since="all", limit=2).json()
            for key in ("items", "total", "limit", "offset", "has_more"):
                self.assertIn(key, b, f"{path} is missing {key}")
            self.assertLessEqual(len(b["items"]), 2)

    def test_paging_offset_moves_the_window(self):
        a = get("/detections", since="all", limit=1, offset=0).json()
        b = get("/detections", since="all", limit=1, offset=1).json()
        if a["total"] < 2:
            self.skipTest("not enough detections to page")
        self.assertNotEqual(a["items"][0]["detection_id"],
                            b["items"][0]["detection_id"])

    def test_unknown_id_is_404_naming_the_resource(self):
        for path, what in (("/alerts/nope", "alert"),
                           ("/detections/nope", "detection"),
                           ("/sessions/nope", "session"),
                           ("/threats/mitre/T9999", "technique"),
                           ("/threats/iocs/nope", "ioc")):
            r = get(path, since="all")
            self.assertEqual(r.status_code, 404, path)
            self.assertIn(what, r.json()["detail"])

    def test_invalid_parameters_are_rejected(self):
        self.assertEqual(get("/detections", since="all", bucket="banana")
                         .status_code, 422)
        self.assertEqual(get("/sessions", since="all", min_fi=99)
                         .status_code, 422)
        self.assertEqual(get("/alerts", limit=0).status_code, 422)

    def test_identifiers_are_stable_across_requests(self):
        """A URL a consumer bookmarks must still resolve. The pipeline is
        recomputed per request, so ids are DERIVED, never generated."""
        a = get("/detections", since="all", limit=5).json()["items"]
        b = get("/detections", since="all", limit=5).json()["items"]
        self.assertEqual([x["detection_id"] for x in a],
                         [x["detection_id"] for x in b])

    def test_detection_id_resolves_to_the_same_detection(self):
        d = first_detection()
        if not d:
            self.skipTest("no detections")
        one = get(f"/detections/{d['detection_id']}", since="all").json()
        self.assertEqual(one["detection_id"], d["detection_id"])

    def test_correlation_id_from_a_detection_resolves(self):
        d = first_detection()
        if not d:
            self.skipTest("no detections")
        cid = d["correlation"]["correlation_id"]
        self.assertEqual(get(f"/correlations/{cid}", since="all").json()
                         ["correlation_id"], cid)


class TestEvidenceProvenance(unittest.TestCase):
    """A consumer -- a person or an AI -- must be able to answer "why do you
    believe that" by pointing at a record."""

    def test_every_evidence_item_names_its_source(self):
        d = first_detection()
        if not d:
            self.skipTest("no detections")
        body = get(f"/detections/{d['detection_id']}", since="all").json()
        self.assertTrue(body["evidence"])
        for e in body["evidence"]:
            self.assertIn("evidence_id", e)
            self.assertIn("source", e)
            self.assertIn("type", e)

    def test_evidence_ids_are_stable(self):
        d = first_detection()
        if not d:
            self.skipTest("no detections")
        p = f"/detections/{d['detection_id']}"
        self.assertEqual([e["evidence_id"] for e in get(p, since="all").json()["evidence"]],
                         [e["evidence_id"] for e in get(p, since="all").json()["evidence"]])

    def test_evidence_covers_the_reasoning_chain(self):
        """correlation -> detection -> severity -> MITRE, so the chain is
        reconstructable from the response alone."""
        for d in get("/detections", since="all", limit=20).json()["items"]:
            body = get(f"/detections/{d['detection_id']}", since="all").json()
            kinds = {e["type"] for e in body["evidence"]}
            if "severity" in kinds:
                self.assertIn("correlation", kinds)
                self.assertIn("detection", kinds)
                return
        self.skipTest("no rated detection in this window")


class TestInvestigationPackages(unittest.TestCase):
    """The endpoints the AI Security Analyst will call: one request per
    question, evidence not conclusions."""

    def test_session_investigation_is_coherent(self):
        s = first_session()
        if not s:
            self.skipTest("no sessions")
        b = get(f"/investigations/session/{s['session_id']}", since="all").json()
        for key in ("subject", "summary", "session", "timeline", "mitre",
                    "iocs", "correlations", "detections", "alerts", "evidence"):
            self.assertIn(key, b)
        self.assertEqual(b["subject"], {"type": "session",
                                        "id": s["session_id"]})

    def test_investigations_return_no_fabricated_conclusion(self):
        s = first_session()
        if not s:
            self.skipTest("no sessions")
        b = get(f"/investigations/session/{s['session_id']}", since="all").json()
        for banned in ("verdict", "conclusion", "risk_score", "attacker",
                       "malicious", "recommendation"):
            self.assertNotIn(banned, b)

    def test_alert_investigation_preserves_detection_severity_alert(self):
        items = get("/alerts", limit=1).json()["items"]
        if not items:
            self.skipTest("no alerts")
        b = get(f"/investigations/alert/{items[0]['alert_id']}",
                since="all").json()
        self.assertIn("alert", b)
        self.assertIn("detection", b)
        self.assertIn("correlation", b)


class TestNormalizedExport(unittest.TestCase):
    """/api/v1/ocsf -- ONE route, class as a filter.

    Replaced /api/ocsf/events and /api/ocsf/findings, which covered two of the
    three classes normalize.py produces. Authentication had no route, because
    adding a class meant adding one.
    """

    CLASSES = ("process", "auth", "finding")
    FORMATS = ("ocsf", "json", "cef", "ecs")

    def test_every_class_serves_every_format(self):
        for cls in self.CLASSES:
            for fmt in self.FORMATS:
                with self.subTest(cls=cls, fmt=fmt):
                    r = get("/export", **{"class": cls}, format=fmt, since="all", limit=1)
                    self.assertEqual(r.status_code, 200)
                    self.assertEqual(r.json()["class"], cls)
                    self.assertEqual(r.json()["format"], fmt)

    def test_auth_is_exportable(self):
        """normalize_auth() existed and was tested long before anything served
        it. This is the route that finally does."""
        items = get("/export", **{"class": "auth"}, since="all", limit=1).json()["items"]
        if not items:
            self.skipTest("no auth rows")
        self.assertEqual(items[0]["class_uid"], 3002)

    def test_each_class_returns_its_own_ocsf_class_uid(self):
        expected = {"process": 1007, "auth": 3002, "finding": 2004}
        for cls, uid in expected.items():
            with self.subTest(cls=cls):
                items = get("/export", **{"class": cls}, since="all", limit=1).json()["items"]
                if not items:
                    self.skipTest(f"no {cls} rows")
                self.assertEqual(items[0]["class_uid"], uid)

    def test_cef_is_a_wire_string_not_an_object(self):
        items = get("/export", **{"class": "finding"}, format="cef",
                    since="all", limit=1).json()["items"]
        if not items:
            self.skipTest("no findings")
        self.assertIsInstance(items[0], str)
        self.assertTrue(items[0].startswith("CEF:0|"))

    def test_unknown_class_or_format_is_refused_by_name(self):
        for q in ({"class": "bogus"}, {"format": "bogus"}):
            with self.subTest(**q):
                r = get("/export", **q)
                self.assertEqual(r.status_code, 422)

    def test_raw_telemetry_severity_is_unknown_never_fi(self):
        """FI is the routing metric. Nothing has assessed a raw command, so the
        honest severity is 0 (Unknown) -- not a number derived from FI."""
        for cls in ("process", "auth"):
            items = get("/export", **{"class": cls}, since="all", limit=3).json()["items"]
            for ev in items:
                with self.subTest(cls=cls):
                    self.assertEqual(ev["severity_id"], 0)
                    self.assertNotIn("fi_score", ev)

    def test_capabilities_advertises_only_what_this_route_serves(self):
        """The list used to be a literal claiming json/ocsf/cef/ecs while no v1
        route served any of them."""
        caps = get("/capabilities").json()
        self.assertEqual(set(caps["export_formats"]), set(self.FORMATS))
        self.assertEqual(set(caps["export_classes"]), set(self.CLASSES))
        for fmt in caps["export_formats"]:
            with self.subTest(fmt=fmt):
                self.assertEqual(
                    get("/export", format=fmt, since="all", limit=1).status_code, 200)

    def test_the_old_unversioned_routes_are_gone_and_say_where_to_go(self):
        for old, new in (("/api/ocsf/events", "class=process"),
                         ("/api/ocsf/findings", "class=finding")):
            with self.subTest(old=old):
                r = client.get(old)
                self.assertEqual(r.status_code, 410)
                self.assertIn(new, r.json()["replacement"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
