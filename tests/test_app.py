import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

import app


class SignalForgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db_path = app.DB_PATH
        app.DB_PATH = Path(self.temp.name) / "test.sqlite"
        app.init_db()
        self.server = app.BoundedThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        app.DB_PATH = self.old_db_path
        self.temp.cleanup()

    def demo_events(self):
        source = Path(__file__).parents[1] / "data" / "demo_events.jsonl"
        return [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]

    def test_demo_detects_four_rules_and_duplicate_import_is_idempotent(self):
        first = app.ingest(self.demo_events())
        second = app.ingest(list(reversed(self.demo_events())))
        self.assertEqual((first["stored"], first["alerts_total"]), (10, 4))
        self.assertEqual((second["stored"], second["duplicates"], second["alerts_total"]), (0, 10, 4))
        with app.database() as conn:
            event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(event_count, 10)

    def test_brute_force_rule_requires_five_failures_in_window(self):
        events = [{
            "timestamp": f"2026-10-05T09:0{minute}:00Z", "event_type": "auth_failure",
            "host": "lab", "user": "analyst", "src_ip": "192.0.2.10", "outcome": "failure",
        } for minute in range(5)]
        app.ingest(events[:4])
        with app.database() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='SF-AUTH-001'").fetchone()[0], 0)
        app.ingest(events[4:])
        with app.database() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='SF-AUTH-001'").fetchone()[0], 1)

    def test_brute_force_alert_updates_evidence_as_window_grows(self):
        events = [{
            "timestamp": f"2026-10-05T09:{minute:02d}:00Z", "event_type": "auth_failure",
            "host": "lab", "user": "analyst", "src_ip": "192.0.2.11", "outcome": "failure",
        } for minute in range(8, 14)]
        with patch.object(app, "utc_now", return_value="2026-10-05T00:00:01Z"):
            app.ingest(events[:5])
        with app.database() as conn:
            alert = conn.execute("SELECT * FROM alerts WHERE rule_id='SF-AUTH-001'").fetchone()
            self.assertEqual(alert["event_count"], 5)
            first_updated_at = alert["updated_at"]
            alert_id = alert["id"]
        request = Request(
            self.base_url + f"/api/alerts/{alert_id}", data=b'{"status":"investigating"}',
            headers={"Content-Type": "application/json"}, method="PATCH",
        )
        with urlopen(request):
            pass
        with patch.object(app, "utc_now", return_value="2026-10-05T00:00:02Z"):
            app.ingest(events[5:])
        with app.database() as conn:
            alert = conn.execute("SELECT * FROM alerts WHERE rule_id='SF-AUTH-001'").fetchone()
            self.assertEqual(alert["event_count"], 6)
            self.assertEqual(alert["last_seen"], "2026-10-05T09:13:00Z")
            self.assertEqual(len(json.loads(alert["evidence_json"])), 6)
            self.assertEqual(alert["status"], "investigating")
            self.assertNotEqual(alert["updated_at"], first_updated_at)
            updated_at = alert["updated_at"]
        with patch.object(app, "utc_now", return_value="2026-10-05T00:00:03Z"):
            app.ingest(events[:5])
        with app.database() as conn:
            alert = conn.execute("SELECT * FROM alerts WHERE rule_id='SF-AUTH-001'").fetchone()
            self.assertEqual(alert["updated_at"], updated_at)

    def test_http_rejects_nonstandard_json_constants(self):
        request = Request(
            self.base_url + "/api/ingest", data=b'{"events":[{"event_type":"test","host":"lab","x":NaN}]}',
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 400)
        self.assertIn("invalid JSON constant", caught.exception.read().decode())

    def test_http_rejects_invalid_utf8_without_server_error(self):
        request = Request(self.base_url + "/api/ingest", data=b"\xff", method="POST")
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 400)

    def test_cross_origin_browser_writes_are_rejected(self):
        request = Request(
            self.base_url + "/api/ingest",
            data=b'{"events":[{"event_type":"test","host":"lab"}]}',
            headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 403)
        self.assertIn("cross-site", caught.exception.read().decode())
        rebinding = Request(
            self.base_url + "/api/ingest", data=b'{"events":[{"event_type":"test","host":"lab"}]}',
            headers={"Host": "evil.example", "Origin": "http://evil.example", "Sec-Fetch-Site": "same-origin"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(rebinding)
        self.assertEqual(caught.exception.code, 403)
        protocol_mismatch = Request(
            self.base_url + "/api/ingest", data=b'{"events":[{"event_type":"test","host":"lab"}]}',
            headers={"Origin": self.base_url.replace("http://", "https://")}, method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(protocol_mismatch)
        self.assertEqual(caught.exception.code, 403)
        missing_host_port = Request(
            self.base_url + "/api/ingest", data=b'{"events":[]}',
            headers={"Host": "127.0.0.1", "Origin": self.base_url}, method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(missing_host_port)
        self.assertEqual(caught.exception.code, 403)
        with app.database() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        request = Request(
            self.base_url + "/api/alerts/deadbeef", data=b'{"status":"resolved"}',
            headers={"Origin": "https://evil.example"}, method="PATCH",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 403)

    def test_non_loopback_bind_is_read_only_even_when_configured_writable(self):
        self.assertFalse(app.read_only_for_host("127.0.0.1", False))
        self.assertFalse(app.read_only_for_host("localhost", False))
        self.assertTrue(app.read_only_for_host("0.0.0.0", False))
        self.assertTrue(app.read_only_for_host("::", False))
        self.assertTrue(app.read_only_for_host("127.0.0.1", True))
        self.assertFalse(app.is_loopback_host("198.51.100.1"))

    def test_main_applies_read_only_mode_for_non_loopback_bind(self):
        with patch.object(app, "READ_ONLY", False), patch.object(sys, "argv", ["app.py", "--host", "0.0.0.0"]), \
                patch.object(app, "init_db"), patch.object(app, "BoundedThreadingHTTPServer") as server_class:
            app.main()
            self.assertTrue(app.READ_ONLY)
            server_class.assert_called_once_with(("0.0.0.0", 8080), app.Handler)

    def test_dashboard_overview_filters_and_alert_status_flow(self):
        app.load_demo()
        with urlopen(self.base_url + "/") as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"SignalForge", response.read())
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])
            self.assertNotIn("Python/", response.headers["Server"])
        with urlopen(self.base_url + "/app.js") as response:
            self.assertIn(b"refresh()", response.read())
        with urlopen(self.base_url + "/api/config") as response:
            self.assertEqual(json.load(response), {"read_only": False})
        with urlopen(self.base_url + "/api/overview") as response:
            overview = json.load(response)
        self.assertEqual((overview["event_count"], overview["alert_count"]), (10, 4))
        with urlopen(self.base_url + "/api/events") as response:
            self.assertEqual(len(json.load(response)), 10)
        with urlopen(self.base_url + "/api/alerts?status=new") as response:
            alerts = json.load(response)
        self.assertEqual(len(alerts), 4)
        request = Request(
            self.base_url + f"/api/alerts/{alerts[0]['id']}", data=b'{"status":"investigating"}',
            headers={"Content-Type": "application/json", "Origin": self.base_url}, method="PATCH",
        )
        with urlopen(request) as response:
            self.assertEqual(json.load(response)["status"], "investigating")
        with urlopen(self.base_url + "/api/alerts?status=investigating") as response:
            self.assertEqual(len(json.load(response)), 1)

    def test_http_rejects_bad_filters_payloads_and_unknown_alerts(self):
        for path in ("/api/alerts?status=not-a-status",):
            with self.assertRaises(HTTPError) as caught:
                urlopen(self.base_url + path)
            self.assertEqual(caught.exception.code, 400)
        requests = [
            Request(self.base_url + "/api/ingest", data=b"not-json", method="POST"),
            Request(self.base_url + "/api/demo/reset", data=b'{"reset":false}', method="POST"),
            Request(self.base_url + "/api/alerts/deadbeef", data=b'{"status":"new"}', method="PATCH"),
        ]
        for request, expected in zip(requests, (400, 400, 404)):
            with self.assertRaises(HTTPError) as caught:
                urlopen(request)
            self.assertEqual(caught.exception.code, expected)

    def test_http_ingest_is_idempotent_and_runs_detection(self):
        events = [{
            "timestamp": f"2026-10-05T09:0{minute}:00Z", "event_type": "auth_failure",
            "host": "api-lab", "user": "analyst", "src_ip": "192.0.2.80", "outcome": "failure",
        } for minute in range(5)]
        request = Request(
            self.base_url + "/api/ingest", data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urlopen(request) as response:
            first = json.load(response)
            self.assertEqual(response.status, 201)
        request = Request(
            self.base_url + "/api/ingest", data=json.dumps({"events": events}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urlopen(request) as response:
            second = json.load(response)
        self.assertEqual((first["stored"], first["alerts_total"]), (5, 1))
        self.assertEqual((second["stored"], second["duplicates"], second["alerts_total"]), (0, 5, 1))

    def test_http_rejects_body_over_limit(self):
        request = Request(
            self.base_url + "/api/ingest", data=b" " * (app.MAX_BODY + 1),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 400)

    def test_rejects_missing_required_fields(self):
        with self.assertRaisesRegex(ValueError, "event_type and host are required"):
            app.normalize_event({"host": "lab"})

    def test_health_endpoint_and_read_only_rejects_mutation(self):
        with urlopen(self.base_url + "/api/health") as response:
            self.assertEqual(json.load(response)["status"], "ok")
        with patch.object(app, "READ_ONLY", True):
            request = Request(self.base_url + "/api/demo/reset", data=b'{"reset":true}', headers={"Content-Type": "application/json"}, method="POST")
            with self.assertRaises(HTTPError) as caught:
                urlopen(request)
            self.assertEqual(caught.exception.code, 403)
            request = Request(self.base_url + "/api/ingest", data=b'{"events":[]}', headers={"Content-Type": "application/json"}, method="POST")
            with self.assertRaises(HTTPError) as caught:
                urlopen(request)
            self.assertEqual(caught.exception.code, 403)
            request = Request(self.base_url + "/api/alerts/deadbeef", data=b'{"status":"resolved"}', headers={"Content-Type": "application/json"}, method="PATCH")
            with self.assertRaises(HTTPError) as caught:
                urlopen(request)
            self.assertEqual(caught.exception.code, 403)
        with app.database() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
