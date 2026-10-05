import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app
import import_logs


class LogImportTests(unittest.TestCase):
    def test_windows_security_xml_maps_failed_logon_fields(self):
        xml = """<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
          <TimeCreated SystemTime="2026-10-05T09:00:00.000Z"/><Computer>win-lab</Computer></System>
          <EventData><Data Name="TargetUserName">analyst</Data><Data Name="IpAddress">192.0.2.15</Data>
          <Data Name="LogonType">3</Data></EventData></Event></Events>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security.xml"
            path.write_text(xml, encoding="utf-8")
            events = import_logs.import_windows_xml(path)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["event_type"], events[0]["outcome"]), ("auth_failure", "failure"))
        self.assertEqual((events[0]["host"], events[0]["user"], events[0]["src_ip"]), ("win-lab", "analyst", "192.0.2.15"))

    def test_windows_xml_rejects_dtd_and_entity_declarations(self):
        xml = '<!DOCTYPE Events [<!ENTITY x "blocked">]><Events/>'
        with tempfile.TemporaryDirectory() as directory:
            for encoding in ("utf-8", "utf-16"):
                path = Path(directory) / f"events-{encoding}.xml"
                path.write_text(xml, encoding=encoding)
                with self.assertRaisesRegex(ValueError, "DOCTYPE"):
                    import_logs.import_windows_xml(path)

    def test_linux_auth_logs_map_ssh_failures_and_sudo(self):
        lines = "\n".join(
            f"Oct  5 09:0{minute}:00 lab-linux sshd[123]: Failed password for analyst from 192.0.2.15 port 22 ssh2"
            for minute in range(5)
        ) + "\nOct  5 09:06:00 lab-linux sudo: analyst : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n"
        lines += "Oct  5 09:07:00 lab-linux sudo: analyst : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo analyst\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(lines, encoding="utf-8")
            events = import_logs.import_linux_auth(path)
        self.assertEqual([event["event_type"] for event in events], ["auth_failure"] * 5 + ["process_start", "privilege_change"])
        self.assertEqual(events[0]["timestamp"], "2026-10-05T09:00:00Z")
        self.assertEqual(events[0]["src_ip"], "192.0.2.15")
        self.assertIn("/usr/sbin/usermod", events[-1]["details"])
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "DB_PATH", Path(directory) / "signalforge.sqlite"):
            app.init_db()
            result = app.ingest(events)
            with app.database() as conn:
                alert_ids = {row[0] for row in conn.execute("SELECT rule_id FROM alerts")}
        self.assertEqual((result["stored"], result["alerts_total"]), (7, 2))
        self.assertEqual(alert_ids, {"SF-AUTH-001", "SF-IAM-001"})

    def test_import_rejects_non_object_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                import_logs.import_jsonl(path)

    def test_cli_initializes_database_when_app_is_not_running(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            source.write_text(json.dumps({
                "timestamp": "2026-10-05T09:00:00Z", "event_type": "auth_success", "host": "lab",
            }) + "\n", encoding="utf-8")
            db_path = Path(directory) / "data" / "signalforge.sqlite"
            with patch.object(app, "DB_PATH", db_path), patch("sys.argv", ["import_logs.py", "--format", "jsonl", str(source)]), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(import_logs.main(), 0)
            self.assertTrue(db_path.is_file())
            self.assertEqual(json.loads(output.getvalue())["stored"], 1)

    def test_cli_reports_deep_jsonl_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "nested.jsonl"
            source.write_text("[" * 5_000 + "]" * 5_000, encoding="utf-8")
            with patch("sys.argv", ["import_logs.py", "--format", "jsonl", str(source)]), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(import_logs.main(), 1)
            self.assertIn("Import failed:", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
