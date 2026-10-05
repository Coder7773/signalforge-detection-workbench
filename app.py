#!/usr/bin/env python3
"""SignalForge: a small, local-first detection engineering workbench."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import threading
import uuid
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SIGNALFORGE_DB", ROOT / "data" / "signalforge.db"))
MAX_BODY = 1_000_000
MAX_BATCH = 5_000
STATUSES = {"new", "investigating", "resolved", "false_positive"}
READ_ONLY = os.environ.get("SIGNALFORGE_READ_ONLY", "false").strip().lower() not in {"0", "false", "no"}


@contextmanager
def database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with database() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                host TEXT NOT NULL,
                user_name TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL DEFAULT '',
                process TEXT NOT NULL DEFAULT '',
                command_line TEXT NOT NULL DEFAULT '',
                outcome TEXT NOT NULL DEFAULT '',
                target_path TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_auth ON events(event_type, outcome, src_ip);
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                mitre_id TEXT NOT NULL,
                description TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                user_name TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at);
            """
        )


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def is_loopback_host(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


def read_only_for_host(host, configured):
    return configured or not is_loopback_host(host)


def normalize_timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("timestamp must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO 8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def clean_text(value, field, limit=500):
    if value is None:
        return ""
    if not isinstance(value, (str, int, float)):
        raise ValueError(f"{field} must be text")
    value = str(value).strip()
    if len(value) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return value


def normalize_event(item):
    if not isinstance(item, dict):
        raise ValueError("each event must be a JSON object")
    event = {
        "timestamp": normalize_timestamp(item.get("timestamp", utc_now())),
        "event_type": clean_text(item.get("event_type"), "event_type", 80).lower(),
        "host": clean_text(item.get("host"), "host", 255),
        "user_name": clean_text(item.get("user"), "user", 255),
        "src_ip": clean_text(item.get("src_ip"), "src_ip", 64),
        "process": clean_text(item.get("process"), "process", 255),
        "command_line": clean_text(item.get("command_line"), "command_line", 2_000),
        "outcome": clean_text(item.get("outcome"), "outcome", 40).lower(),
        "target_path": clean_text(item.get("target_path"), "target_path", 1_000),
        "details": clean_text(item.get("details"), "details", 2_000),
        "raw_json": json.dumps(item, ensure_ascii=False, sort_keys=True, allow_nan=False),
    }
    if not event["event_type"] or not event["host"]:
        raise ValueError("event_type and host are required")
    if event["outcome"] not in {"", "success", "failure", "blocked", "unknown"}:
        raise ValueError("outcome must be success, failure, blocked, or unknown")
    return event


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_alert(conn, *, key, rule_id, title, severity, mitre_id, description,
                 host, user_name, src_ip, first_seen, last_seen, evidence):
    now = utc_now()
    conn.execute(
        """INSERT INTO alerts
        (id, fingerprint, rule_id, title, severity, status, mitre_id, description,
         host, user_name, src_ip, first_seen, last_seen, event_count,
         evidence_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            host=excluded.host,
            user_name=excluded.user_name,
            src_ip=excluded.src_ip,
            first_seen=excluded.first_seen,
            last_seen=excluded.last_seen,
            event_count=excluded.event_count,
            evidence_json=excluded.evidence_json,
            updated_at=excluded.updated_at
        WHERE alerts.host != excluded.host
           OR alerts.user_name != excluded.user_name
           OR alerts.src_ip != excluded.src_ip
           OR alerts.first_seen != excluded.first_seen
           OR alerts.last_seen != excluded.last_seen
           OR alerts.event_count != excluded.event_count
           OR alerts.evidence_json != excluded.evidence_json""",
        (uuid.uuid4().hex, fingerprint(key), rule_id, title, severity, mitre_id,
         description, host, user_name, src_ip, first_seen, last_seen,
         len(evidence), json.dumps(evidence, ensure_ascii=False), now, now),
    )


def run_detections(conn):
    """Run deterministic lab rules; unique fingerprints make ingestion idempotent."""
    events = [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY timestamp, id")]
    failures = defaultdict(list)
    for event in events:
        if event["event_type"] in {"auth_failure", "login_failure"} and event["outcome"] == "failure" and event["src_ip"]:
            failures[(event["src_ip"], event["user_name"])].append(event)

    # A sliding ten-minute window catches repeated failures without alerting per event.
    brute_force_alerts = {}
    for (src_ip, user_name), rows in failures.items():
        left = 0
        for right, event in enumerate(rows):
            current = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp()
            while left < right and current - datetime.fromisoformat(rows[left]["timestamp"].replace("Z", "+00:00")).timestamp() > 600:
                left += 1
            if right - left + 1 < 5:
                continue
            window = int(datetime.fromisoformat(rows[left]["timestamp"].replace("Z", "+00:00")).timestamp() // 600)
            evidence = rows[left:right + 1]
            key = f"brute-force|{src_ip}|{user_name}|{window}"
            brute_force_alerts[key] = (event, evidence, user_name, src_ip)
    for key, (event, evidence, user_name, src_ip) in brute_force_alerts.items():
        create_alert(
            conn, key=key, rule_id="SF-AUTH-001", title="Repeated authentication failures",
            severity="high", mitre_id="T1110",
            description="At least five failed authentication attempts from one source against one account within ten minutes.",
            host=event["host"], user_name=user_name, src_ip=src_ip,
            first_seen=evidence[0]["timestamp"], last_seen=evidence[-1]["timestamp"], evidence=evidence,
        )

    persistence_markers = ("/.ssh/authorized_keys", "/etc/cron", "/var/spool/cron", "/etc/systemd/system", ".config/systemd/user")
    for event in events:
        command = f"{event['process']} {event['command_line']}".lower()
        if "powershell" in command or "pwsh" in command:
            if re.search(r"(?:^|\s)-(?:e|enc|encodedcommand)(?:\s|$)", command) or "frombase64string" in command:
                create_alert(
                    conn, key=f"encoded-powershell|{event['id']}", rule_id="SF-WIN-001",
                    title="Encoded PowerShell execution", severity="high", mitre_id="T1059.001",
                    description="PowerShell command line contains an encoded-command or Base64 decoding indicator.",
                    host=event["host"], user_name=event["user_name"], src_ip=event["src_ip"],
                    first_seen=event["timestamp"], last_seen=event["timestamp"], evidence=[event],
                )
        path = event["target_path"].lower()
        if event["event_type"] in {"file_write", "file_create"} and any(marker in path for marker in persistence_markers):
            create_alert(
                conn, key=f"linux-persistence|{event['id']}", rule_id="SF-LNX-001",
                title="Write to a Linux persistence location", severity="medium", mitre_id="T1053.003",
                description="A file event targets a common cron, systemd, or SSH key persistence location.",
                host=event["host"], user_name=event["user_name"], src_ip=event["src_ip"],
                first_seen=event["timestamp"], last_seen=event["timestamp"], evidence=[event],
            )
        details = f"{event['details']} {event['raw_json']}".lower()
        if event["event_type"] in {"privilege_change", "account_change"} and any(
            marker in details for marker in ("sudo", "administrator", "privileged group", "domain admins")
        ):
            create_alert(
                conn, key=f"privilege-change|{event['id']}", rule_id="SF-IAM-001",
                title="Privileged group or account change", severity="high", mitre_id="T1098",
                description="An account-change event references a privileged group; review the actor and change approval.",
                host=event["host"], user_name=event["user_name"], src_ip=event["src_ip"],
                first_seen=event["timestamp"], last_seen=event["timestamp"], evidence=[event],
            )


def ingest(items):
    if not isinstance(items, list) or not items or len(items) > MAX_BATCH:
        raise ValueError(f"events must be a non-empty list of at most {MAX_BATCH} objects")
    normalized = [normalize_event(item) for item in items]
    with database() as conn:
        before = conn.total_changes
        conn.executemany(
            """INSERT OR IGNORE INTO events
            (id, timestamp, event_type, host, user_name, src_ip, process, command_line,
             outcome, target_path, details, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(hashlib.sha256(event["raw_json"].encode("utf-8")).hexdigest(), *(event[key] for key in (
                "timestamp", "event_type", "host", "user_name", "src_ip", "process",
                "command_line", "outcome", "target_path", "details", "raw_json"))) for event in normalized],
        )
        stored = conn.total_changes - before
        run_detections(conn)
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {"accepted": len(normalized), "stored": stored, "duplicates": len(normalized) - stored, "alerts_total": total}


def load_demo(reset=False):
    with database() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if reset:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM events")
        elif count:
            run_detections(conn)
            return {"loaded": 0, "message": "Existing events kept; use reset=true to reload the demo."}
    with (ROOT / "data" / "demo_events.jsonl").open(encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream if line.strip()]
    result = ingest(records)
    return {"loaded": result["accepted"], "alerts_total": result["alerts_total"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "SignalForge"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def check_same_origin(self):
        origin = self.headers.get("Origin")
        if self.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
            self.send_json({"error": "cross-site requests are not allowed"}, 403)
            return False
        try:
            request_host = urlsplit("//" + self.headers.get("Host", ""))
            request_port = request_host.port or (443 if isinstance(self.connection, ssl.SSLSocket) else 80)
        except ValueError:
            request_host = None
        if (not request_host or not request_host.hostname or request_host.username or request_host.password
                or request_port != self.server.server_port):
            self.send_json({"error": "invalid request host or port"}, 403)
            return False
        if not READ_ONLY and (not is_loopback_host(request_host.hostname)
                              or not is_loopback_host(self.client_address[0])):
            self.send_json({"error": "writable mode is restricted to loopback clients"}, 403)
            return False
        if origin is None:
            return True
        try:
            parsed_origin = urlsplit(origin)
            if (parsed_origin.scheme not in {"http", "https"} or not parsed_origin.hostname
                    or parsed_origin.username or parsed_origin.password or parsed_origin.path
                    or parsed_origin.query or parsed_origin.fragment):
                raise ValueError("invalid origin")
            origin_port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
            request_scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
            same_origin = (parsed_origin.scheme == request_scheme
                           and parsed_origin.hostname.casefold() == request_host.hostname.casefold()
                           and origin_port == request_port)
        except ValueError:
            same_origin = False
        if not same_origin:
            self.send_json({"error": "cross-origin requests are not allowed"}, 403)
            return False
        return True

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 1 or length > MAX_BODY:
            raise ValueError(f"request body must be between 1 and {MAX_BODY} bytes")
        def reject_constant(value):
            raise ValueError(f"invalid JSON constant: {value}")

        try:
            return json.loads(self.rfile.read(length), parse_constant=reject_constant)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ValueError("request body must be valid JSON") from exc

    def do_GET(self):
        path = urlparse(self.path)
        static_files = {"/": ("index.html", "text/html; charset=utf-8"),
                        "/index.html": ("index.html", "text/html; charset=utf-8"),
                        "/app.js": ("app.js", "text/javascript; charset=utf-8")}
        if path.path in static_files:
            name, content_type = static_files[path.path]
            body = (ROOT / "static" / name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path.path == "/api/health":
            self.send_json({"status": "ok", "name": "SignalForge", "version": "1.0.0"})
            return
        if path.path == "/api/config":
            self.send_json({"read_only": READ_ONLY})
            return
        if path.path == "/api/overview":
            with database() as conn:
                statuses = {row["status"]: row["count"] for row in conn.execute("SELECT status, COUNT(*) AS count FROM alerts GROUP BY status")}
                severities = {row["severity"]: row["count"] for row in conn.execute("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity")}
                event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            self.send_json({"event_count": event_count, "alert_count": sum(statuses.values()), "statuses": statuses, "severities": severities})
            return
        if path.path == "/api/alerts":
            status = parse_qs(path.query).get("status", ["all"])[0]
            if status not in STATUSES | {"all"}:
                self.send_json({"error": "invalid status filter"}, 400)
                return
            sql = "SELECT * FROM alerts" + (" WHERE status = ?" if status != "all" else "") + " ORDER BY created_at DESC LIMIT 500"
            with database() as conn:
                rows = conn.execute(sql, (status,) if status != "all" else ()).fetchall()
            self.send_json([self.alert_json(row) for row in rows])
            return
        if path.path == "/api/events":
            with database() as conn:
                rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 200").fetchall()
            self.send_json([self.event_json(row) for row in rows])
            return
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if READ_ONLY:
            self.send_json({"error": "this public demo is read-only"}, 403)
            return
        if not self.check_same_origin():
            return
        path = urlparse(self.path).path
        try:
            if path == "/api/ingest":
                payload = self.read_json()
                items = payload if isinstance(payload, list) else payload.get("events") if isinstance(payload, dict) else None
                self.send_json(ingest(items), 201)
            elif path == "/api/demo/reset":
                payload = self.read_json()
                if not isinstance(payload, dict) or payload.get("reset") is not True:
                    self.send_json({"error": "send {\"reset\": true} to replace local data with the demo"}, 400)
                    return
                self.send_json(load_demo(reset=True))
            else:
                self.send_json({"error": "not found"}, 404)
        except (ValueError, TypeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except sqlite3.Error:
            self.send_json({"error": "database operation failed"}, 500)

    def do_PATCH(self):
        if READ_ONLY:
            self.send_json({"error": "this public demo is read-only"}, 403)
            return
        if not self.check_same_origin():
            return
        match = re.fullmatch(r"/api/alerts/([a-f0-9]+)", urlparse(self.path).path)
        if not match:
            self.send_json({"error": "not found"}, 404)
            return
        try:
            payload = self.read_json()
            status = payload.get("status") if isinstance(payload, dict) else None
            if status not in STATUSES:
                self.send_json({"error": "status must be new, investigating, resolved, or false_positive"}, 400)
                return
            with database() as conn:
                result = conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?", (status, utc_now(), match.group(1)))
                if not result.rowcount:
                    self.send_json({"error": "alert not found"}, 404)
                    return
                row = conn.execute("SELECT * FROM alerts WHERE id = ?", (match.group(1),)).fetchone()
            self.send_json(self.alert_json(row))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
        except sqlite3.Error:
            self.send_json({"error": "database operation failed"}, 500)

    @staticmethod
    def alert_json(row):
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        return item

    @staticmethod
    def event_json(row):
        item = dict(row)
        item["raw"] = json.loads(item.pop("raw_json"))
        return item

    def log_message(self, fmt, *args):
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}")


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.worker_slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.worker_slots.release()


def main():
    global READ_ONLY
    parser = argparse.ArgumentParser(description="Run the local SignalForge detection workbench")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--demo", action="store_true", help="load demo events if the database is empty")
    args = parser.parse_args()
    READ_ONLY = read_only_for_host(args.host, READ_ONLY)
    init_db()
    if args.demo:
        print(load_demo())
    server = BoundedThreadingHTTPServer((args.host, args.port), Handler)
    print(f"SignalForge running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSignalForge stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
