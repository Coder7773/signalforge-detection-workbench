#!/usr/bin/env python3
"""Import authorized Windows event XML or Linux auth.log into SignalForge."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import app

MAX_FILE_BYTES = 50_000_000
MAX_EVENTS = app.MAX_BATCH
DTD_MARKERS = tuple("<!DOCTYPE".encode(encoding) for encoding in ("ascii", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"))
DTD_OVERLAP = max(map(len, DTD_MARKERS)) - 1
SYSLOG = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[^:]+):\s*(?P<message>.*)$")
FAILED_SSH = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_SSH = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
SUDO = re.compile(r"(?P<user>\S+)\s*:\s*TTY=.*?;\s*COMMAND=(?P<command>.*)$")

WINDOWS_EVENTS = {
    "1": "process_start", "3": "network_connection", "5": "process_stop",
    "10": "process_access", "11": "file_create", "12": "registry_change",
    "13": "registry_change", "14": "registry_change", "22": "dns_query",
    "4624": "auth_success", "4625": "auth_failure", "4688": "process_start",
    "4728": "privilege_change", "4732": "privilege_change", "4756": "privilege_change",
}


def import_windows_xml(path: Path) -> list[dict]:
    overlap = b""
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            sample = overlap + chunk
            if any(marker in sample for marker in DTD_MARKERS):
                raise ValueError("DOCTYPE declarations are not supported")
            overlap = sample[-DTD_OVERLAP:]
    events = []
    for _, node in ET.iterparse(path, events=("end",)):
        if node.tag.rsplit("}", 1)[-1] != "Event":
            continue
        system = next((child for child in node if child.tag.rsplit("}", 1)[-1] == "System"), None)
        if system is None:
            node.clear()
            continue
        get = lambda parent, name: next((child for child in parent.iter() if child.tag.rsplit("}", 1)[-1] == name), None)
        event_id_node = get(system, "EventID")
        event_id = event_id_node.text.strip() if event_id_node is not None and event_id_node.text else ""
        event_type = WINDOWS_EVENTS.get(event_id)
        if event_type:
            time_node = get(system, "TimeCreated")
            timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
            computer_node = get(system, "Computer")
            host = computer_node.text.strip() if computer_node is not None and computer_node.text else ""
            values = {
                item.attrib.get("Name", ""): item.text or ""
                for item in node.iter() if item.tag.rsplit("}", 1)[-1] == "Data"
            }
            image = values.get("Image") or values.get("NewProcessName", "")
            target = values.get("TargetFilename", "")
            username = values.get("TargetUserName") or values.get("SubjectUserName") or values.get("User", "")
            src_ip = values.get("SourceIp") or values.get("IpAddress", "")
            details = "; ".join(f"{key}={value}" for key, value in values.items() if value)[:2_000]
            events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "host": host,
                "user": username,
                "src_ip": src_ip,
                "process": image.rsplit("\\", 1)[-1],
                "command_line": values.get("CommandLine", ""),
                "outcome": "failure" if event_id == "4625" else "success" if event_id == "4624" else "unknown",
                "target_path": target,
                "details": f"Windows Event ID {event_id}; {details}"[:2_000],
            })
            if len(events) > MAX_EVENTS:
                raise ValueError(f"file contains more than {MAX_EVENTS} supported events")
        node.clear()
    return events


def import_linux_auth(path: Path, timezone_offset: str = "+00:00") -> list[dict]:
    events = []
    year = datetime.now(timezone.utc).year
    tz = datetime.fromisoformat(f"2000-01-01T00:00:00{timezone_offset}").tzinfo
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        entry = SYSLOG.match(line)
        if not entry:
            continue
        message = entry["message"]
        failed = FAILED_SSH.search(message)
        accepted = ACCEPTED_SSH.search(message)
        sudo = SUDO.search(message)
        if not (failed or accepted or sudo):
            continue
        date = datetime.strptime(f"{year} {entry['month']} {entry['day']} {entry['time']}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz).astimezone(timezone.utc)
        sudo_command = sudo["command"] if sudo else ""
        privileged_sudo = sudo and re.search(r"(?:^|/)(?:useradd|usermod|userdel|groupadd|groupdel|gpasswd|visudo|passwd)(?:\s|$)|/etc/sudoers", sudo_command, re.IGNORECASE)
        event_type = "auth_failure" if failed else "auth_success" if accepted else "privilege_change" if privileged_sudo else "process_start"
        match = failed or accepted or sudo
        events.append({
            "timestamp": date.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "event_type": event_type,
            "host": entry["host"],
            "user": match["user"],
            "src_ip": match.groupdict().get("ip", ""),
            "process": "sshd" if failed or accepted else "sudo",
            "outcome": "failure" if failed else "success" if accepted else "unknown",
            "details": (f"SSH authentication failure; source line {line_number}" if failed else
                        f"SSH authentication success; source line {line_number}" if accepted else
                        f"sudo command: {sudo_command}"),
        })
        if len(events) > MAX_EVENTS:
            raise ValueError(f"file contains more than {MAX_EVENTS} supported events")
    return events


def import_jsonl(path: Path) -> list[dict]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("each JSONL line must be a JSON object")
            events.append(event)
            if len(events) > MAX_EVENTS:
                raise ValueError(f"file contains more than {MAX_EVENTS} events")
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Import authorized endpoint logs into the local SignalForge database")
    parser.add_argument("--format", required=True, choices=("windows-xml", "linux-auth", "jsonl"))
    parser.add_argument("--timezone", default="+00:00", help="source timezone for yearless Linux auth.log timestamps (default: UTC, e.g. +05:30)")
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error(f"file not found: {args.file}")
    if args.file.stat().st_size > MAX_FILE_BYTES:
        parser.error(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        events = (import_linux_auth(args.file, args.timezone) if args.format == "linux-auth" else
                  {"windows-xml": import_windows_xml, "jsonl": import_jsonl}[args.format](args.file))
        app.init_db()
        result = app.ingest(events)
    except (ET.ParseError, OSError, UnicodeError, ValueError, RecursionError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"Import failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"parsed": len(events), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
