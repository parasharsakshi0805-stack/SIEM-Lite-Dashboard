#!/usr/bin/env python3
import argparse
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

DEFAULT_LOG_FILE = "/var/log/auth.log"
DEFAULT_API_URL = os.environ.get("SIEM_API_URL", "http://localhost:8000/agents/ingest/batch")
DEFAULT_API_KEY = os.environ.get("SIEM_AGENT_API_KEY", "")
DEFAULT_STATE_FILE = os.environ.get("SIEM_AGENT_STATE_FILE", "agent_state.json")
DEFAULT_TENANT_ID = os.environ.get("SIEM_TENANT_ID", "default")

BATCH_SIZE = 50
FLUSH_INTERVAL = 5
POLL_INTERVAL = 0.5
MAX_BACKOFF = 60

IP_GROUP = r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# Each rule: (pattern, event_type, severity, outcome, description)
#
# `outcome` is what the rules engine counts. One real failed login writes SEVERAL
# lines in auth.log ("Invalid user...", "Failed password...", "pam_unix ...
# authentication failure"). If every line counted as a failure, 3 attempts would
# look like 9. So ONLY the "Failed password" line is marked "failure"; the
# others still get shipped (useful context) but with outcome=None.
RULES = [
    (re.compile(rf"Failed password for invalid user (?P<user>\S+) from {IP_GROUP}"),
     "login_attempt", "high", "failure", "failed login, unknown username"),
    (re.compile(rf"Failed password for (?P<user>\S+) from {IP_GROUP}"),
     "login_attempt", "medium", "failure", "failed login, valid username"),
    (re.compile(rf"Invalid user (?P<user>\S+) from {IP_GROUP}"),
     "login_attempt", "medium", None, "login attempt with nonexistent username"),
    (re.compile(rf"Accepted password for (?P<user>\S+) from {IP_GROUP}"),
     "login_attempt", "low", "success", "successful password login"),
    (re.compile(rf"Accepted publickey for (?P<user>\S+) from {IP_GROUP}"),
     "login_attempt", "low", "success", "successful key-based login"),
    (re.compile(rf"authentication failure;.*rhost={IP_GROUP}(?:\s+user=(?P<user>\S+))?"),
     "login_attempt", "medium", None, "PAM authentication failure"),
    (re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND="),
     "config_change", "medium", None, "privilege escalation via sudo"),
]

# Two timestamp styles exist in auth.log:
#   classic syslog : "Oct  2 10:15:01 myhost sshd[123]: ..."          (no year, no zone)
#   ISO / RFC3339  : "2026-10-02T10:15:01.123456+05:30 myhost sshd..." (Ubuntu 22.04+)
CLASSIC_HEADER = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s")
ISO_HEADER = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(?P<host>\S+)\s")


@dataclass
class ParsedEvent:
    source_ip: str
    event_type: str
    severity: str
    raw_message: str
    tenant_id: str
    username: Optional[str] = None
    host: Optional[str] = None
    outcome: Optional[str] = None
    timestamp: Optional[str] = None      # ISO-8601 in UTC: when the event HAPPENED


def parse_header(line: str, now: Optional[datetime] = None):
    """
    Pull (timestamp_iso_utc, hostname) off the front of a log line.
    Returns (None, None) if the line has no recognisable header.
    """
    now = now or datetime.now().astimezone()

    match = ISO_HEADER.match(line)
    if match:
        try:
            ts = datetime.fromisoformat(match.group("ts").replace("Z", "+00:00"))
        except ValueError:
            return None, match.group("host")
        if ts.tzinfo is None:
            ts = ts.astimezone()                       # no zone written: assume this machine's zone
        return ts.astimezone(timezone.utc).isoformat(), match.group("host")

    match = CLASSIC_HEADER.match(line)
    if match:
        try:
            ts = datetime.strptime(f"{now.year} {match.group('ts')}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None, match.group("host")
        ts = ts.astimezone()                           # classic syslog is in this machine's local time
        # The line has no year. On 1 Jan, a line from 31 Dec would be parsed as
        # "31 Dec this year" = almost a year in the future. Detect that, step back a year.
        if ts > now + timedelta(days=1):
            ts = ts.replace(year=ts.year - 1)
        return ts.astimezone(timezone.utc).isoformat(), match.group("host")

    return None, None


def parse_line(line: str, tenant_id: str, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
    for pattern, event_type, severity, outcome, _description in RULES:
        match = pattern.search(line)
        if match:
            groups = match.groupdict()
            timestamp, host = parse_header(line, now)
            return ParsedEvent(
                source_ip=groups.get("ip") or "0.0.0.0",
                event_type=event_type,
                severity=severity,
                raw_message=line.strip(),
                tenant_id=tenant_id,
                username=groups.get("user"),
                host=host,
                outcome=outcome,
                timestamp=timestamp,
            )
    return None


def load_checkpoint(state_file: str) -> dict:
    path = Path(state_file)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"inode": None, "offset": 0}


def save_checkpoint(state_file: str, inode, offset: int) -> None:
    Path(state_file).write_text(json.dumps({"inode": inode, "offset": offset}))


def tail_file(log_file: str, state_file: str):
    checkpoint = load_checkpoint(state_file)
    f = open(log_file, "r")

    current_id = os.fstat(f.fileno()).st_ino if hasattr(os, "fstat") else None
    if checkpoint.get("inode") == current_id and current_id is not None:
        f.seek(checkpoint["offset"])
    else:
        f.seek(0, os.SEEK_END)

    while True:
        line = f.readline()
        if line:
            yield line
            save_checkpoint(state_file, current_id, f.tell())
            continue

        yield None

        try:
            disk_size = os.path.getsize(log_file)
            cur_size = f.tell()
            shrank = cur_size > disk_size
        except FileNotFoundError:
            shrank = False

        if shrank:
            f.close()
            f = open(log_file, "r")
            current_id = os.fstat(f.fileno()).st_ino if hasattr(os, "fstat") else None
            save_checkpoint(state_file, current_id, 0)
            continue

        time.sleep(POLL_INTERVAL)


def send_batch(api_url: str, api_key: str, events: list) -> bool:
    payload = [asdict(e) for e in events]
    backoff = 1
    while True:
        try:
            resp = requests.post(
                api_url,
                json=payload,
                headers={"X-API-Key": api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                print(f"[shipped] {len(events)} events -> {api_url}")
                return True
            # 503 means the server's queue is full: backing off and retrying is the right move.
            print(f"[error] server returned {resp.status_code}: {resp.text[:200]}")
        except requests.RequestException as exc:
            print(f"[error] network problem sending batch: {exc}")

        print(f"[retry] backing off {backoff}s before retrying this batch")
        time.sleep(backoff)
        backoff = min(backoff * 2, MAX_BACKOFF)


def run(log_file: str, api_url: str, api_key: str, state_file: str, tenant_id: str):
    print(f"Watching {log_file}")
    print(f"Shipping to {api_url}")

    buffer = []
    last_flush = time.time()

    for line in tail_file(log_file, state_file):
        if line is not None:
            event = parse_line(line, tenant_id)
            if event:
                buffer.append(event)

        due_to_size = len(buffer) >= BATCH_SIZE
        due_to_time = buffer and (time.time() - last_flush >= FLUSH_INTERVAL)

        if due_to_size or due_to_time:
            send_batch(api_url, api_key, buffer)
            buffer = []
            last_flush = time.time()


def main():
    parser = argparse.ArgumentParser(description="Tail a log and ship parsed events to SIEM-Lite.")
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--api-key", default=DEFAULT_API_KEY)
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("No API key provided. Set --api-key or SIEM_AGENT_API_KEY.")

    run(args.log_file, args.api_url, args.api_key, args.state_file, args.tenant_id)


if __name__ == "__main__":
    main()
