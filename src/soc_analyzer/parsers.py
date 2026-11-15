"""Parsers that turn raw log lines into normalized LogEvent objects.

Two formats are supported out of the box:

  * Linux ``auth.log`` / ``secure`` (syslog format, produced by sshd, sudo, su)
  * The Apache/Nginx *combined* access-log format specifically (NCSA combined
    log format: IP, timestamp, request line, status, size, referrer, user
    agent). Other Apache/Nginx log formats — custom `LogFormat` directives,
    JSON-structured logs, etc. — are NOT covered by this parser.

Both parsers are intentionally forgiving: a line that doesn't match any
known pattern is simply skipped rather than raising, so a single malformed
or unusual line in a multi-thousand-line log file doesn't kill the run.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional

from .models import LogEvent

# --------------------------------------------------------------------------
# auth.log (syslog) parsing
# --------------------------------------------------------------------------

# Aug 10 09:15:32 hostname sshd[12345]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2
_SSH_FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)

# Aug 10 09:15:40 hostname sshd[12345]: Accepted password for root from 203.0.113.7 port 51244 ssh2
_SSH_ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

# Aug 10 09:16:01 hostname sshd[12345]: Invalid user test from 203.0.113.7 port 51235
_SSH_INVALID_USER_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)

# Aug 10 09:20:11 hostname sudo:   bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
_SUDO_FAIL_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo:\s+"
    r"(?P<user>\S+)\s*:\s*(?P<reason>user NOT in sudoers|.*authentication failure.*)"
)

# Aug 10 09:20:30 hostname sudo:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/su -
_SUDO_SUCCESS_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo:\s+"
    r"(?P<user>\S+)\s*:\s*TTY=.*COMMAND=(?P<command>.+)$"
)


def _parse_syslog_timestamp(ts: str, year: Optional[int] = None) -> datetime:
    """Syslog timestamps have no year, so we splice one in (default: current)."""
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")


def parse_auth_log(lines: Iterable[str], year: Optional[int] = None) -> List[LogEvent]:
    events: List[LogEvent] = []
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue

        if m := _SSH_FAILED_RE.match(line):
            events.append(LogEvent(
                timestamp=_parse_syslog_timestamp(m["ts"], year),
                source="auth", event_type="failed_login",
                source_ip=m["ip"], username=m["user"], raw_line=line,
            ))
        elif m := _SSH_ACCEPTED_RE.match(line):
            events.append(LogEvent(
                timestamp=_parse_syslog_timestamp(m["ts"], year),
                source="auth", event_type="accepted_login",
                source_ip=m["ip"], username=m["user"], raw_line=line,
            ))
        elif m := _SSH_INVALID_USER_RE.match(line):
            events.append(LogEvent(
                timestamp=_parse_syslog_timestamp(m["ts"], year),
                source="auth", event_type="invalid_user",
                source_ip=m["ip"], username=m["user"], raw_line=line,
            ))
        elif m := _SUDO_FAIL_RE.match(line):
            events.append(LogEvent(
                timestamp=_parse_syslog_timestamp(m["ts"], year),
                source="auth", event_type="sudo_failure",
                username=m["user"], raw_line=line,
                extra={"reason": m["reason"]},
            ))
        elif m := _SUDO_SUCCESS_RE.match(line):
            events.append(LogEvent(
                timestamp=_parse_syslog_timestamp(m["ts"], year),
                source="auth", event_type="sudo_success",
                username=m["user"], raw_line=line,
                extra={"command": m["command"]},
            ))
    return events


# --------------------------------------------------------------------------
# Apache / Nginx combined access log parsing
# --------------------------------------------------------------------------

# 203.0.113.7 - - [10/Aug/2026:09:15:32 +0000] "GET /admin/login.php HTTP/1.1" 404 1234 "-" "Mozilla/5.0"
_ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


def parse_apache_log(lines: Iterable[str]) -> List[LogEvent]:
    events: List[LogEvent] = []
    for line in lines:
        line = line.rstrip("\n")
        if not (m := _ACCESS_LOG_RE.match(line)):
            continue
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            continue
        events.append(LogEvent(
            timestamp=ts, source="apache", event_type="http_request",
            source_ip=m["ip"], method=m["method"], path=m["path"],
            status_code=int(m["status"]), raw_line=line,
        ))
    return events


# --------------------------------------------------------------------------
# Format auto-detection + top-level entry point
# --------------------------------------------------------------------------

def detect_log_type(lines: List[str], sample_size: int = 20) -> str:
    """Guess whether a log file is auth.log-style or an access log."""
    sample = lines[:sample_size]
    auth_hits = sum(1 for l in sample if " sshd[" in l or " sudo:" in l)
    apache_hits = sum(1 for l in sample if _ACCESS_LOG_RE.match(l.rstrip("\n")))
    if apache_hits >= auth_hits and apache_hits > 0:
        return "apache"
    if auth_hits > 0:
        return "auth"
    return "unknown"


def parse_log_file(path: str, log_type: str = "auto", year: Optional[int] = None) -> List[LogEvent]:
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()

    if log_type == "auto":
        log_type = detect_log_type(lines)

    if log_type == "auth":
        return parse_auth_log(lines, year=year)
    if log_type == "apache":
        return parse_apache_log(lines)

    raise ValueError(
        f"Could not determine log format for {path!r}. "
        "Pass --type auth or --type apache explicitly."
    )
