"""Parsers that turn raw log lines into normalized LogEvent objects.

Two formats are supported out of the box:

  * Linux ``auth.log`` / ``secure`` (syslog format, produced by sshd, sudo, su)
  * The Apache/Nginx *combined* access-log format specifically (NCSA combined
    log format: IP, timestamp, request line, status, size, referrer, user
    agent). Other Apache/Nginx log formats — custom `LogFormat` directives,
    JSON-structured logs, etc. — are NOT covered by this parser.

Both parsers are intentionally forgiving: a line that doesn't match any known
pattern is ignored, and a line that matches a known pattern but cannot be parsed
(for example an impossible date such as Feb 29 in a non-leap year) is skipped and
counted in ``ParseResult.skipped_lines``. One bad line never kills the run.

Files are read as UTF-8 with undecodable bytes replaced, one line at a time, after a
size check (``max_bytes``), so a huge or binary file cannot exhaust memory before the
analyst gets a clear error.
"""

from __future__ import annotations

import itertools
import os
import re
import stat
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timezone, tzinfo

from .models import LogEvent, ParseResult

DEFAULT_MAX_FILE_MB = 100
DETECTION_SAMPLE_LINES = 20
_BOM = chr(0xFEFF)
_MB = 1024 * 1024

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

# Checked in this order; the first match wins.
_AUTH_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (_SSH_FAILED_RE, "failed_login"),
    (_SSH_ACCEPTED_RE, "accepted_login"),
    (_SSH_INVALID_USER_RE, "invalid_user"),
    (_SUDO_FAIL_RE, "sudo_failure"),
    (_SUDO_SUCCESS_RE, "sudo_success"),
)


def _parse_syslog_timestamp(ts: str, year: int, tz: tzinfo) -> datetime:
    """Syslog timestamps have no year or zone: splice in ``year`` and attach ``tz``.

    Raises ValueError for an impossible date (e.g. ``Feb 29`` in a non-leap year).
    A local time that is ambiguous or does not exist because of a DST change resolves
    with ``fold=0`` (the first occurrence), which is how zoneinfo treats it.
    """
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)


def parse_auth_log(
    lines: Iterable[str], year: int | None = None, tz: tzinfo = timezone.utc
) -> ParseResult:
    """Parse auth.log lines. ``year`` defaults to the current year in ``tz``."""
    if year is None:
        year = datetime.now(tz).year
    result = ParseResult(log_type="auth")
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        for regex, event_type in _AUTH_RULES:
            match = regex.match(line)
            if match:
                break
        else:
            continue  # not an entry this tool looks at
        try:
            timestamp = _parse_syslog_timestamp(match["ts"], year, tz)
        except ValueError:
            result.skipped_lines += 1
            continue
        groups = match.groupdict()
        extra = {key: groups[key] for key in ("reason", "command") if key in groups}
        result.events.append(
            LogEvent(
                timestamp=timestamp,
                source="auth",
                event_type=event_type,
                source_ip=groups.get("ip"),
                username=groups["user"],
                raw_line=line,
                extra=extra,
            )
        )
    return result


# --------------------------------------------------------------------------
# Apache / Nginx combined access log parsing
# --------------------------------------------------------------------------

# 203.0.113.7 - - [10/Aug/2026:09:15:32 +0000] "GET /admin/login.php HTTP/1.1" 404 1234 "-" "Mozilla/5.0"
_ACCESS_LOG_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)


def parse_apache_log(lines: Iterable[str], tz: tzinfo = timezone.utc) -> ParseResult:
    """Parse combined-format lines. Each timestamp's own offset is honored, then the
    timestamp is converted to ``tz``."""
    result = ParseResult(log_type="apache")
    for raw in lines:
        line = raw.rstrip("\r\n")
        match = _ACCESS_LOG_RE.match(line)
        if not match:
            continue
        try:
            timestamp = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(tz)
        except ValueError:
            result.skipped_lines += 1
            continue
        result.events.append(
            LogEvent(
                timestamp=timestamp,
                source="apache",
                event_type="http_request",
                source_ip=match["ip"],
                method=match["method"],
                path=match["path"],
                status_code=int(match["status"]),
                raw_line=line,
            )
        )
    return result


# --------------------------------------------------------------------------
# Format auto-detection + top-level entry point
# --------------------------------------------------------------------------


def detect_log_type(lines: Sequence[str], sample_size: int = DETECTION_SAMPLE_LINES) -> str:
    """Guess whether a log file is auth.log-style or an access log."""
    sample = lines[:sample_size]
    auth_hits = sum(1 for line in sample if " sshd[" in line or " sudo:" in line)
    apache_hits = sum(1 for line in sample if _ACCESS_LOG_RE.match(line.rstrip("\r\n")))
    if apache_hits >= auth_hits and apache_hits > 0:
        return "apache"
    if auth_hits > 0:
        return "auth"
    return "unknown"


class FileTooLargeError(ValueError):
    """The input file is larger than the configured limit."""

    def __init__(self, path: str, size: int, max_bytes: int) -> None:
        super().__init__(
            f"{path} is {size / _MB:.1f} MB, over the {max_bytes / _MB:g} MB limit"
        )
        self.path = path
        self.size = size
        self.max_bytes = max_bytes


def check_input_file(path: str, max_bytes: int) -> None:
    """Fail early, with a clear message, on a missing, non-regular or oversized file."""
    info = os.stat(path)  # FileNotFoundError / PermissionError propagate as OSError
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{path} is not a regular file")
    if info.st_size > max_bytes:
        raise FileTooLargeError(path, info.st_size, max_bytes)


def iter_text_lines(handle: Iterable[str]) -> Iterator[str]:
    """Yield lines, dropping a UTF-8 byte-order mark at the very start of the file."""
    iterator = iter(handle)
    first = next(iterator, None)
    if first is None:
        return
    yield first[1:] if first.startswith(_BOM) else first
    yield from iterator


def parse_log_file(
    path: str,
    log_type: str = "auto",
    year: int | None = None,
    tz: tzinfo = timezone.utc,
    max_bytes: int = DEFAULT_MAX_FILE_MB * _MB,
) -> ParseResult:
    """Parse one log file, streaming it line by line.

    Raises OSError if the file cannot be read, FileTooLargeError if it is over
    ``max_bytes``, and ValueError if it is not a regular file or its format cannot be
    determined.
    """
    check_input_file(path, max_bytes)
    with open(path, encoding="utf-8", errors="replace") as handle:
        lines = iter_text_lines(handle)
        head = list(itertools.islice(lines, DETECTION_SAMPLE_LINES))
        if log_type == "auto":
            log_type = detect_log_type(head)
        stream = itertools.chain(head, lines)
        if log_type == "auth":
            return parse_auth_log(stream, year=year, tz=tz)
        if log_type == "apache":
            return parse_apache_log(stream, tz=tz)

    raise ValueError(
        f"Could not determine log format for {path!r}. "
        "Pass --type auth or --type apache explicitly."
    )
