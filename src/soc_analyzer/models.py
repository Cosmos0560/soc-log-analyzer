"""Core data models shared across the analyzer.

Keeping these in one module (rather than inside parsers.py / detectors.py)
avoids circular imports between the modules that produce events (parsers)
and the modules that consume them (detectors, database, reporting).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


@dataclass
class LogEvent:
    """A single normalized log line, regardless of source format."""

    timestamp: datetime
    source: str  # e.g. "auth", "apache"
    event_type: str  # e.g. "failed_login", "accepted_login", "http_request"
    source_ip: str | None = None
    username: str | None = None
    status_code: int | None = None
    path: str | None = None
    method: str | None = None
    raw_line: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """A detection engine finding, ready for display or storage."""

    alert_type: str
    severity: Severity
    description: str
    timestamp: datetime
    source_ip: str | None = None
    username: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "details": self.details,
        }


@dataclass
class ParseResult:
    """What a parser produced from one log source.

    ``skipped_lines`` counts lines that matched a known log format but could not be
    turned into an event (for example an impossible date such as Feb 29 in a non-leap
    year). Lines that match no known format at all are ignored and not counted: real
    auth logs contain plenty of unrelated entries (cron, PAM sessions) by design.
    """

    log_type: str
    events: list[LogEvent] = field(default_factory=list)
    skipped_lines: int = 0
