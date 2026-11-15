"""Core data models shared across the analyzer.

Keeping these in one module (rather than inside parsers.py / detectors.py)
avoids circular imports between the modules that produce events (parsers)
and the modules that consume them (detectors, database, reporting).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
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
    source_ip: Optional[str] = None
    username: Optional[str] = None
    status_code: Optional[int] = None
    path: Optional[str] = None
    method: Optional[str] = None
    raw_line: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """A detection engine finding, ready for display or storage."""

    alert_type: str
    severity: Severity
    description: str
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "details": self.details,
        }
