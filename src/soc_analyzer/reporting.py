"""Turns Alert objects into human-readable console output or JSON.

Everything printed here that came from a log line is passed through
``escape_for_terminal`` first (see sanitize.py): usernames, source IPs, detail values
such as request paths, and anything read back from a SQLite database, which may have
been written by an older version or edited by hand.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from . import __version__
from .models import Alert, ParseResult, Severity
from .sanitize import escape_for_terminal

_COLOR = {
    Severity.CRITICAL: "\033[1;41m",  # bold, red background
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[1;33m",  # bold yellow
    Severity.LOW: "\033[1;36m",  # bold cyan
}
_RESET = "\033[0m"

_LABELS = {
    "brute_force": "Possible Brute Force",
    "possible_compromised_credential": "Possible Compromised Credential",
    "privilege_escalation_attempt": "Privilege Escalation Attempt",
    "web_scanning": "Web Scanning / Enumeration",
    "suspicious_request": "Suspicious Request",
    "recon_to_intrusion": "Recon-to-Intrusion (Cross-Source Correlation)",
}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _use_color(no_color: bool) -> bool:
    return not no_color and sys.stdout.isatty()


def _severity_display(severity: str, color: bool) -> str:
    """Color a known severity; escape anything else (e.g. a tampered database value)."""
    try:
        known = Severity(severity)
    except ValueError:
        return escape_for_terminal(severity)
    return f"{_COLOR[known]}{known.value}{_RESET}" if color else known.value


def _render(
    *,
    alert_type: str,
    source_ip: str | None,
    username: str | None,
    details: Mapping[str, Any],
    timestamp: str,
    severity: str,
    color: bool,
) -> str:
    """Render one alert block. Every value is escaped; only the severity color is ANSI."""
    esc = escape_for_terminal
    label = _LABELS.get(alert_type, alert_type)
    lines = ["[!] SECURITY ALERT", ""]
    if source_ip:
        lines.append(f"Source IP: {esc(source_ip)}")
    if username:
        lines.append(f"User: {esc(username)}")
    lines.append(f"Event: {esc(label)}")
    for key, value in details.items():
        pretty_key = str(key).replace("_", " ").title()
        lines.append(f"{esc(pretty_key)}: {esc(value)}")
    lines.append(f"Time: {esc(timestamp)}")
    lines.append(f"Severity: {_severity_display(severity, color)}")
    return "\n".join(lines)


def format_alert(alert: Alert, color: bool = True) -> str:
    return _render(
        alert_type=alert.alert_type,
        source_ip=alert.source_ip,
        username=alert.username,
        details=alert.details,
        timestamp=alert.timestamp.isoformat(sep=" "),
        severity=alert.severity.value,
        color=color,
    )


def format_summary(severities: Iterable[str]) -> str:
    counts = Counter(severities)
    total = sum(counts.values())
    known = [f"{sev}: {counts[sev]}" for sev in _SEVERITY_ORDER if counts[sev]]
    unknown = [
        f"{escape_for_terminal(sev)}: {n}"
        for sev, n in counts.items()
        if sev not in _SEVERITY_ORDER
    ]
    return f"\nSummary: {total} alert(s) — " + ", ".join(known + unknown)


def print_alerts(alerts: Sequence[Alert], no_color: bool = False) -> None:
    color = _use_color(no_color)
    if not alerts:
        print("[+] No alerts triggered — nothing suspicious found.")
        return

    for alert in alerts:
        print(format_alert(alert, color=color))
        print("-" * 40)

    print_summary(alerts)


def print_summary(alerts: Sequence[Alert]) -> None:
    print(format_summary(a.severity.value for a in alerts))


# --------------------------------------------------------------------------
# JSON output contract (docs/OUTPUT_SCHEMA.md)
# --------------------------------------------------------------------------

# MAJOR.MINOR: a minor bump only adds fields; a major bump removes, renames or changes
# the meaning of a field. Consumers should check the major version.
SCHEMA_VERSION = "1.0"


def _by_severity(severities: Iterable[str]) -> dict[str, int]:
    """Counts for every known severity, highest first, zeros included."""
    counts = Counter(severities)
    return {sev: counts[sev] for sev in _SEVERITY_ORDER}


def analysis_document(
    *,
    sources: Sequence[tuple[str, ParseResult]],
    alerts: Sequence[Alert],
    suppressed_alerts: int,
    timezone_name: str,
) -> dict[str, Any]:
    """The ``kind: "analysis"`` document printed by ``--json``."""
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "kind": "analysis",
        "timezone": timezone_name,
        "sources": [
            {
                "path": path,
                "log_type": result.log_type,
                "events": len(result.events),
                "skipped_lines": result.skipped_lines,
            }
            for path, result in sources
        ],
        "summary": {
            "events": sum(len(result.events) for _, result in sources),
            "skipped_lines": sum(result.skipped_lines for _, result in sources),
            "alerts": len(alerts),
            "suppressed_alerts": suppressed_alerts,
            "by_severity": _by_severity(a.severity.value for a in alerts),
        },
        "alerts": [a.to_dict() for a in alerts],
    }


def stored_alerts_document(rows: Sequence[sqlite3.Row]) -> dict[str, Any]:
    """The ``kind: "stored_alerts"`` document printed by ``--show-alerts --json``."""
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "kind": "stored_alerts",
        "summary": {
            "alerts": len(rows),
            "by_severity": _by_severity(str(row["severity"]) for row in rows),
        },
        "alerts": [
            {
                "id": row["id"],
                "alert_type": row["alert_type"],
                "severity": row["severity"],
                "description": row["description"],
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "username": row["username"],
                "details": dict(_stored_details(row["details"])),
            }
            for row in rows
        ],
    }


def to_json(document: Mapping[str, Any]) -> str:
    """Serialize a document. ``ensure_ascii`` is part of the contract: every control and
    non-ASCII character in log-derived text is written as a ``\\uXXXX`` escape, so the
    raw output is always safe to view in a terminal."""
    return json.dumps(document, indent=2, ensure_ascii=True)


def _stored_details(raw: object) -> Mapping[str, Any]:
    """Decode the stored details JSON; show undecodable content as a single raw field."""
    if not raw:
        return {}
    try:
        decoded = json.loads(str(raw))
    except ValueError:
        return {"details": raw}
    return decoded if isinstance(decoded, dict) else {"details": decoded}


def print_stored_alerts(rows: Sequence[sqlite3.Row], no_color: bool = False) -> None:
    """Print alerts read back from SQLite (sqlite3.Row objects from query_alerts)."""
    color = _use_color(no_color)
    if not rows:
        print("[+] No stored alerts match.")
        return

    for row in rows:
        print(
            _render(
                alert_type=str(row["alert_type"]),
                source_ip=row["source_ip"],
                username=row["username"],
                details=_stored_details(row["details"]),
                timestamp=str(row["timestamp"]),
                severity=str(row["severity"]),
                color=color,
            )
        )
        print("-" * 40)

    print(format_summary(str(row["severity"]) for row in rows))
