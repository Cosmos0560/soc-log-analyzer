"""Turns Alert objects into human-readable console output or JSON."""

from __future__ import annotations

import json
import sys
from collections import Counter
from typing import List

from .models import Alert, Severity

_COLOR = {
    Severity.CRITICAL: "\033[1;41m",  # bold, red background
    Severity.HIGH: "\033[1;31m",      # bold red
    Severity.MEDIUM: "\033[1;33m",    # bold yellow
    Severity.LOW: "\033[1;36m",       # bold cyan
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


def _use_color(no_color: bool) -> bool:
    return not no_color and sys.stdout.isatty()


def format_alert(alert: Alert, color: bool = True) -> str:
    label = _LABELS.get(alert.alert_type, alert.alert_type)
    sev = alert.severity.value
    sev_display = f"{_COLOR[alert.severity]}{sev}{_RESET}" if color else sev

    lines = ["[!] SECURITY ALERT", ""]
    if alert.source_ip:
        lines.append(f"Source IP: {alert.source_ip}")
    if alert.username:
        lines.append(f"User: {alert.username}")
    lines.append(f"Event: {label}")
    for key, value in alert.details.items():
        pretty_key = key.replace("_", " ").title()
        lines.append(f"{pretty_key}: {value}")
    lines.append(f"Time: {alert.timestamp.isoformat(sep=' ')}")
    lines.append(f"Severity: {sev_display}")
    return "\n".join(lines)


def print_alerts(alerts: List[Alert], no_color: bool = False) -> None:
    color = _use_color(no_color)
    if not alerts:
        print("[+] No alerts triggered — nothing suspicious found.")
        return

    for alert in alerts:
        print(format_alert(alert, color=color))
        print("-" * 40)

    print_summary(alerts)


def print_summary(alerts: List[Alert]) -> None:
    counts = Counter(a.severity.value for a in alerts)
    print(f"\nSummary: {len(alerts)} alert(s) — "
          + ", ".join(f"{sev}: {counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[sev]))


def alerts_to_json(alerts: List[Alert]) -> str:
    return json.dumps([a.to_dict() for a in alerts], indent=2)


def print_stored_alerts(rows, no_color: bool = False) -> None:
    """Print alerts read back from SQLite (sqlite3.Row objects from query_alerts)."""
    color = _use_color(no_color)
    if not rows:
        print("[+] No stored alerts match.")
        return

    for row in rows:
        details = json.loads(row["details"]) if row["details"] else {}
        sev = row["severity"]
        sev_display = f"{_COLOR[Severity(sev)]}{sev}{_RESET}" if color else sev
        label = _LABELS.get(row["alert_type"], row["alert_type"])

        lines = ["[!] SECURITY ALERT", ""]
        if row["source_ip"]:
            lines.append(f"Source IP: {row['source_ip']}")
        if row["username"]:
            lines.append(f"User: {row['username']}")
        lines.append(f"Event: {label}")
        for key, value in details.items():
            lines.append(f"{key.replace('_', ' ').title()}: {value}")
        lines.append(f"Time: {row['timestamp']}")
        lines.append(f"Severity: {sev_display}")
        print("\n".join(lines))
        print("-" * 40)

    counts = Counter(row["severity"] for row in rows)
    print(f"\nSummary: {len(rows)} alert(s) — "
          + ", ".join(f"{sev}: {counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[sev]))
