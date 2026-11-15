"""Rule-based detection engine.

Each ``detect_*`` function takes the full list of parsed events plus some
tunable thresholds, and returns a list of Alert objects. Detection logic is
deliberately simple and explainable — every rule here is the kind of thing
a SOC analyst could describe in one sentence, which is the point: this is a
teaching/portfolio tool, not a replacement for a real SIEM's correlation
engine. See docs/DETECTION_RULES.md for the reasoning behind each threshold.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote, urlsplit

from .models import Alert, LogEvent, Severity

# --------------------------------------------------------------------------
# Suspicious-path pattern lists, split by matching strategy.
#
# Substring matching alone is fragile ("/admin" would also match
# "/administrator" or "/my-admin-panel"), so each category below is matched
# with logic appropriate to what it actually is:
#
#   * SENSITIVE_FILE_SUFFIXES — exact files. Matched as a full trailing path
#     segment (path == "/x" or path.endswith("/x")), never a raw substring.
#   * SENSITIVE_PATH_PREFIXES — directory-style paths. Matched as the request
#     path starting with the prefix, followed by "/" or end-of-string, so
#     "/admin" matches "/admin/panel" but NOT "/administrator".
#   * INJECTION_PATTERNS — payload signatures. These legitimately can appear
#     anywhere inside a path or query string, so substring matching is
#     correct here (matched against the URL-decoded, lowercased full path).
# --------------------------------------------------------------------------

SENSITIVE_FILE_SUFFIXES = [
    ".env",
    ".git/config",
    ".aws/credentials",
    ".ssh/id_rsa",
    "config.php",
    "wp-login.php",
]

SENSITIVE_PATH_PREFIXES = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
]

INJECTION_PATTERNS = [
    "union select",
    "select * from",
    "<script",
    "' or '1'='1",
    "' or 1=1",
    "../",
]


def _match_sensitive_file(path: str) -> str | None:
    for suffix in SENSITIVE_FILE_SUFFIXES:
        if path == "/" + suffix or path.endswith("/" + suffix):
            return suffix
    return None


def _match_path_prefix(path: str) -> str | None:
    for prefix in SENSITIVE_PATH_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return prefix
    return None


def detect_brute_force(
    events: list[LogEvent], threshold: int = 5, window_minutes: int = 5
) -> list[Alert]:
    """Flag an IP that racks up >= threshold failed logins inside a sliding window."""
    window = timedelta(minutes=window_minutes)
    failed = [e for e in events if e.event_type in ("failed_login", "invalid_user")]
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in failed:
        if e.source_ip is not None:
            by_ip[e.source_ip].append(e)

    alerts: list[Alert] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                usernames = sorted({e.username for e in evs[start : end + 1] if e.username})
                alerts.append(
                    Alert(
                        alert_type="brute_force",
                        severity=Severity.HIGH,
                        description="Possible brute-force login attempt",
                        timestamp=evs[end].timestamp,
                        source_ip=ip,
                        details={
                            "failed_attempts": count,
                            "window_minutes": window_minutes,
                            "usernames_tried": usernames[:10],
                        },
                    )
                )
                break  # one alert per IP is enough; avoid duplicate spam
    return alerts


def detect_compromised_credential(
    events: list[LogEvent], window_minutes: int = 5, precede_threshold: int = 3
) -> list[Alert]:
    """Flag a successful login that immediately follows a burst of failures
    from the SAME IP — a strong signal the brute force eventually worked.

    Uses a true sliding window: failures older than ``window_minutes``
    relative to the success are dropped before the threshold check, so a
    stale failure from hours earlier can't combine with a single recent
    failure to falsely reach the threshold.
    """
    window = timedelta(minutes=window_minutes)
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if (
            e.event_type in ("failed_login", "invalid_user", "accepted_login")
            and e.source_ip is not None
        ):
            by_ip[e.source_ip].append(e)

    alerts: list[Alert] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        recent_failures: deque[datetime] = deque()  # failures not yet expired
        for e in evs:
            if e.event_type in ("failed_login", "invalid_user"):
                recent_failures.append(e.timestamp)
            elif e.event_type == "accepted_login":
                while recent_failures and e.timestamp - recent_failures[0] > window:
                    recent_failures.popleft()
                if len(recent_failures) >= precede_threshold:
                    alerts.append(
                        Alert(
                            alert_type="possible_compromised_credential",
                            severity=Severity.CRITICAL,
                            description=(
                                "Successful login immediately followed a burst of "
                                "failed attempts from the same IP"
                            ),
                            timestamp=e.timestamp,
                            source_ip=ip,
                            username=e.username,
                            details={
                                "preceding_failures": len(recent_failures),
                                "window_minutes": window_minutes,
                            },
                        )
                    )
                recent_failures.clear()  # a login (success) closes out this burst
    return alerts


def detect_privilege_escalation(
    events: list[LogEvent], threshold: int = 3, window_minutes: int = 5
) -> list[Alert]:
    """Flag a user who racks up >= threshold failed sudo attempts inside a
    sliding window — mirrors detect_brute_force's windowing so a handful of
    unrelated failures spread over weeks doesn't falsely trigger this."""
    window = timedelta(minutes=window_minutes)
    fails = [e for e in events if e.event_type == "sudo_failure"]
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e in fails:
        if e.username is not None:
            by_user[e.username].append(e)

    alerts = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                alerts.append(
                    Alert(
                        alert_type="privilege_escalation_attempt",
                        severity=Severity.MEDIUM,
                        description="Repeated failed sudo/privilege escalation attempts",
                        timestamp=evs[end].timestamp,
                        username=user,
                        details={"failed_attempts": count, "window_minutes": window_minutes},
                    )
                )
                break
    return alerts


def detect_web_scanning(
    events: list[LogEvent], threshold: int = 10, window_minutes: int = 2
) -> list[Alert]:
    """Flag an IP generating a burst of 404s — typical of directory/content scanning."""
    window = timedelta(minutes=window_minutes)
    not_found = [e for e in events if e.event_type == "http_request" and e.status_code == 404]
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in not_found:
        if e.source_ip is not None:
            by_ip[e.source_ip].append(e)

    alerts = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                alerts.append(
                    Alert(
                        alert_type="web_scanning",
                        severity=Severity.MEDIUM,
                        description="Burst of 404 responses suggests directory/content scanning",
                        timestamp=evs[end].timestamp,
                        source_ip=ip,
                        details={"requests_404": count, "window_minutes": window_minutes},
                    )
                )
                break
    return alerts


def detect_suspicious_paths(events: list[LogEvent]) -> list[Alert]:
    """Flag requests to known-sensitive paths or containing injection-style payloads.

    NOTE: this is pattern/signature matching against the request path, not a
    real SQL-injection or XSS detection engine — it will catch obvious,
    unencoded-once probes and miss anything more sophisticated. See
    docs/DETECTION_RULES.md for the honest scope of this rule.
    """
    alerts = []
    for e in events:
        if e.event_type != "http_request" or not e.path:
            continue

        parsed = urlsplit(e.path)
        path_only = unquote(parsed.path).lower()
        # Injection payloads can hide in the query string too, and use "+" as an
        # encoded space, so this check normalizes the whole path+query for that
        # search only — path/prefix matching above stays scoped to the real path.
        full_decoded = unquote(e.path).replace("+", " ").lower()

        match = _match_sensitive_file(path_only) or _match_path_prefix(path_only)
        if not match:
            for pattern in INJECTION_PATTERNS:
                if pattern in full_decoded:
                    match = pattern
                    break

        if match:
            alerts.append(
                Alert(
                    alert_type="suspicious_request",
                    severity=Severity.HIGH,
                    description=f"Request matched suspicious pattern: {match}",
                    timestamp=e.timestamp,
                    source_ip=e.source_ip,
                    details={"path": e.path, "method": e.method, "status": e.status_code},
                )
            )
    return alerts


def detect_recon_to_intrusion(
    events: list[LogEvent],
    correlation_window_minutes: int = 60,
    scan_threshold: int = 10,
    scan_window: int = 2,
) -> list[Alert]:
    """Flag an IP whose web recon (scanning or a suspicious request) is
    followed by SSH authentication activity from the SAME IP within a
    window — the signature of an actor who scanned first, then pivoted to
    a direct attack, rather than two unrelated events. This only fires
    when events from BOTH a web log and an auth log are present in the
    same run (pass --file more than once).

    Deliberately reuses detect_web_scanning / detect_suspicious_paths
    rather than re-implementing "what counts as recon" — this rule is a
    second layer on top of those, not a competing definition of recon.

    Only the EARLIEST recon alert per IP is used as the reference point
    ("first sign of this actor casing the target"), and only the FIRST
    qualifying auth event after it fires the alert — one correlation
    alert per IP, not one per event pair, to avoid duplicate spam for a
    single multi-stage incident.
    """
    window = timedelta(minutes=correlation_window_minutes)

    recon_alerts = detect_web_scanning(
        events, scan_threshold, scan_window
    ) + detect_suspicious_paths(events)
    first_recon_by_ip: dict[str, Alert] = {}
    for a in recon_alerts:
        if not a.source_ip:
            continue
        if (
            a.source_ip not in first_recon_by_ip
            or a.timestamp < first_recon_by_ip[a.source_ip].timestamp
        ):
            first_recon_by_ip[a.source_ip] = a

    if not first_recon_by_ip:
        return []

    auth_events = [
        e
        for e in events
        if e.event_type in ("failed_login", "invalid_user", "accepted_login") and e.source_ip
    ]
    auth_events.sort(key=lambda e: e.timestamp)

    alerts: list[Alert] = []
    already_flagged: set[str] = set()
    for e in auth_events:
        ip = e.source_ip
        if ip not in first_recon_by_ip or ip in already_flagged:
            continue
        recon_alert = first_recon_by_ip[ip]
        delta = e.timestamp - recon_alert.timestamp
        if delta.total_seconds() < 0 or delta > window:
            continue  # auth activity before recon, or outside the window, isn't this pattern
        alerts.append(
            Alert(
                alert_type="recon_to_intrusion",
                severity=Severity.CRITICAL,
                description=(
                    "Web reconnaissance from this IP was followed by SSH "
                    "authentication activity within the correlation window — "
                    "likely the same actor moving from scanning to a direct attack"
                ),
                timestamp=e.timestamp,
                source_ip=ip,
                username=e.username,
                details={
                    "recon_alert_type": recon_alert.alert_type,
                    "recon_first_seen": recon_alert.timestamp.isoformat(),
                    "auth_activity_type": e.event_type,
                    "minutes_between": round(delta.total_seconds() / 60, 1),
                    "correlation_window_minutes": correlation_window_minutes,
                },
            )
        )
        already_flagged.add(ip)
    return alerts


def run_all_detectors(
    events: list[LogEvent],
    brute_force_threshold: int = 5,
    brute_force_window: int = 5,
    privesc_threshold: int = 3,
    privesc_window: int = 5,
    scan_threshold: int = 10,
    scan_window: int = 2,
    correlation_window: int = 60,
) -> list[Alert]:
    """Run every applicable detector and return alerts sorted by severity (highest first)."""
    alerts: list[Alert] = []
    alerts += detect_brute_force(events, brute_force_threshold, brute_force_window)
    alerts += detect_compromised_credential(events, brute_force_window)
    alerts += detect_privilege_escalation(events, privesc_threshold, privesc_window)
    alerts += detect_web_scanning(events, scan_threshold, scan_window)
    alerts += detect_suspicious_paths(events)
    alerts += detect_recon_to_intrusion(events, correlation_window, scan_threshold, scan_window)
    alerts.sort(key=lambda a: (a.severity.rank, a.timestamp), reverse=True)
    return alerts
