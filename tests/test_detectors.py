from datetime import datetime, timedelta

from soc_analyzer.detectors import (
    detect_brute_force,
    detect_compromised_credential,
    detect_privilege_escalation,
    detect_recon_to_intrusion,
    detect_suspicious_paths,
    detect_web_scanning,
)
from soc_analyzer.models import LogEvent

BASE = datetime(2026, 8, 10, 9, 0, 0)


def _login_event(ip, event_type="failed_login", user="root", minutes=0.0, seconds=0):
    return LogEvent(
        timestamp=BASE + timedelta(minutes=minutes, seconds=seconds),
        source="auth",
        event_type=event_type,
        source_ip=ip,
        username=user,
    )


# --------------------------------------------------------------------------
# Brute force
# --------------------------------------------------------------------------


def test_brute_force_triggers_at_threshold():
    events = [_login_event("203.0.113.4", seconds=i * 6) for i in range(5)]
    alerts = detect_brute_force(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.4"
    assert alerts[0].details["failed_attempts"] == 5


def test_brute_force_does_not_trigger_below_threshold():
    events = [_login_event("203.0.113.4", minutes=i) for i in range(3)]
    assert detect_brute_force(events, threshold=5, window_minutes=5) == []


def test_brute_force_ignores_events_outside_window():
    events = [_login_event("203.0.113.4", minutes=i * 30) for i in range(5)]
    assert detect_brute_force(events, threshold=5, window_minutes=5) == []


def test_brute_force_boundary_exactly_at_window_counts():
    # 5 minute window; first and last event exactly 5 minutes apart should count
    events = [
        _login_event("203.0.113.4", minutes=0),
        _login_event("203.0.113.4", minutes=1),
        _login_event("203.0.113.4", minutes=2),
        _login_event("203.0.113.4", minutes=3),
        _login_event("203.0.113.4", minutes=5),
    ]
    alerts = detect_brute_force(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1


def test_brute_force_boundary_just_outside_window_excludes_oldest():
    # last event 5 min + 1 second after the first -> only 4 of 5 fall in-window
    events = [
        _login_event("203.0.113.4", minutes=0),
        _login_event("203.0.113.4", minutes=1),
        _login_event("203.0.113.4", minutes=2),
        _login_event("203.0.113.4", minutes=3),
        _login_event("203.0.113.4", minutes=5, seconds=1),
    ]
    assert detect_brute_force(events, threshold=5, window_minutes=5) == []


def test_brute_force_tracks_multiple_ips_independently():
    events = (
        [_login_event("203.0.113.4", seconds=i * 6) for i in range(5)]
        + [_login_event("198.51.100.9", minutes=i) for i in range(2)]  # below threshold
    )
    alerts = detect_brute_force(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.4"


# --------------------------------------------------------------------------
# Compromised credential (the sliding-window fix)
# --------------------------------------------------------------------------


def test_compromised_credential_detected_for_genuine_burst():
    events = [_login_event("203.0.113.4", "failed_login", minutes=i) for i in range(4)]
    events.append(_login_event("203.0.113.4", "accepted_login", user="root", minutes=4.1))
    alerts = detect_compromised_credential(events, window_minutes=5, precede_threshold=3)
    assert len(alerts) == 1
    assert alerts[0].severity.value == "CRITICAL"
    assert alerts[0].details["preceding_failures"] == 4


def test_compromised_credential_not_flagged_for_clean_login():
    events = [_login_event("203.0.113.4", "accepted_login", user="deploy")]
    assert detect_compromised_credential(events) == []


def test_compromised_credential_ignores_stale_failures_expired_from_window():
    # 3 failures at t=0,1,2 minutes, then a clean success at t=20 minutes.
    # With a 5-minute window, all 3 failures have expired by the time of
    # the success -> must NOT alert. This is the scenario the sliding
    # window is specifically responsible for getting right.
    events = [_login_event("203.0.113.4", "failed_login", minutes=i) for i in range(3)]
    events.append(_login_event("203.0.113.4", "accepted_login", user="root", minutes=20))
    assert detect_compromised_credential(events, window_minutes=5, precede_threshold=3) == []


def test_compromised_credential_does_not_combine_stale_and_fresh_failures():
    # 2 stale failures ~2 hours before a 3rd, fresh, isolated failure that
    # immediately precedes a success. A naive "count since last success"
    # implementation would report preceding_failures=3 here; a correct
    # sliding window only counts the one failure actually inside the window.
    events = [
        _login_event("203.0.113.4", "failed_login", minutes=0),
        _login_event("203.0.113.4", "failed_login", minutes=1),
        _login_event("203.0.113.4", "failed_login", minutes=125),
        _login_event("203.0.113.4", "accepted_login", user="root", minutes=126),
    ]
    alerts = detect_compromised_credential(events, window_minutes=5, precede_threshold=3)
    assert alerts == []  # only 1 failure was actually within the window -> below threshold


def test_compromised_credential_tracks_multiple_ips_independently():
    events = [_login_event("203.0.113.4", "failed_login", minutes=i) for i in range(3)]
    events.append(_login_event("203.0.113.4", "accepted_login", user="root", minutes=3.1))
    events.append(_login_event("198.51.100.9", "accepted_login", user="deploy", minutes=3.1))
    alerts = detect_compromised_credential(events, window_minutes=5, precede_threshold=3)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.4"


# --------------------------------------------------------------------------
# Privilege escalation (now windowed)
# --------------------------------------------------------------------------


def test_privilege_escalation_triggers_within_window():
    events = [
        LogEvent(BASE + timedelta(minutes=i), "auth", "sudo_failure", username="bob")
        for i in range(3)
    ]
    alerts = detect_privilege_escalation(events, threshold=3, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0].username == "bob"


def test_privilege_escalation_does_not_trigger_spread_over_weeks():
    # 3 sudo failures, but weeks apart -> should NOT be treated as one burst
    events = [
        LogEvent(BASE, "auth", "sudo_failure", username="bob"),
        LogEvent(BASE + timedelta(days=7), "auth", "sudo_failure", username="bob"),
        LogEvent(BASE + timedelta(days=14), "auth", "sudo_failure", username="bob"),
    ]
    assert detect_privilege_escalation(events, threshold=3, window_minutes=5) == []


def test_privilege_escalation_tracks_users_independently():
    events = [
        LogEvent(BASE + timedelta(minutes=i), "auth", "sudo_failure", username="bob")
        for i in range(3)
    ] + [
        LogEvent(BASE + timedelta(minutes=i), "auth", "sudo_failure", username="alice")
        for i in range(2)  # below threshold
    ]
    alerts = detect_privilege_escalation(events, threshold=3, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0].username == "bob"


# --------------------------------------------------------------------------
# Web scanning
# --------------------------------------------------------------------------


def test_web_scanning_detects_404_burst():
    events = [
        LogEvent(
            BASE + timedelta(seconds=i),
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            status_code=404,
            path=f"/x{i}",
        )
        for i in range(10)
    ]
    alerts = detect_web_scanning(events, threshold=10, window_minutes=2)
    assert len(alerts) == 1
    assert alerts[0].details["requests_404"] == 10


# --------------------------------------------------------------------------
# Suspicious paths — including the false-positive fix
# --------------------------------------------------------------------------


def test_suspicious_path_matches_sensitive_file():
    events = [
        LogEvent(
            BASE, "apache", "http_request", source_ip="198.51.100.8", path="/.env", status_code=404
        )
    ]
    alerts = detect_suspicious_paths(events)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "suspicious_request"


def test_suspicious_path_matches_nested_sensitive_file():
    events = [
        LogEvent(
            BASE,
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            path="/app/.git/config",
            status_code=404,
        )
    ]
    assert len(detect_suspicious_paths(events)) == 1


def test_suspicious_path_catches_url_encoded_sqli():
    events = [
        LogEvent(
            BASE,
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            path="/search?q=%27+union+select+1--",
            status_code=500,
        )
    ]
    assert len(detect_suspicious_paths(events)) == 1


def test_suspicious_path_ignores_clean_request():
    events = [
        LogEvent(
            BASE, "apache", "http_request", source_ip="198.51.100.8", path="/about", status_code=200
        )
    ]
    assert detect_suspicious_paths(events) == []


def test_suspicious_path_prefix_match_still_flags_admin_login():
    events = [
        LogEvent(
            BASE,
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            path="/admin/login",
            status_code=404,
        )
    ]
    assert len(detect_suspicious_paths(events)) == 1


def test_suspicious_path_does_not_false_positive_on_admin_substring():
    # These paths merely CONTAIN "admin" as a substring but are not actually
    # under the sensitive "/admin" prefix -- must not be flagged.
    events = [
        LogEvent(
            BASE,
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            path="/my-admin-panel",
            status_code=200,
        ),
        LogEvent(
            BASE,
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            path="/administrative-tools",
            status_code=200,
        ),
    ]
    assert detect_suspicious_paths(events) == []


def test_suspicious_path_administrator_still_flagged_on_its_own_merits():
    # /administrator is a known Joomla admin panel path -- it should still be
    # flagged, but via its own explicit prefix entry, not an accidental
    # substring match against "/admin".
    events = [
        LogEvent(
            BASE,
            "apache",
            "http_request",
            source_ip="198.51.100.8",
            path="/administrator",
            status_code=404,
        )
    ]
    assert len(detect_suspicious_paths(events)) == 1


# --------------------------------------------------------------------------
# Cross-source correlation (recon -> intrusion)
# --------------------------------------------------------------------------


def _scan_burst(ip, start_minutes=0):
    """10 404s in under 2 minutes from `ip` -- enough to trip detect_web_scanning."""
    return [
        LogEvent(
            BASE + timedelta(minutes=start_minutes, seconds=i * 6),
            "apache",
            "http_request",
            source_ip=ip,
            status_code=404,
            path=f"/scan{i}",
        )
        for i in range(10)
    ]


def _ssh_failed(ip, start_minutes, user="admin"):
    return LogEvent(
        BASE + timedelta(minutes=start_minutes), "auth", "failed_login", source_ip=ip, username=user
    )


def test_recon_to_intrusion_flags_scan_then_ssh_from_same_ip():
    events = _scan_burst("198.51.100.9") + [_ssh_failed("198.51.100.9", start_minutes=10)]
    alerts = detect_recon_to_intrusion(events, correlation_window_minutes=60)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "198.51.100.9"
    assert alerts[0].severity.value == "CRITICAL"
    assert alerts[0].alert_type == "recon_to_intrusion"


def test_recon_to_intrusion_ignores_different_ips():
    events = _scan_burst("198.51.100.9") + [_ssh_failed("192.0.2.8", start_minutes=10)]
    assert detect_recon_to_intrusion(events) == []


def test_recon_to_intrusion_respects_correlation_window():
    # SSH activity 100 minutes after recon, window is only 60 -> must NOT fire
    events = _scan_burst("198.51.100.9") + [_ssh_failed("198.51.100.9", start_minutes=100)]
    assert detect_recon_to_intrusion(events, correlation_window_minutes=60) == []


def test_recon_to_intrusion_no_recon_means_no_alert():
    # A brute force by itself, with no preceding web recon at all, isn't this pattern.
    events = [_ssh_failed("198.51.100.9", start_minutes=i) for i in range(5)]
    assert detect_recon_to_intrusion(events) == []


def test_recon_to_intrusion_does_not_flag_auth_activity_before_recon():
    # SSH activity happens BEFORE the web recon -- wrong order, must not correlate.
    events = [_ssh_failed("198.51.100.9", start_minutes=0)] + _scan_burst(
        "198.51.100.9", start_minutes=30
    )
    assert detect_recon_to_intrusion(events) == []


def test_recon_to_intrusion_one_alert_per_ip():
    events = _scan_burst("198.51.100.9") + [
        _ssh_failed("198.51.100.9", start_minutes=10),
        _ssh_failed("198.51.100.9", start_minutes=11),
        _ssh_failed("198.51.100.9", start_minutes=12),
    ]
    alerts = detect_recon_to_intrusion(events)
    assert len(alerts) == 1


def test_recon_to_intrusion_fires_from_suspicious_path_alone():
    # A single sensitive-file hit (no 404 burst needed) still counts as recon.
    events = [
        LogEvent(
            BASE, "apache", "http_request", source_ip="198.51.100.9", path="/.env", status_code=404
        ),
        _ssh_failed("198.51.100.9", start_minutes=5),
    ]
    alerts = detect_recon_to_intrusion(events)
    assert len(alerts) == 1
    assert alerts[0].details["recon_alert_type"] == "suspicious_request"


# --------------------------------------------------------------------------
# General robustness
# --------------------------------------------------------------------------


def test_detectors_handle_empty_event_list():
    assert detect_brute_force([]) == []
    assert detect_compromised_credential([]) == []
    assert detect_privilege_escalation([]) == []
    assert detect_web_scanning([]) == []
    assert detect_suspicious_paths([]) == []
    assert detect_recon_to_intrusion([]) == []


def test_brute_force_handles_ipv6_source():
    ip = "2001:db8::1"
    events = [_login_event(ip, seconds=i * 6) for i in range(5)]
    alerts = detect_brute_force(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0].source_ip == ip


def test_events_without_ip_or_user_never_form_an_alert_group():
    no_ip = [
        LogEvent(timestamp=BASE + timedelta(seconds=i), source="auth", event_type=kind)
        for i in range(10)
        for kind in ("failed_login", "accepted_login")
    ]
    no_ip += [
        LogEvent(timestamp=BASE, source="apache", event_type="http_request", status_code=404)
        for _ in range(20)
    ]
    no_user = [
        LogEvent(timestamp=BASE + timedelta(seconds=i), source="auth", event_type="sudo_failure")
        for i in range(5)
    ]
    assert detect_brute_force(no_ip, threshold=3) == []
    assert detect_compromised_credential(no_ip, precede_threshold=1) == []
    assert detect_web_scanning(no_ip, threshold=3) == []
    assert detect_privilege_escalation(no_user, threshold=3) == []
