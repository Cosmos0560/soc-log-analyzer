from soc_analyzer.parsers import (
    detect_log_type,
    parse_apache_log,
    parse_auth_log,
)


def test_parse_failed_login():
    line = "Aug 10 09:15:32 host sshd[123]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2"
    events = parse_auth_log([line], year=2026).events
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "failed_login"
    assert e.source_ip == "203.0.113.7"
    assert e.username == "admin"
    assert e.timestamp.month == 8 and e.timestamp.day == 10


def test_parse_accepted_login():
    line = "Aug 10 09:15:40 host sshd[123]: Accepted password for root from 203.0.113.7 port 51244 ssh2"
    events = parse_auth_log([line], year=2026).events
    assert events[0].event_type == "accepted_login"
    assert events[0].username == "root"


def test_parse_sudo_failure():
    line = "Aug 10 09:20:11 host sudo:   bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
    events = parse_auth_log([line], year=2026).events
    assert events[0].event_type == "sudo_failure"
    assert events[0].username == "bob"


def test_parse_auth_log_skips_unmatched_lines():
    lines = ["this is not a real log line", "", "   "]
    assert parse_auth_log(lines).events == []


def test_parse_apache_access_log():
    line = '203.0.113.7 - - [10/Aug/2026:09:15:32 +0000] "GET /admin/login.php HTTP/1.1" 404 1234 "-" "Mozilla/5.0"'
    events = parse_apache_log([line]).events
    assert len(events) == 1
    e = events[0]
    assert e.source_ip == "203.0.113.7"
    assert e.method == "GET"
    assert e.path == "/admin/login.php"
    assert e.status_code == 404


def test_detect_log_type_auth():
    lines = ["Aug 10 09:15:32 host sshd[123]: Failed password for root from 203.0.113.4 port 22 ssh2"]
    assert detect_log_type(lines) == "auth"


def test_detect_log_type_apache():
    lines = ['203.0.113.4 - - [10/Aug/2026:09:15:32 +0000] "GET / HTTP/1.1" 200 100 "-" "curl"']
    assert detect_log_type(lines) == "apache"


def test_detect_log_type_unknown():
    assert detect_log_type(["nothing recognizable here"]) == "unknown"


def test_parse_auth_log_empty_input():
    assert parse_auth_log([]).events == []


def test_parse_apache_log_empty_input():
    assert parse_apache_log([]).events == []


def test_parse_apache_log_skips_malformed_lines():
    lines = [
        "this is not an access log line at all",
        '203.0.113.7 - - [10/Aug/2026:09:15:32 +0000] "GET /ok HTTP/1.1" 200 100 "-" "curl"',
        "",
    ]
    events = parse_apache_log(lines).events
    assert len(events) == 1
    assert events[0].path == "/ok"


def test_parse_auth_log_handles_ipv6_source():
    line = ("Aug 10 09:15:32 host sshd[123]: Failed password for invalid user admin "
            "from 2001:db8::1 port 51234 ssh2")
    events = parse_auth_log([line], year=2026).events
    assert events[0].source_ip == "2001:db8::1"
