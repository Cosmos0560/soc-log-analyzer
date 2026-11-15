from datetime import datetime

import pytest

from soc_analyzer.allowlist import AllowList, build_allowlist, load_allowlist_file
from soc_analyzer.models import Alert, Severity

BASE = datetime(2026, 8, 10, 9, 0, 0)


def _alert(source_ip=None, username=None):
    return Alert(
        alert_type="brute_force", severity=Severity.HIGH,
        description="test", timestamp=BASE, source_ip=source_ip, username=username,
    )


# --------------------------------------------------------------------------
# AllowList.filter_alerts
# --------------------------------------------------------------------------

def test_filter_alerts_suppresses_matching_ip():
    allowlist = AllowList(ips={"203.0.113.4"})
    kept, suppressed = allowlist.filter_alerts([_alert(source_ip="203.0.113.4")])
    assert kept == []
    assert len(suppressed) == 1


def test_filter_alerts_suppresses_matching_user():
    allowlist = AllowList(usernames={"webapp"})
    kept, suppressed = allowlist.filter_alerts([_alert(username="webapp")])
    assert kept == []
    assert len(suppressed) == 1


def test_filter_alerts_keeps_non_matching_alerts():
    allowlist = AllowList(ips={"203.0.113.4"})
    alert = _alert(source_ip="198.51.100.9")
    kept, suppressed = allowlist.filter_alerts([alert])
    assert kept == [alert]
    assert suppressed == []


def test_filter_alerts_ip_match_suppresses_regardless_of_user():
    # Allow-listing an IP should cover ANY account touching it (e.g. a scanner box).
    allowlist = AllowList(ips={"203.0.113.4"})
    kept, suppressed = allowlist.filter_alerts([_alert(source_ip="203.0.113.4", username="root")])
    assert kept == []
    assert len(suppressed) == 1


def test_empty_allowlist_is_falsy_and_suppresses_nothing():
    allowlist = AllowList()
    assert not allowlist
    alert = _alert(source_ip="203.0.113.4")
    kept, suppressed = allowlist.filter_alerts([alert])
    assert kept == [alert]
    assert suppressed == []


def test_nonempty_allowlist_is_truthy():
    assert AllowList(ips={"203.0.113.4"})
    assert AllowList(usernames={"bob"})


# --------------------------------------------------------------------------
# load_allowlist_file
# --------------------------------------------------------------------------

def test_load_allowlist_file_parses_ips_and_users(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("ip:203.0.113.4\nuser:webapp\n")
    allowlist = load_allowlist_file(str(f))
    assert allowlist.ips == {"203.0.113.4"}
    assert allowlist.usernames == {"webapp"}


def test_load_allowlist_file_ignores_comments_and_blank_lines(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# a comment\n\nip:203.0.113.4\n   \n# another\nuser:bob\n")
    allowlist = load_allowlist_file(str(f))
    assert allowlist.ips == {"203.0.113.4"}
    assert allowlist.usernames == {"bob"}


def test_load_allowlist_file_rejects_unknown_entry_type(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("host:203.0.113.4\n")
    with pytest.raises(ValueError):
        load_allowlist_file(str(f))


def test_load_allowlist_file_rejects_malformed_line(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("not-a-valid-line\n")
    with pytest.raises(ValueError):
        load_allowlist_file(str(f))


def test_load_allowlist_file_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_allowlist_file("/nonexistent/path/allow.txt")


# --------------------------------------------------------------------------
# build_allowlist (CLI flags + file, combined)
# --------------------------------------------------------------------------

def test_build_allowlist_combines_cli_and_file(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("ip:203.0.113.4\n")
    allowlist = build_allowlist(cli_ips=["198.51.100.9"], cli_users=["bob"], file_path=str(f))
    assert allowlist.ips == {"203.0.113.4", "198.51.100.9"}
    assert allowlist.usernames == {"bob"}


def test_build_allowlist_with_no_inputs_is_empty():
    allowlist = build_allowlist()
    assert not allowlist
