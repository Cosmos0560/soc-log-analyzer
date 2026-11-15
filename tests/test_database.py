import json
from datetime import datetime, timedelta, timezone

import pytest

from soc_analyzer.database import db_timestamp, init_db, query_alerts, store_alerts, store_events
from soc_analyzer.models import Alert, LogEvent, Severity


@pytest.fixture
def conn(tmp_path):
    connection = init_db(str(tmp_path / "test.db"))
    yield connection
    connection.close()


def test_store_events_persists_core_fields(conn):
    events = [LogEvent(
        timestamp=datetime(2026, 8, 10, 9, 0, 0), source="auth",
        event_type="sudo_failure", username="bob", source_ip="203.0.113.4",
        extra={"reason": "user NOT in sudoers"},
    )]
    store_events(conn, events)

    row = conn.execute(
        "SELECT event_type, username, source_ip FROM events"
    ).fetchone()
    assert row == ("sudo_failure", "bob", "203.0.113.4")


def test_extra_field_is_persisted_not_lost(conn):
    conn.row_factory = None
    events = [LogEvent(
        timestamp=datetime(2026, 8, 10, 9, 0, 0), source="auth",
        event_type="sudo_success", username="root",
        extra={"command": "/usr/bin/systemctl restart nginx"},
    )]
    store_events(conn, events)

    cur = conn.execute("SELECT extra FROM events")
    (extra_json,) = cur.fetchone()
    assert extra_json is not None
    assert json.loads(extra_json) == {"command": "/usr/bin/systemctl restart nginx"}


def test_extra_field_is_null_when_empty(conn):
    events = [LogEvent(timestamp=datetime(2026, 8, 10, 9, 0, 0), source="auth",
                        event_type="accepted_login", username="deploy")]
    store_events(conn, events)
    cur = conn.execute("SELECT extra FROM events")
    (extra_json,) = cur.fetchone()
    assert extra_json is None


def test_query_alerts_filters_by_severity(conn):
    alerts = [
        Alert(alert_type="brute_force", severity=Severity.HIGH,
              description="x", timestamp=datetime(2026, 8, 10, 9, 0, 0), source_ip="203.0.113.4"),
        Alert(alert_type="privilege_escalation_attempt", severity=Severity.MEDIUM,
              description="y", timestamp=datetime(2026, 8, 10, 9, 5, 0), username="bob"),
    ]
    store_alerts(conn, alerts)

    high_only = query_alerts(conn, severity="HIGH")
    assert len(high_only) == 1
    assert high_only[0]["alert_type"] == "brute_force"

    all_alerts = query_alerts(conn)
    assert len(all_alerts) == 2


def test_aware_timestamps_are_stored_in_utc(conn):
    plus_0530 = timezone(timedelta(hours=5, minutes=30))
    ts = datetime(2026, 8, 10, 9, 0, 0, tzinfo=plus_0530)
    store_alerts(conn, [Alert(alert_type="brute_force", severity=Severity.HIGH,
                              description="x", timestamp=ts)])
    (stored,) = conn.execute("SELECT timestamp FROM alerts").fetchone()
    assert stored == "2026-08-10T03:30:00+00:00"


def test_naive_timestamps_are_stored_unchanged():
    assert db_timestamp(datetime(2026, 8, 10, 9, 0, 0)) == "2026-08-10T09:00:00"
