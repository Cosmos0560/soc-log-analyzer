import json
from datetime import datetime

from soc_analyzer.database import init_db, query_alerts, store_alerts, store_events
from soc_analyzer.models import Alert, LogEvent, Severity


def test_store_events_persists_core_fields(tmp_path):
    db_path = str(tmp_path / "test.db")
    conn = init_db(db_path)
    events = [LogEvent(
        timestamp=datetime(2026, 8, 10, 9, 0, 0), source="auth",
        event_type="sudo_failure", username="bob", source_ip="1.2.3.4",
        extra={"reason": "user NOT in sudoers"},
    )]
    store_events(conn, events)

    row = conn.execute(
        "SELECT event_type, username, source_ip FROM events"
    ).fetchone()
    assert row == ("sudo_failure", "bob", "1.2.3.4")


def test_extra_field_is_persisted_not_lost(tmp_path):
    db_path = str(tmp_path / "test.db")
    conn = init_db(db_path)
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


def test_extra_field_is_null_when_empty(tmp_path):
    db_path = str(tmp_path / "test.db")
    conn = init_db(db_path)
    events = [LogEvent(timestamp=datetime(2026, 8, 10, 9, 0, 0), source="auth",
                        event_type="accepted_login", username="deploy")]
    store_events(conn, events)
    cur = conn.execute("SELECT extra FROM events")
    (extra_json,) = cur.fetchone()
    assert extra_json is None


def test_query_alerts_filters_by_severity(tmp_path):
    db_path = str(tmp_path / "test.db")
    conn = init_db(db_path)
    alerts = [
        Alert(alert_type="brute_force", severity=Severity.HIGH,
              description="x", timestamp=datetime(2026, 8, 10, 9, 0, 0), source_ip="1.2.3.4"),
        Alert(alert_type="privilege_escalation_attempt", severity=Severity.MEDIUM,
              description="y", timestamp=datetime(2026, 8, 10, 9, 5, 0), username="bob"),
    ]
    store_alerts(conn, alerts)

    high_only = query_alerts(conn, severity="HIGH")
    assert len(high_only) == 1
    assert high_only[0]["alert_type"] == "brute_force"

    all_alerts = query_alerts(conn)
    assert len(all_alerts) == 2
