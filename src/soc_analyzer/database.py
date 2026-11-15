"""SQLite persistence for parsed events and generated alerts.

Kept deliberately thin: raw ``sqlite3`` + hand-written SQL rather than an
ORM, since the schema is small and it keeps the dependency footprint at
zero (sqlite3 ships with the Python standard library).
"""

from __future__ import annotations

import json
import sqlite3
from typing import List, Optional

from .models import Alert, LogEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    username TEXT,
    status_code INTEGER,
    path TEXT,
    method TEXT,
    raw_line TEXT,
    extra TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    username TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""


def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def store_events(conn: sqlite3.Connection, events: List[LogEvent]) -> None:
    conn.executemany(
        """INSERT INTO events
           (timestamp, source, event_type, source_ip, username, status_code, path, method, raw_line, extra)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (e.timestamp.isoformat(), e.source, e.event_type, e.source_ip,
             e.username, e.status_code, e.path, e.method, e.raw_line,
             json.dumps(e.extra) if e.extra else None)
            for e in events
        ],
    )
    conn.commit()


def store_alerts(conn: sqlite3.Connection, alerts: List[Alert]) -> None:
    conn.executemany(
        """INSERT INTO alerts
           (alert_type, severity, description, timestamp, source_ip, username, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [
            (a.alert_type, a.severity.value, a.description, a.timestamp.isoformat(),
             a.source_ip, a.username, json.dumps(a.details))
            for a in alerts
        ],
    )
    conn.commit()


def query_alerts(conn: sqlite3.Connection, severity: Optional[str] = None) -> List[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if severity:
        cur.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC", (severity,))
    else:
        cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    return cur.fetchall()
