"""Console reporting: log-derived text never reaches the terminal unescaped.

Covers every field that can carry log-derived text (username, source IP, detail keys and
values such as request paths and tried usernames, unknown alert types) both for freshly
detected alerts and for rows read back from SQLite, plus end-to-end runs of the CLI.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from soc_analyzer import cli
from soc_analyzer.database import init_db
from soc_analyzer.models import Alert, LogEvent, ParseResult, Severity
from soc_analyzer.reporting import (
    alerts_to_json,
    format_alert,
    format_summary,
    print_alerts,
    print_stored_alerts,
)
from tests.terminal_payloads import PAYLOADS, RLO, unsafe_chars

TS = datetime(2026, 8, 10, 9, 0, 0)
PAYLOAD_IDS = sorted(PAYLOADS)


def _alert(**kwargs: object) -> Alert:
    fields: dict[str, object] = {
        "alert_type": "brute_force",
        "severity": Severity.HIGH,
        "description": "test",
        "timestamp": TS,
        "source_ip": "203.0.113.7",
        "username": "root",
    }
    fields.update(kwargs)
    return Alert(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------- format_alert, every field

FIELD_OVERRIDES = {
    "username": lambda p: {"username": p},
    "source_ip": lambda p: {"source_ip": p},
    "details_path": lambda p: {"details": {"path": p, "method": "GET", "status": 404}},
    "details_key": lambda p: {"details": {p: 1}},
    "usernames_tried": lambda p: {"details": {"usernames_tried": ["root", p]}},
    "alert_type": lambda p: {"alert_type": p},
}


@pytest.mark.parametrize("name", PAYLOAD_IDS)
@pytest.mark.parametrize("field", sorted(FIELD_OVERRIDES))
def test_format_alert_escapes_every_log_derived_field(name: str, field: str) -> None:
    text = format_alert(_alert(**FIELD_OVERRIDES[field](PAYLOADS[name])), color=False)
    assert unsafe_chars(text) == []
    # One alert field is one output line: a payload cannot forge extra lines.
    details = FIELD_OVERRIDES[field]("x").get("details", {})
    assert len(text.splitlines()) == 7 + len(details)


def test_format_alert_keeps_severity_color_only() -> None:
    text = format_alert(_alert(username="\x1b[31mx"), color=True)
    assert "\x1b[1;31mHIGH\x1b[0m" in text  # our own color code survives
    assert "User: \\x1b[31mx" in text  # the log's escape sequence does not


def test_print_alerts_output_is_safe(capsys: pytest.CaptureFixture[str]) -> None:
    alerts = [_alert(username=p, source_ip=p) for p in PAYLOADS.values()]
    print_alerts(alerts, no_color=True)
    out = capsys.readouterr().out
    assert unsafe_chars(out) == []
    assert f"Summary: {len(alerts)} alert(s)" in out


def test_print_alerts_without_alerts(capsys: pytest.CaptureFixture[str]) -> None:
    print_alerts([], no_color=True)
    assert "No alerts triggered" in capsys.readouterr().out


def test_format_summary_escapes_unknown_severities() -> None:
    text = format_summary(["HIGH", "HIGH", "EVIL\x1b[5m"])
    assert "Summary: 3 alert(s)" in text
    assert "HIGH: 2" in text
    assert "EVIL\\x1b[5m: 1" in text
    assert unsafe_chars(text) == []


def test_json_output_escapes_control_characters() -> None:
    text = alerts_to_json([_alert(username=p) for p in PAYLOADS.values()])
    assert unsafe_chars(text) == []
    assert all(ord(ch) < 128 for ch in text)  # ensure_ascii: no raw non-ASCII either
    decoded = json.loads(text)
    assert [a["username"] for a in decoded] == list(PAYLOADS.values())


# ---------------------------------------------------------------- stored alerts (SQLite)


def _stored_rows(db: Path, rows: list[tuple[object, ...]]) -> list[sqlite3.Row]:
    conn = init_db(str(db))
    conn.executemany(
        "INSERT INTO alerts (alert_type, severity, description, timestamp, source_ip,"
        " username, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.row_factory = sqlite3.Row
    result = conn.execute("SELECT * FROM alerts").fetchall()
    conn.close()
    return result


def test_stored_alerts_are_escaped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows: list[tuple[object, ...]] = [
        (
            p,  # alert_type
            "EVIL\x1b[5m" if i % 2 else "HIGH",  # tampered severity on every other row
            "d",
            f"2026-08-10T09:00:0{i % 10}\x1b[2J",
            p,
            p,
            json.dumps({"path": p, p: [p]}),
        )
        for i, p in enumerate(PAYLOADS.values())
    ]
    print_stored_alerts(_stored_rows(tmp_path / "a.db", rows), no_color=False)
    out = capsys.readouterr().out
    assert unsafe_chars(out) == []
    assert "\\x1b]0;pwned\\x07" in out


def test_stored_alerts_with_undecodable_details(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows: list[tuple[object, ...]] = [
        ("brute_force", "HIGH", "d", "t", None, None, "{not json \x1b[2J"),
        ("brute_force", "LOW", "d", "t", None, None, json.dumps(["\x1b[2J"])),
        ("brute_force", "MEDIUM", "d", "t", None, None, None),
    ]
    print_stored_alerts(_stored_rows(tmp_path / "b.db", rows), no_color=True)
    out = capsys.readouterr().out
    assert unsafe_chars(out) == []
    assert "Details: {not json \\x1b[2J" in out
    assert "Summary: 3 alert(s)" in out


def test_no_stored_alerts(capsys: pytest.CaptureFixture[str]) -> None:
    print_stored_alerts([], no_color=True)
    assert "No stored alerts match" in capsys.readouterr().out


# ---------------------------------------------------------------- end to end through the CLI

SUDO_FAIL = (
    "Aug 10 09:07:{sec:02d} host sudo:   {user} : user NOT in sudoers ; "
    "TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/bin/bash"
)
SSH_FAIL = "Aug 10 09:02:{sec:02d} host sshd[1]: Failed password for root from {ip} port 4000 ssh2"
APACHE_404 = '203.0.113.9 - - [10/Aug/2026:10:00:00 +0000] "GET {path} HTTP/1.1" 404 10 "-" "x"'


def _write_log(tmp_path: Path, name: str, lines: list[str]) -> str:
    path = tmp_path / name
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return str(path)


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_escapes_esc_in_sudo_username(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    user = "\x1b]0;pwned\x07evil"
    lines = [SUDO_FAIL.format(sec=s, user=user) for s in (10, 20, 30)]
    log = _write_log(tmp_path, "auth.log", lines)
    code, out, _ = _run(["--file", log, "--no-color", "--year", "2026"], capsys)
    assert code == 0
    assert "\x1b" not in out and "\x07" not in out
    assert "User: \\x1b]0;pwned\\x07evil" in out


def test_cli_escapes_esc_in_source_ip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ip = "203.0.113.9\x1b[8m"
    log = _write_log(tmp_path, "auth.log", [SSH_FAIL.format(sec=s, ip=ip) for s in range(5)])
    code, out, _ = _run(["--file", log, "--no-color", "--year", "2026"], capsys)
    assert code == 0
    assert unsafe_chars(out) == []
    assert "Source IP: 203.0.113.9\\x1b[8m" in out


def test_cli_escapes_esc_in_request_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = _write_log(tmp_path, "access.log", [APACHE_404.format(path="/\x1b[2J\x7f/.env")])
    code, out, _ = _run(["--file", log, "--no-color"], capsys)
    assert code == 0
    assert unsafe_chars(out) == []
    assert "Path: /\\x1b[2J\\x7f/.env" in out


def test_cli_escapes_allowlist_error_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = [SSH_FAIL.format(sec=s, ip="203.0.113.9") for s in range(5)]
    log = _write_log(tmp_path, "auth.log", lines)
    allow = _write_log(tmp_path, "allow.txt", ["\x1b]0;x\x07evil:" + RLO + "value"])
    code, _, err = _run(["--file", log, "--allowlist-file", allow], capsys)
    assert code == 1
    assert "unknown entry type" in err
    assert unsafe_chars(err) == []


def test_cli_escapes_file_paths_in_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Windows forbids control characters in file names, so the parser is stubbed out.
    event = LogEvent(
        timestamp=TS, source="auth", event_type="failed_login", source_ip="203.0.113.9"
    )
    monkeypatch.setattr(cli, "parse_log_file", lambda *_a, **_k: ParseResult("auth", [event]))
    db = str(tmp_path / "out.db")
    code, out, _ = _run(["--file", "x\x1b]0;t\x07" + RLO + ".log", "--db", db], capsys)
    assert code == 0
    assert unsafe_chars(out) == []
    assert "from x\\x1b]0;t\\x07\\u202e.log" in out


def test_cli_show_alerts_escapes_stored_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "s.db"
    _stored_rows(db, [("brute_force", "HIGH", "d", "t", "\x1b[2J", RLO + "root", None)])
    code, out, _ = _run(["--show-alerts", "--db", str(db)], capsys)
    assert code == 0
    assert unsafe_chars(out) == []
    assert "User: \\u202eroot" in out


def test_cli_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _run(["--show-alerts"], capsys)
    assert code == 1 and "--show-alerts requires --db" in err
    code, _, err = _run([], capsys)
    assert code == 1 and "--file is required" in err


def test_console_streams_use_backslashreplace(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class Stream:
        def reconfigure(self, *, errors: str) -> None:
            calls.append(errors)

    monkeypatch.setattr("sys.stdout", Stream())
    monkeypatch.setattr("sys.stderr", object())  # no reconfigure(): left alone
    cli._harden_console()
    assert calls == ["backslashreplace"]
