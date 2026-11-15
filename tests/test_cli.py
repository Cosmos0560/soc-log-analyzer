"""CLI behaviour: skipped-line reporting, --tz, file errors, database errors."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from soc_analyzer import cli
from tests.terminal_payloads import RLO, unsafe_chars

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAMPLE_AUTH = str(EXAMPLES / "sample_auth.log")

SSH_FAIL = "{date} 09:02:{sec:02d} host sshd[1]: Failed password for root from {ip} port 22 ssh2"
SUDO_FAIL = (
    "Aug 10 09:07:{sec:02d} host sudo:   {user} : user NOT in sudoers ; "
    "TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/bin/bash"
)


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_log(tmp_path: Path, name: str, lines: list[str]) -> str:
    path = tmp_path / name
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return str(path)


def brute_force_lines(date: str = "Aug 10", ip: str = "203.0.113.9") -> list[str]:
    return [SSH_FAIL.format(date=date, sec=s, ip=ip) for s in range(5)]


# ---------------------------------------------------------------- skipped lines


def test_skipped_lines_are_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lines = [*brute_force_lines(), SSH_FAIL.format(date="Feb 29", sec=0, ip="203.0.113.9")]
    log = write_log(tmp_path, "auth.log", lines)
    code, out, _ = run(["--file", log, "--year", "2026", "--no-color"], capsys)
    assert code == 0
    assert "[!] Skipped 1 line(s)" in out
    assert "Possible Brute Force" in out


def test_only_bad_lines_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = write_log(tmp_path, "auth.log", brute_force_lines(date="Feb 29"))
    code, out, err = run(["--file", log, "--year", "2026"], capsys)
    assert code == 1
    assert "Skipped 5 line(s)" in out
    assert "No recognizable log lines" in err


def test_skipped_notice_goes_to_stderr_in_json_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = [*brute_force_lines(), SSH_FAIL.format(date="Feb 29", sec=0, ip="203.0.113.9")]
    log = write_log(tmp_path, "auth.log", lines)
    code, out, err = run(["--file", log, "--year", "2026", "--json"], capsys)
    assert code == 0
    assert "Skipped 1 line(s)" in err
    json.loads(out)


# ---------------------------------------------------------------- --tz


def test_tz_offset_shows_in_console_output(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(["--file", SAMPLE_AUTH, "--year", "2026", "--tz", "+05:30"], capsys)
    assert code == 0
    assert "Time: 2026-08-10 09:06:10+05:30" in out


def test_tz_default_is_utc(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(["--file", SAMPLE_AUTH, "--year", "2026"], capsys)
    assert code == 0
    assert "Time: 2026-08-10 09:06:10+00:00" in out


def test_tz_iana_name(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(["--file", SAMPLE_AUTH, "--year", "2026", "--tz", "Asia/Tokyo"], capsys)
    assert code == 0
    assert "Time: 2026-08-10 09:06:10+09:00" in out


def test_invalid_tz_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--file", SAMPLE_AUTH, "--tz", "Mars/Olympus"])
    assert exc.value.code == 2
    assert "unknown time zone" in capsys.readouterr().err


# ---------------------------------------------------------------- file errors


def test_file_over_the_size_limit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    big = tmp_path / "big.log"
    big.write_bytes(b"x" * (1024 * 1024 + 1))
    code, _, err = run(["--file", str(big), "--max-file-mb", "1"], capsys)
    assert code == 1
    assert "over the 1 MB limit (raise it with --max-file-mb)" in err


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_max_file_mb_must_be_positive(value: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--file", SAMPLE_AUTH, "--max-file-mb", value])
    assert exc.value.code == 2
    assert "expected a whole number" in capsys.readouterr().err


def test_directory_as_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(["--file", str(tmp_path)], capsys)
    assert code == 1 and "not a regular file" in err


def test_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(["--file", str(tmp_path / "missing.log")], capsys)
    assert code == 1 and "cannot read" in err


def test_unknown_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = write_log(tmp_path, "x.log", ["nothing recognizable"])
    code, _, err = run(["--file", log], capsys)
    assert code == 1 and "Could not determine log format" in err


def test_missing_allowlist_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(
        ["--file", SAMPLE_AUTH, "--allowlist-file", str(tmp_path / "nope.txt")], capsys
    )
    assert code == 1 and "cannot read" in err


# ---------------------------------------------------------------- UTF-8 end to end


def test_bidi_and_c1_in_a_utf8_log_are_escaped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = [SUDO_FAIL.format(sec=s, user="adm" + RLO + "in\x9b2J") for s in (10, 20, 30)]
    log = write_log(tmp_path, "auth.log", lines)
    code, out, _ = run(["--file", log, "--year", "2026", "--no-color"], capsys)
    assert code == 0
    assert unsafe_chars(out) == []
    assert "User: adm" + "\\" + "u202ein" + "\\" + "x9b2J" in out


# ---------------------------------------------------------------- database


def test_db_stores_utc_and_status_goes_to_stderr_in_json_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "f.db"
    argv = ["--file", SAMPLE_AUTH, "--year", "2026", "--tz", "+05:30", "--db", str(db), "--json"]
    code, out, err = run(argv, capsys)
    assert code == 0
    json.loads(out)  # stdout is exactly the JSON document
    assert "Saved 40 event(s)" in err
    conn = sqlite3.connect(db)
    try:
        stamps = {row[0] for row in conn.execute("SELECT timestamp FROM alerts")}
    finally:
        conn.close()
    assert stamps and all(s.endswith("+00:00") for s in stamps)
    assert "2026-08-10T03:36:10+00:00" in stamps  # 09:06:10 at +05:30


def test_unwritable_db(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "no" / "such" / "dir" / "f.db"
    code, _, err = run(["--file", SAMPLE_AUTH, "--db", str(db)], capsys)
    assert code == 1 and "cannot write database" in err


def test_unreadable_db_in_query_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(["--show-alerts", "--db", str(tmp_path)], capsys)
    assert code == 1 and "cannot read database" in err


def test_show_alerts_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "r.db")
    assert run(["--file", SAMPLE_AUTH, "--year", "2026", "--db", db], capsys)[0] == 0
    code, out, _ = run(["--show-alerts", "--db", db, "--severity", "CRITICAL"], capsys)
    assert code == 0
    assert "Possible Compromised Credential" in out
    assert "Summary: 1 alert(s)" in out
