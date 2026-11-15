"""Bad lines, time zones and file handling in the parsers and the allow-list loader."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from soc_analyzer.allowlist import MAX_ALLOWLIST_BYTES, load_allowlist_file
from soc_analyzer.parsers import (
    FileTooLargeError,
    check_input_file,
    iter_text_lines,
    parse_apache_log,
    parse_auth_log,
    parse_log_file,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
BOM = chr(0xFEFF)
REPLACEMENT = chr(0xFFFD)

SSH_FAIL = "{date} 09:15:32 host sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"
SUDO_OK = (
    "Aug 10 09:20:30 host sudo:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/su -"
)
ACCESS = '203.0.113.7 - - [{ts}] "GET / HTTP/1.1" 200 10 "-" "curl"'


# ---------------------------------------------------------------- one bad line never kills the run


def test_feb_29_in_a_non_leap_year_is_skipped_and_counted() -> None:
    lines = [SSH_FAIL.format(date="Feb 28"), SSH_FAIL.format(date="Feb 29")]
    result = parse_auth_log(lines, year=2026)
    assert len(result.events) == 1
    assert result.skipped_lines == 1


def test_feb_29_in_a_leap_year_parses() -> None:
    result = parse_auth_log([SSH_FAIL.format(date="Feb 29")], year=2028)
    assert result.skipped_lines == 0
    assert result.events[0].timestamp == datetime(2028, 2, 29, 9, 15, 32, tzinfo=UTC)


@pytest.mark.parametrize(
    "ts",
    ["31/Feb/2026:10:00:00 +0000", "10/Aug/2026:10:00:00", "10/Foo/2026:10:00:00 +0000"],
)
def test_bad_access_log_timestamps_are_counted(ts: str) -> None:
    ok = ACCESS.format(ts="10/Aug/2026:10:00:00 +0000")
    result = parse_apache_log([ok, ACCESS.format(ts=ts)])
    assert len(result.events) == 1
    assert result.skipped_lines == 1


def test_unrecognized_lines_are_ignored_not_counted() -> None:
    result = parse_auth_log(["Aug 10 09:00:00 host CRON[1]: session opened", "noise"])
    assert result.events == [] and result.skipped_lines == 0


def test_crlf_line_endings_do_not_leak_into_fields() -> None:
    result = parse_auth_log([SUDO_OK + "\r\n"], year=2026)
    assert result.events[0].extra == {"command": "/bin/su -"}


# ---------------------------------------------------------------- time zones


def test_syslog_timestamps_take_the_given_zone() -> None:
    plus_0530 = timezone(timedelta(hours=5, minutes=30))
    event = parse_auth_log([SSH_FAIL.format(date="Aug 10")], year=2026, tz=plus_0530).events[0]
    assert event.timestamp.isoformat() == "2026-08-10T09:15:32+05:30"


def test_syslog_default_is_utc() -> None:
    event = parse_auth_log([SSH_FAIL.format(date="Aug 10")], year=2026).events[0]
    assert event.timestamp.utcoffset() == timedelta(0)


def test_default_year_is_current_year_in_zone() -> None:
    event = parse_auth_log([SSH_FAIL.format(date="Aug 10")]).events[0]
    assert event.timestamp.year == datetime.now(UTC).year


def test_access_log_offset_is_honored_then_converted() -> None:
    line = ACCESS.format(ts="10/Aug/2026:12:00:00 +0200")
    event = parse_apache_log([line]).events[0]
    assert event.timestamp.isoformat() == "2026-08-10T10:00:00+00:00"
    berlin = parse_apache_log([line], tz=ZoneInfo("Europe/Berlin")).events[0]
    assert berlin.timestamp.isoformat() == "2026-08-10T12:00:00+02:00"


def test_dst_ambiguous_local_time_resolves_to_first_occurrence() -> None:
    # 2026-10-25 02:30 happens twice in Berlin; fold=0 picks the summer-time (+02:00) one.
    line = SSH_FAIL.format(date="Oct 25").replace("09:15:32", "02:30:00")
    event = parse_auth_log([line], year=2026, tz=ZoneInfo("Europe/Berlin")).events[0]
    assert event.timestamp.utcoffset() == timedelta(hours=2)


def test_mixed_sources_compare_as_aware_datetimes() -> None:
    auth = parse_auth_log([SSH_FAIL.format(date="Aug 10")], year=2026).events[0]
    web = parse_apache_log([ACCESS.format(ts="10/Aug/2026:11:15:32 +0200")]).events[0]
    assert auth.timestamp == web.timestamp


# ---------------------------------------------------------------- file handling


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_bom_is_stripped_so_the_first_line_parses(tmp_path: Path) -> None:
    text = BOM + SSH_FAIL.format(date="Aug 10") + "\n"
    path = _write(tmp_path, "auth.log", text.encode("utf-8"))
    result = parse_log_file(path, year=2026)
    assert result.log_type == "auth" and len(result.events) == 1


def test_invalid_utf8_bytes_are_replaced(tmp_path: Path) -> None:
    line = SSH_FAIL.format(date="Aug 10").replace("root", "r\xffot").encode("latin-1")
    result = parse_log_file(_write(tmp_path, "auth.log", line + b"\n"), year=2026)
    assert result.events[0].username == "r" + REPLACEMENT + "ot"


def test_files_are_streamed_past_the_detection_sample() -> None:
    result = parse_log_file(str(EXAMPLES / "sample_auth.log"), year=2026)
    assert result.log_type == "auth"
    assert len(result.events) == 40  # more than the 20-line detection sample


def test_type_override_skips_detection() -> None:
    result = parse_log_file(str(EXAMPLES / "sample_auth.log"), log_type="apache")
    assert result.log_type == "apache" and result.events == []


def test_size_limit(tmp_path: Path) -> None:
    path = _write(tmp_path, "big.log", b"x" * 2048)
    with pytest.raises(FileTooLargeError) as exc:
        parse_log_file(path, max_bytes=1024)
    assert "over the" in str(exc.value) and exc.value.size == 2048
    check_input_file(path, max_bytes=2048)  # exactly at the limit is fine


def test_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        parse_log_file(str(tmp_path))


def test_missing_file_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        parse_log_file(str(tmp_path / "missing.log"))


def test_unknown_format_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Could not determine log format"):
        parse_log_file(_write(tmp_path, "x.log", b"nothing here\n"))


def test_empty_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Could not determine"):
        parse_log_file(_write(tmp_path, "empty.log", b""))
    assert list(iter_text_lines([])) == []


# ---------------------------------------------------------------- allow-list file


def test_allowlist_is_utf8_with_bom(tmp_path: Path) -> None:
    user = "jos" + chr(0xE9)
    path = _write(tmp_path, "allow.txt", (BOM + "user:" + user + "\n").encode("utf-8"))
    assert load_allowlist_file(path).usernames == {user}


def test_allowlist_invalid_bytes_are_replaced(tmp_path: Path) -> None:
    path = _write(tmp_path, "allow.txt", b"user:a\xffb\n")
    assert load_allowlist_file(path).usernames == {"a" + REPLACEMENT + "b"}


def test_allowlist_size_limit(tmp_path: Path) -> None:
    path = _write(tmp_path, "allow.txt", b"#" * (MAX_ALLOWLIST_BYTES + 1))
    with pytest.raises(FileTooLargeError):
        load_allowlist_file(path)


def test_allowlist_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        load_allowlist_file(str(tmp_path))
