"""--tz parsing and labels."""

from __future__ import annotations

from datetime import UTC, timedelta
from zoneinfo import ZoneInfo

import pytest

from soc_analyzer.timezones import parse_timezone, timezone_label


@pytest.mark.parametrize("spec", ["UTC", "utc", "Z", " UTC "])
def test_utc_spellings(spec: str) -> None:
    assert parse_timezone(spec) is UTC


@pytest.mark.parametrize(
    ("spec", "offset", "label"),
    [
        ("+05:30", timedelta(hours=5, minutes=30), "+05:30"),
        ("-0300", timedelta(hours=-3), "-03:00"),
        ("+00:00", timedelta(0), "UTC"),
        ("-09:45", -timedelta(hours=9, minutes=45), "-09:45"),
    ],
)
def test_fixed_offsets(spec: str, offset: timedelta, label: str) -> None:
    tz = parse_timezone(spec)
    assert tz.utcoffset(None) == offset
    assert timezone_label(tz) == label


def test_iana_name() -> None:
    tz = parse_timezone("Europe/Berlin")
    assert isinstance(tz, ZoneInfo)
    assert timezone_label(tz) == "Europe/Berlin"


def test_utc_label() -> None:
    assert timezone_label(UTC) == "UTC"


@pytest.mark.parametrize("spec", ["+24:00", "+05:60"])
def test_out_of_range_offsets(spec: str) -> None:
    with pytest.raises(ValueError, match="invalid UTC offset"):
        parse_timezone(spec)


@pytest.mark.parametrize("spec", ["Nowhere/Zone", "../../etc/passwd", "", "+5"])
def test_unknown_zones_have_a_helpful_message(spec: str) -> None:
    with pytest.raises(ValueError, match="unknown time zone") as exc:
        parse_timezone(spec)
    assert "tzdata" in str(exc.value)
