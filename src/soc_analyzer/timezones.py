"""Time zone handling for ``--tz``.

Syslog (auth.log) timestamps carry no zone at all, so the analyst has to say which zone
the log was written in. Access-log timestamps carry an offset of their own. Every parsed
timestamp is made timezone-aware and converted to the ``--tz`` zone, so detectors compare
aware datetimes and all output (console, JSON) uses one consistent offset.

Accepted forms:

* ``UTC`` (the default) or ``Z``
* a fixed offset: ``+05:30``, ``-0300``, ``+00:00``
* an IANA zone name such as ``Europe/Berlin``. This uses ``zoneinfo``, which needs the
  system time zone database (present on Linux and macOS) or, on Windows, the ``tzdata``
  package from PyPI. The tool itself stays dependency-free.
"""

from __future__ import annotations

import re
from datetime import UTC, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def parse_timezone(spec: str) -> tzinfo:
    """Turn a ``--tz`` value into a tzinfo. Raises ValueError with a helpful message."""
    text = spec.strip()
    if text.upper() in {"UTC", "Z"}:
        return UTC
    match = _OFFSET_RE.match(text)
    if match:
        sign, hours, minutes = match.group(1), int(match.group(2)), int(match.group(3))
        if hours > 23 or minutes > 59:
            raise ValueError(f"invalid UTC offset {spec!r}")
        delta = timedelta(hours=hours, minutes=minutes)
        return timezone(-delta if sign == "-" else delta)
    try:
        return ZoneInfo(text)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"unknown time zone {spec!r}: use UTC, an offset such as +05:30, or an IANA "
            "name such as Europe/Berlin (IANA names need the system time zone database; "
            "on Windows install the 'tzdata' package)"
        ) from exc


def timezone_label(tz: tzinfo) -> str:
    """A stable name for output: ``UTC``, ``+05:30`` or the IANA key."""
    if isinstance(tz, ZoneInfo):
        return tz.key
    offset = tz.utcoffset(None)
    if offset is None or offset == timedelta(0):
        return "UTC"
    total = int(offset.total_seconds()) // 60
    sign = "-" if total < 0 else "+"
    hours, minutes = divmod(abs(total), 60)
    return f"{sign}{hours:02d}:{minutes:02d}"
