"""escape_for_terminal: every control, format and separator character becomes visible text."""

from __future__ import annotations

import pytest

from soc_analyzer.sanitize import escape_for_terminal
from tests.terminal_payloads import LS, PAYLOADS, RLO, escaped, unsafe_chars

BS = "\\"


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_payload_is_neutralized(name: str) -> None:
    result = escape_for_terminal(PAYLOADS[name])
    assert unsafe_chars(result) == []
    assert "\n" not in result


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("\x1b[31m", BS + "x1b[31m"),
        ("\x9b", BS + "x9b"),
        ("\x00", BS + "x00"),
        ("\x7f", BS + "x7f"),
        ("a\nb\rc\td", f"a{BS}nb{BS}rc{BS}td"),
        (RLO, escaped(0x202E)),
        (LS, escaped(0x2028)),
        (chr(0xE0001), BS + "U000e0001"),  # language tag (Cf), outside the BMP
        (chr(0x10FFFD), BS + "U0010fffd"),  # private use (Co)
        (chr(0xD800), escaped(0xD800)),  # lone surrogate (Cs)
    ],
)
def test_escape_forms(raw: str, expected: str) -> None:
    assert escape_for_terminal(raw) == expected


@pytest.mark.parametrize(
    "text",
    [
        "root",
        "203.0.113.7",
        "/wp-login.php?x=1",
        "jos" + chr(0xE9),
        chr(0x65E5) + chr(0x672C),
        "a" + chr(0xA0) + "b",  # no-break space: a harmless space, kept
        "",
    ],
)
def test_printable_text_is_unchanged(text: str) -> None:
    assert escape_for_terminal(text) == text


def test_non_strings_are_converted() -> None:
    assert escape_for_terminal(5) == "5"
    assert escape_for_terminal(["a\x1b"]) == "['a" + BS + "x1b']"
    assert escape_for_terminal(None) == "None"
