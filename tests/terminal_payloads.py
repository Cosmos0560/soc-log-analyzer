"""Terminal-injection payloads shared by the sanitizer, reporting and CLI tests.

Non-ASCII characters are built with chr() so this file stays ASCII and every payload is
unambiguous when read.
"""

from __future__ import annotations

import unicodedata

from soc_analyzer.sanitize import UNSAFE_CATEGORIES

ESC = "\x1b"
BEL = "\x07"
ST = ESC + "\\"  # string terminator for OSC sequences
RLO = chr(0x202E)  # right-to-left override
LRI = chr(0x2066)  # left-to-right isolate
PDI = chr(0x2069)  # pop directional isolate
ZWSP = chr(0x200B)  # zero-width space
LS = chr(0x2028)  # line separator
PS = chr(0x2029)  # paragraph separator
BOM = chr(0xFEFF)

PAYLOADS: dict[str, str] = {
    "ansi_csi_color": ESC + "[31mRED" + ESC + "[0m",
    "ansi_clear_screen": ESC + "[2J" + ESC + "[H",
    "osc_window_title": ESC + "]0;pwned" + BEL,
    "osc8_hyperlink": ESC + "]8;;https://example.invalid/" + ST + "click" + ESC + "]8;;" + ST,
    "c1_csi": "\x9b31m",
    "nul": "a\x00b",
    "bell_backspace_del": "a\x07\x08\x7fb",
    "cr_overwrite": "fake\rreal",
    "lf_new_line": "user\nSeverity: LOW",
    "tab": "a\tb",
    "bidi_rlo": "admin" + RLO + "txt.exe",
    "bidi_isolate": LRI + "root" + PDI,
    "zero_width_space": "ro" + ZWSP + "ot",
    "line_separator": "a" + LS + "b",
    "paragraph_separator": "a" + PS + "b",
    "bom": BOM + "root",
}


def escaped(code: int) -> str:
    """The visible form escape_for_terminal gives a BMP character, e.g. backslash-u202e."""
    return "\\" + f"u{code:04x}"


def unsafe_chars(text: str) -> list[str]:
    """Characters in ``text`` that a terminal could interpret (newlines between lines aside)."""
    return [
        ch
        for line in text.split("\n")
        for ch in line
        if unicodedata.category(ch) in UNSAFE_CATEGORIES
    ]
