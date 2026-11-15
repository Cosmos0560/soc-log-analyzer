"""Make untrusted, log-derived text safe to print to a terminal.

Every field this tool extracts from a log line (usernames, source IPs, request paths,
sudo commands) is attacker-controlled: the parsers match them with ``\\S+``, which happily
accepts ESC and other control characters. Printed raw, such a field can inject ANSI/OSC
escape sequences into the analyst's terminal (recolor or erase output, set the window
title, plant hyperlinks) or use bidi and line-separator characters to make one alert
look like another.

``escape_for_terminal`` replaces every character that is not safe to display with a
visible escape (``\\x1b``, ``\\u202e``, ``\\n``), so the analyst sees exactly what was in
the log and the terminal interprets nothing. It is applied at the console boundary only.
Stored data (SQLite) keeps the raw values, and JSON output is safe on its own because
``json.dumps`` escapes all control and non-ASCII characters.
"""

from __future__ import annotations

import unicodedata

# Unicode categories that must never reach a terminal unescaped:
#   Cc  control characters: C0 (incl. ESC, BEL, NUL, CR, LF, TAB), DEL, C1 (incl. CSI 0x9b)
#   Cf  format characters: bidi overrides/isolates (U+202A-U+202E, U+2066-U+2069),
#       zero-width characters (U+200B-U+200F), BOM
#   Cs  lone surrogates (from errors="surrogateescape" style decoding)
#   Co  private-use characters (terminal-specific glyphs)
#   Cn  unassigned code points
#   Zl  line separator (U+2028)
#   Zp  paragraph separator (U+2029)
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

_SHORT_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escape_char(ch: str) -> str:
    if ch in _SHORT_ESCAPES:
        return _SHORT_ESCAPES[ch]
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def escape_for_terminal(value: object) -> str:
    """Return ``str(value)`` with every unsafe character replaced by a visible escape."""
    text = value if isinstance(value, str) else str(value)
    if text.isprintable():
        # Fast path: isprintable() is False for every unsafe category (and for
        # non-ASCII spaces, which are harmless and handled below).
        return text
    return "".join(
        _escape_char(ch) if unicodedata.category(ch) in UNSAFE_CATEGORIES else ch for ch in text
    )
