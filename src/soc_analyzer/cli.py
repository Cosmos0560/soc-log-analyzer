"""Command-line interface: ``python analyzer.py --file auth.log``"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from datetime import tzinfo

from .allowlist import build_allowlist
from .database import init_db, query_alerts, store_alerts, store_events
from .detectors import run_all_detectors
from .models import Alert
from .parsers import DEFAULT_MAX_FILE_MB, FileTooLargeError, parse_log_file
from .reporting import (
    analysis_document,
    print_alerts,
    print_stored_alerts,
    stored_alerts_document,
    to_json,
)
from .sanitize import escape_for_terminal
from .timezones import parse_timezone, timezone_label


def _tz_arg(value: str) -> tzinfo:
    try:
        return parse_timezone(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        number = 0
    if number < 1:
        raise argparse.ArgumentTypeError(f"expected a whole number of 1 or more, got {value!r}")
    return number


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Parse security log file(s) and surface suspicious activity.",
    )
    p.add_argument(
        "--file",
        "-f",
        action="append",
        default=None,
        help="Path to a log file to analyze (required unless --show-alerts is used). "
        "Repeatable — pass it more than once (e.g. --file auth.log --file "
        "access.log) to analyze multiple files together in one run, which is "
        "required for cross-source correlation. Each file's format is "
        "auto-detected independently unless --type overrides all of them.",
    )
    p.add_argument(
        "--type",
        choices=["auto", "auth", "apache"],
        default="auto",
        help="Log format applied to every --file (default: auto-detect each one)",
    )
    p.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to assume for auth.log entries (which omit it). "
        "Defaults to the current year in --tz.",
    )
    p.add_argument(
        "--tz",
        type=_tz_arg,
        default=parse_timezone("UTC"),
        metavar="ZONE",
        help="Time zone of auth.log timestamps (which carry none), and the zone all "
        "output timestamps are converted to: UTC, an offset such as +05:30, or "
        "an IANA name such as Europe/Berlin (default: UTC)",
    )
    p.add_argument(
        "--max-file-mb",
        type=_positive_int,
        default=DEFAULT_MAX_FILE_MB,
        metavar="MB",
        help=f"Refuse log files larger than this many megabytes (default: {DEFAULT_MAX_FILE_MB})",
    )
    p.add_argument("--db", default=None, help="SQLite file to persist events + alerts into")
    p.add_argument(
        "--json",
        action="store_true",
        help="Print one JSON document (schema: docs/OUTPUT_SCHEMA.md) instead of "
        "console output; status messages go to stderr",
    )
    p.add_argument("--no-color", action="store_true", help="Disable colored console output")

    grp = p.add_argument_group("detection thresholds")
    grp.add_argument(
        "--failed-threshold",
        type=int,
        default=5,
        help="Failed logins from one IP to trigger a brute-force / "
        "compromised-credential alert (default: 5)",
    )
    grp.add_argument(
        "--window",
        type=int,
        default=5,
        help="Sliding time window in minutes for brute-force, compromised-"
        "credential, AND privilege-escalation detection (default: 5)",
    )
    grp.add_argument(
        "--privesc-threshold",
        type=int,
        default=3,
        help="Failed sudo attempts by one user, inside --window, to trigger "
        "a privilege-escalation alert (default: 3)",
    )
    grp.add_argument(
        "--scan-threshold",
        type=int,
        default=10,
        help="404s from one IP to trigger a scanning alert (default: 10)",
    )
    grp.add_argument(
        "--scan-window",
        type=int,
        default=2,
        help="Sliding time window in minutes for scan detection (default: 2)",
    )
    grp.add_argument(
        "--correlation-window",
        type=int,
        default=60,
        help="Minutes within which SSH auth activity from an IP, following that "
        "same IP's web recon, is treated as one multi-stage incident "
        "(default: 60). Only relevant when --file is passed more than once.",
    )

    agrp = p.add_argument_group("allow-listing (suppress expected-noise alerts)")
    agrp.add_argument(
        "--allow-ip",
        action="append",
        default=None,
        help="Suppress alerts whose source IP matches this value. Repeatable.",
    )
    agrp.add_argument(
        "--allow-user",
        action="append",
        default=None,
        help="Suppress alerts whose username matches this value. Repeatable.",
    )
    agrp.add_argument(
        "--allowlist-file",
        default=None,
        help="Path to a file with 'ip:<value>' / 'user:<value>' lines "
        "(one per line, '#' comments allowed) to merge with --allow-ip/--allow-user",
    )

    qgrp = p.add_argument_group("query an existing database (no log file needed)")
    qgrp.add_argument(
        "--show-alerts",
        action="store_true",
        help="Print alerts already stored in --db instead of parsing a new log file",
    )
    qgrp.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="With --show-alerts, filter to a single severity level",
    )
    return p


def _error(message: object) -> None:
    """Print an error to stderr. Messages may quote paths or log content: escape them."""
    print(f"Error: {escape_for_terminal(message)}", file=sys.stderr)


def _harden_console() -> None:
    """Never crash on text the console encoding cannot represent (e.g. cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _run_query_mode(args: argparse.Namespace) -> int:
    if not args.db:
        _error("--show-alerts requires --db <path>")
        return 1
    try:
        conn = init_db(args.db)
        try:
            rows = query_alerts(conn, severity=args.severity)
        finally:
            conn.close()
    except sqlite3.Error as exc:
        _error(f"cannot read database {args.db!r}: {exc}")
        return 1
    if args.json:
        print(to_json(stored_alerts_document(rows)))
    else:
        print_stored_alerts(rows, no_color=args.no_color)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    _harden_console()
    args = build_parser().parse_args(argv)

    if args.show_alerts:
        return _run_query_mode(args)

    if not args.file:
        _error("--file is required (or use --show-alerts to query an existing --db)")
        return 1

    results = []
    for path in args.file:
        try:
            results.append(
                parse_log_file(
                    path,
                    log_type=args.type,
                    year=args.year,
                    tz=args.tz,
                    max_bytes=args.max_file_mb * 1024 * 1024,
                )
            )
        except FileTooLargeError as exc:
            _error(f"{exc} (raise it with --max-file-mb)")
            return 1
        except OSError as exc:
            _error(f"cannot read {path!r}: {exc.strerror or exc}")
            return 1
        except ValueError as exc:
            _error(exc)
            return 1

    events = [event for result in results for event in result.events]
    skipped = sum(result.skipped_lines for result in results)
    # Status lines go to stderr in --json mode so stdout stays machine-readable.
    status_stream = sys.stderr if args.json else sys.stdout

    if skipped:
        print(
            f"[!] Skipped {skipped} line(s) that matched a known log format but could "
            "not be parsed (e.g. an impossible date)",
            file=status_stream,
        )

    if not events:
        print(
            "[!] No recognizable log lines were parsed. "
            "Check the file path(s) and format, or pass --type explicitly.",
            file=sys.stderr,
        )
        return 1

    try:
        allowlist = build_allowlist(args.allow_ip, args.allow_user, args.allowlist_file)
    except OSError as exc:
        _error(f"cannot read {args.allowlist_file!r}: {exc.strerror or exc}")
        return 1
    except ValueError as exc:
        _error(exc)
        return 1

    alerts = run_all_detectors(
        events,
        brute_force_threshold=args.failed_threshold,
        brute_force_window=args.window,
        privesc_threshold=args.privesc_threshold,
        privesc_window=args.window,
        scan_threshold=args.scan_threshold,
        scan_window=args.scan_window,
        correlation_window=args.correlation_window,
    )

    suppressed: list[Alert] = []
    if allowlist:
        alerts, suppressed = allowlist.filter_alerts(alerts)

    if args.json:
        document = analysis_document(
            sources=list(zip(args.file, results, strict=True)),
            alerts=alerts,
            suppressed_alerts=len(suppressed),
            timezone_name=timezone_label(args.tz),
        )
        print(to_json(document))
    else:
        sources = escape_for_terminal(", ".join(args.file))
        print(f"[*] Parsed {len(events)} event(s) from {sources}\n")
        print_alerts(alerts, no_color=args.no_color)
        if suppressed:
            print(f"\n[*] Suppressed {len(suppressed)} alert(s) via allow-list")

    if args.db:
        try:
            conn = init_db(args.db)
            try:
                store_events(conn, events)
                store_alerts(conn, alerts)
            finally:
                conn.close()
        except sqlite3.Error as exc:
            _error(f"cannot write database {args.db!r}: {exc}")
            return 1
        print(
            f"\n[*] Saved {len(events)} event(s) and {len(alerts)} alert(s) to "
            f"{escape_for_terminal(args.db)}",
            file=status_stream,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
