"""Command-line interface: ``python analyzer.py --file auth.log``"""

from __future__ import annotations

import argparse
import sys

from .allowlist import build_allowlist
from .database import init_db, query_alerts, store_alerts, store_events
from .detectors import run_all_detectors
from .parsers import parse_log_file
from .reporting import alerts_to_json, print_alerts, print_stored_alerts


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Parse security log file(s) and surface suspicious activity.",
    )
    p.add_argument("--file", "-f", action="append", default=None,
                    help="Path to a log file to analyze (required unless --show-alerts is used). "
                         "Repeatable — pass it more than once (e.g. --file auth.log --file "
                         "access.log) to analyze multiple files together in one run, which is "
                         "required for cross-source correlation. Each file's format is "
                         "auto-detected independently unless --type overrides all of them.")
    p.add_argument("--type", choices=["auto", "auth", "apache"], default="auto",
                    help="Log format applied to every --file (default: auto-detect each one)")
    p.add_argument("--year", type=int, default=None,
                    help="Year to assume for auth.log entries (which omit it). Defaults to current year.")
    p.add_argument("--db", default=None, help="SQLite file to persist events + alerts into")
    p.add_argument("--json", action="store_true", help="Print alerts as JSON instead of console output")
    p.add_argument("--no-color", action="store_true", help="Disable colored console output")

    grp = p.add_argument_group("detection thresholds")
    grp.add_argument("--failed-threshold", type=int, default=5,
                      help="Failed logins from one IP to trigger a brute-force / "
                           "compromised-credential alert (default: 5)")
    grp.add_argument("--window", type=int, default=5,
                      help="Sliding time window in minutes for brute-force, compromised-"
                           "credential, AND privilege-escalation detection (default: 5)")
    grp.add_argument("--privesc-threshold", type=int, default=3,
                      help="Failed sudo attempts by one user, inside --window, to trigger "
                           "a privilege-escalation alert (default: 3)")
    grp.add_argument("--scan-threshold", type=int, default=10,
                      help="404s from one IP to trigger a scanning alert (default: 10)")
    grp.add_argument("--scan-window", type=int, default=2,
                      help="Sliding time window in minutes for scan detection (default: 2)")
    grp.add_argument("--correlation-window", type=int, default=60,
                      help="Minutes within which SSH auth activity from an IP, following that "
                           "same IP's web recon, is treated as one multi-stage incident "
                           "(default: 60). Only relevant when --file is passed more than once.")

    agrp = p.add_argument_group("allow-listing (suppress expected-noise alerts)")
    agrp.add_argument("--allow-ip", action="append", default=None,
                       help="Suppress alerts whose source IP matches this value. Repeatable.")
    agrp.add_argument("--allow-user", action="append", default=None,
                       help="Suppress alerts whose username matches this value. Repeatable.")
    agrp.add_argument("--allowlist-file", default=None,
                       help="Path to a file with 'ip:<value>' / 'user:<value>' lines "
                            "(one per line, '#' comments allowed) to merge with --allow-ip/--allow-user")

    qgrp = p.add_argument_group("query an existing database (no log file needed)")
    qgrp.add_argument("--show-alerts", action="store_true",
                       help="Print alerts already stored in --db instead of parsing a new log file")
    qgrp.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                       help="With --show-alerts, filter to a single severity level")
    return p


def _run_query_mode(args) -> int:
    if not args.db:
        print("Error: --show-alerts requires --db <path>", file=sys.stderr)
        return 1
    conn = init_db(args.db)
    rows = query_alerts(conn, severity=args.severity)
    conn.close()
    if args.json:
        import json
        print(json.dumps([dict(r) for r in rows], indent=2))
    else:
        print_stored_alerts(rows, no_color=args.no_color)
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.show_alerts:
        return _run_query_mode(args)

    if not args.file:
        print("Error: --file is required (or use --show-alerts to query an existing --db)",
              file=sys.stderr)
        return 1

    events = []
    for path in args.file:
        try:
            events += parse_log_file(path, log_type=args.type, year=args.year)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if not events:
        print("[!] No recognizable log lines were parsed. "
              "Check the file path(s) and format, or pass --type explicitly.", file=sys.stderr)
        return 1

    try:
        allowlist = build_allowlist(args.allow_ip, args.allow_user, args.allowlist_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
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

    suppressed = []
    if allowlist:
        alerts, suppressed = allowlist.filter_alerts(alerts)

    if args.json:
        print(alerts_to_json(alerts))
    else:
        sources = ", ".join(args.file)
        print(f"[*] Parsed {len(events)} event(s) from {sources}\n")
        print_alerts(alerts, no_color=args.no_color)
        if suppressed:
            print(f"\n[*] Suppressed {len(suppressed)} alert(s) via allow-list")

    if args.db:
        conn = init_db(args.db)
        store_events(conn, events)
        store_alerts(conn, alerts)
        conn.close()
        print(f"\n[*] Saved {len(events)} event(s) and {len(alerts)} alert(s) to {args.db}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
