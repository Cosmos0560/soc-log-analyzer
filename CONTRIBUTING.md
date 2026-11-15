# Contributing

Thanks for considering a contribution. This started as a training/portfolio
project, so contributions that improve its teaching value are especially
welcome — clearer detection reasoning, additional log formats, edge-case
tests, and so on.

## Getting set up

Requires Python 3.11+.

```bash
git clone https://github.com/Cosmos0560/soc-log-analyzer.git
cd soc-log-analyzer
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Linux/macOS: .venv/bin/python
.venv/Scripts/python scripts/gate.py
```

`scripts/gate.py` is the single check that must pass before every commit. It runs
ruff, ruff format --check, mypy --strict, pytest with at least 90% branch coverage,
an email/secret scan, the RFC 5737 address check and a CLI smoke test. CI runs the
same gate on Windows and Ubuntu with Python 3.11 to 3.14.

## Adding a new detection rule

1. Add a `detect_<name>(events, ...)` function to `src/soc_analyzer/detectors.py`
   that takes a list of `LogEvent` and returns a list of `Alert`.
2. Wire it into `run_all_detectors()`.
3. Add at least one positive test (rule fires) and one negative test (rule
   correctly stays silent) to `tests/test_detectors.py`.
4. Document the rule's trigger condition, reasoning, and severity in
   `docs/DETECTION_RULES.md`, following the existing format.
5. Document its `alert_type` and every `details` key in
   `docs/OUTPUT_SCHEMA.md`. A new alert type or detail key is a minor
   `schema_version` bump. Then regenerate the golden file (see
   `tests/test_output_schema.py`).
6. Update the rule table in `README.md`.

## Adding a new log format parser

1. Add a `parse_<format>_log(lines, tz)` function to `src/soc_analyzer/parsers.py`
   that returns a `ParseResult`. Count lines that match the format but cannot
   be parsed in `skipped_lines`; never let one bad line raise.
2. Make every timestamp timezone-aware and convert it to `tz`.
3. Extend `detect_log_type()` so auto-detection recognizes the new format.
4. Add sample log lines and parser tests to `tests/test_parsers.py`.
5. Add a small synthetic example file under `examples/`.

## Code style and data rules

- Type hints everywhere. `src/` must pass `mypy --strict`. ruff and ruff format
  are enforced.
- No new third-party dependencies for core functionality without
  discussion first — the zero-dependency design is intentional.
- Anything printed to the console that came from a log line goes through
  `soc_analyzer.sanitize.escape_for_terminal`.
- Tests and samples use only RFC 5737 documentation addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and IPv6 `2001:db8::/32`.
  The gate enforces this.

## Reporting issues

Open a GitHub issue with the log line (redacted/synthetic if it's from a
real system) that isn't being parsed or detected as expected.
