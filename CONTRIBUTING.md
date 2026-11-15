# Contributing

Thanks for considering a contribution. This started as a training/portfolio
project, so contributions that improve its teaching value are especially
welcome — clearer detection reasoning, additional log formats, edge-case
tests, and so on.

## Getting set up

```bash
git clone https://github.com/<your-username>/soc-log-analyzer.git
cd soc-log-analyzer
pip install -r requirements.txt
pytest -v
```

## Adding a new detection rule

1. Add a `detect_<name>(events, ...)` function to `src/soc_analyzer/detectors.py`
   that takes a list of `LogEvent` and returns a list of `Alert`.
2. Wire it into `run_all_detectors()`.
3. Add at least one positive test (rule fires) and one negative test (rule
   correctly stays silent) to `tests/test_detectors.py`.
4. Document the rule's trigger condition, reasoning, and severity in
   `docs/DETECTION_RULES.md`, following the existing format.
5. Update the rule table in `README.md`.

## Adding a new log format parser

1. Add a `parse_<format>_log(lines)` function to `src/soc_analyzer/parsers.py`
   that returns a list of `LogEvent`.
2. Extend `detect_log_type()` so auto-detection recognizes the new format.
3. Add sample log lines and parser tests to `tests/test_parsers.py`.
4. Add a small synthetic example file under `examples/`.

## Code style

- Type hints on function signatures.
- No new third-party dependencies for core functionality without
  discussion first — the zero-dependency design is intentional.
- Run `pytest -v` before opening a PR; CI will run it again automatically.

## Reporting issues

Open a GitHub issue with the log line (redacted/synthetic if it's from a
real system) that isn't being parsed or detected as expected.
