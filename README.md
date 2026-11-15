# 🛡️ SOC Log Analyzer

A Python-based security log parsing and rule-based threat detection tool,
built as a SOC analyst training project. It reads Linux `auth.log` and
Apache/Nginx access logs, normalizes them into structured events, runs a
small detection engine over them, and reports findings as readable
console alerts, a versioned JSON document, or a queryable SQLite database.

No external dependencies required — the entire tool runs on the Python
standard library.

## 🎯 Objectives

This project exists to demonstrate, hands-on, the core loop of a SOC
analyst's job: **collect → parse → detect → triage → report.** Rather
than just describing detection concepts (brute force, privilege
escalation, web scanning), it implements them as working, tested code
against realistic log samples — and documents *why* each rule fires,
not just that it does.

## ✨ Features

- Parses **Linux `auth.log`** (SSH login attempts, `sudo` activity) and the
  **Apache/Nginx combined access-log format**
- Auto-detects log format per file, or set it explicitly with `--type`
- Accepts **multiple `--file` arguments in one run** (e.g. an `auth.log`
  and an `access.log` together), enabling cross-source correlation
- Six detection rules covering authentication abuse, privilege escalation,
  web recon, and cross-source correlation (full list below) — all
  time-windowed where a window is conceptually meaningful, with regression
  tests for the window boundaries
- Configurable thresholds and time windows for every rule
- **Allow-listing** (`--allow-ip` / `--allow-user` / `--allowlist-file`) to
  suppress alerts from known-good IPs or accounts without touching
  detection thresholds
- **Terminal-safe output**: log-derived text (usernames, IPs, request paths)
  is escaped before it reaches the console, so a crafted log line cannot
  inject ANSI/OSC escape sequences or bidi characters into your terminal
- **Timezone-aware timestamps** (`--tz`, default UTC) with ISO 8601 offsets
- **Robust input handling**: UTF-8 with undecodable bytes replaced, streamed
  line by line, a file-size limit, and bad lines (e.g. `Feb 29` in a
  non-leap year) skipped and counted instead of crashing the run
- **Versioned JSON output** (`--json`) with a documented contract in
  [`docs/OUTPUT_SCHEMA.md`](docs/OUTPUT_SCHEMA.md), plus optional SQLite
  persistence and a `--show-alerts --severity` query mode to inspect a saved
  database without re-parsing a log file
- Zero third-party dependencies for core functionality
- 556-test suite with 98% branch coverage, plus a stdlib-only gate
  (`scripts/gate.py`) that also runs ruff, ruff format and strict mypy
- CI on Windows and Ubuntu × Python 3.11–3.14, CodeQL scanning and Dependabot
  configured (see [`SECURITY.md`](SECURITY.md))

## 🏗️ Architecture

```text
        auth.log / access.log (any number of --file, mixed formats)
                          │
                          ▼
                 ┌─────────────────┐
                 │    parsers.py    │   raw lines → normalized LogEvent objects
                 └────────┬─────────┘   (timezones.py: --tz handling)
                          ▼
                 ┌─────────────────┐
                 │   detectors.py   │   LogEvents → Alert objects (6 rules,
                 └────────┬─────────┘   incl. cross-source correlation)
                          ▼
                 ┌─────────────────┐
                 │   allowlist.py   │   drops alerts matching --allow-ip /
                 └────────┬─────────┘   --allow-user / --allowlist-file
                          ▼
              ┌───────────┴────────────┐
              ▼                        ▼
     ┌─────────────────┐      ┌─────────────────┐
     │   reporting.py   │      │   database.py    │
     │ console / JSON    │      │ SQLite storage   │
     └─────────────────┘      └─────────────────┘
```

`models.py` holds the shared `LogEvent`, `Alert` and `ParseResult`
dataclasses so the parsing, detection, storage, and reporting layers stay
decoupled from each other — you could swap in a new log parser or a new
storage backend without touching the detection logic. Allow-listing runs
strictly *after* detection: every event is still parsed (and still stored
to `--db` if used) so the underlying history stays intact for audit even
when an alert is suppressed from the console/JSON output. `sanitize.py`
escapes log-derived text at the console boundary.

## 🔍 Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Brute Force | ≥5 failed SSH logins from one IP in 5 min | HIGH |
| Possible Compromised Credential | Successful login right after a failure burst from the same IP, within the window | CRITICAL |
| Privilege Escalation Attempt | ≥3 failed `sudo` attempts by one user in 5 min | MEDIUM |
| Web Scanning / Enumeration | ≥10 HTTP 404s from one IP in 2 min | MEDIUM |
| Suspicious Request | Request path matches a sensitive file, a sensitive path prefix, or an injection payload signature | HIGH |
| Recon-to-Intrusion (correlation) | Web recon from an IP is followed by SSH auth activity from that *same* IP within 60 min | CRITICAL |

Full reasoning for each rule (and what the tool deliberately leaves out)
is in [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md).

## 🚀 Installation

Requires Python 3.11+.

```bash
git clone https://github.com/Cosmos0560/soc-log-analyzer.git
cd soc-log-analyzer
# Option 1: run in place, no installation needed
python analyzer.py --help
# Option 2: install the soc-log-analyzer command
pip install .
soc-log-analyzer --help
```

IANA time zone names (`--tz Europe/Berlin`) use the system time zone
database. Windows has none, so there you also need `pip install tzdata`.
`UTC` and fixed offsets such as `+05:30` always work.

## 💻 Usage

```bash
# Auto-detect format, print alerts to the console
python analyzer.py --file examples/sample_auth.log

# Force a format explicitly
python analyzer.py --file access.log --type apache

# Tune detection thresholds
python analyzer.py --file auth.log --failed-threshold 3 --window 10

# Analyze multiple files together in one run -- required for cross-source
# correlation (each file's format is still auto-detected independently)
python analyzer.py --file access.log --file auth.log --correlation-window 30

# auth.log timestamps carry no year or time zone: say which ones they are
python analyzer.py --file auth.log --year 2026 --tz Europe/Berlin

# Refuse files over 20 MB instead of the default 100 MB
python analyzer.py --file huge.log --max-file-mb 20

# Suppress alerts from a known-good IP or account (a monitoring box, a
# vuln scanner, a service account) without touching detection thresholds
python analyzer.py --file auth.log --allow-ip 198.51.100.50 --allow-user healthcheck
python analyzer.py --file auth.log --allowlist-file examples/sample_allowlist.txt

# Get one JSON document for another tool (status messages go to stderr)
python analyzer.py --file auth.log --json

# Persist events + alerts to SQLite for later querying
python analyzer.py --file auth.log --db findings.db

# Query a previously-populated database without re-parsing anything
python analyzer.py --show-alerts --db findings.db
python analyzer.py --show-alerts --db findings.db --severity CRITICAL --json
```

Run `python analyzer.py --help` for the full flag list.

## 📊 Example Output

Running against the included sample (`examples/sample_auth.log`, which
simulates an attacker brute-forcing SSH, guessing `root`'s password, then
attempting privilege escalation as a different account):

```text
$ python analyzer.py --file examples/sample_auth.log --year 2026

[*] Parsed 40 event(s) from examples/sample_auth.log

[!] SECURITY ALERT

Source IP: 203.0.113.7
User: root
Event: Possible Compromised Credential
Preceding Failures: 30
Window Minutes: 5
Time: 2026-08-10 09:06:10+00:00
Severity: CRITICAL
----------------------------------------
[!] SECURITY ALERT

Source IP: 203.0.113.7
Event: Possible Brute Force
Failed Attempts: 5
Window Minutes: 5
Usernames Tried: ['admin', 'oracle', 'root', 'test', 'ubuntu']
Time: 2026-08-10 09:02:32+00:00
Severity: HIGH
----------------------------------------
[!] SECURITY ALERT

User: webapp
Event: Privilege Escalation Attempt
Failed Attempts: 3
Window Minutes: 5
Time: 2026-08-10 09:07:50+00:00
Severity: MEDIUM
----------------------------------------

Summary: 3 alert(s) — CRITICAL: 1, HIGH: 1, MEDIUM: 1
```

A second sample, `examples/sample_apache.log`, simulates a scanner
probing for `.env`, `.git/config`, `wp-login.php`, and a SQL injection
payload — try it with `python analyzer.py --file examples/sample_apache.log`.

A third pair, `examples/sample_recon_apache.log` and
`examples/sample_recon_auth.log`, simulates the same actor first scanning
the web server, then pivoting to a successful SSH brute force 20 minutes
later — run them together to see the Recon-to-Intrusion correlation rule
fire alongside the individual brute-force/scanning alerts:

```bash
python analyzer.py --file examples/sample_recon_apache.log --file examples/sample_recon_auth.log
```

To see allow-listing suppress expected noise, compare running
`examples/sample_apache.log` with and without
`--allowlist-file examples/sample_allowlist.txt` (which allow-lists that
sample's scanner IP) — the alert count drops from 12 to 0.

## 🧾 JSON Output

`--json` prints exactly one JSON document to stdout. It is a versioned
contract (`schema_version` `"1.0"`), and every field is described in
[`docs/OUTPUT_SCHEMA.md`](docs/OUTPUT_SCHEMA.md):

```json
{
  "schema_version": "1.0",
  "tool_version": "1.0.0",
  "kind": "analysis",
  "timezone": "UTC",
  "sources": [
    {"path": "examples/sample_recon_apache.log", "log_type": "apache", "events": 15, "skipped_lines": 0}
  ],
  "summary": {"events": 23, "skipped_lines": 0, "alerts": 14, "suppressed_alerts": 0,
              "by_severity": {"CRITICAL": 2, "HIGH": 11, "MEDIUM": 1, "LOW": 0}},
  "alerts": [
    {"alert_type": "possible_compromised_credential", "severity": "CRITICAL",
     "timestamp": "2026-08-10T14:20:30+00:00", "source_ip": "192.0.2.66", "username": "root",
     "description": "...", "details": {"preceding_failures": 5, "window_minutes": 5}}
  ]
}
```

(Shortened.) `source_ip`, `username`, request paths and file paths are copied
from the logs **unvalidated** — consumers must treat them as untrusted data
(see the Trust section of the schema).

## 🧪 Testing and Development

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Linux/macOS: .venv/bin/python
.venv/Scripts/python scripts/gate.py
```

`scripts/gate.py` (standard library only, same behaviour on Windows and
Linux) runs everything CI runs and stops at the first failure:

- ruff check and ruff format --check
- mypy --strict on `src/`
- pytest with ≥90% branch coverage
- an AST check that `src/` never uses `subprocess`, `eval` or `exec`
- an email and secret scan of every tracked file
- a check that tests, samples and docs only use RFC 5737 documentation IPs
- a CLI smoke test against the sample logs
- a check that the test count in this README is correct

The 556 tests cover:
- parsers: field extraction, malformed and skipped lines, format
  auto-detection, IPv6 sources, BOM and invalid UTF-8, size limits, time zones;
- all six detectors: threshold boundaries, time-window edge cases,
  multi-IP/multi-user independence, true negatives, false-positive regression
  cases, correlation ordering;
- terminal-injection payloads (ANSI CSI, OSC, C1, bidi, line separators) in
  every log-derived field;
- the JSON contract: a golden file, and a check that every emitted field is
  documented;
- the allow-list and the SQLite layer;
- the repository guardrails.

See [`CHANGELOG.md`](CHANGELOG.md) for the specific bugs this suite was built
to catch.

## ⚠️ Limitations

These are limits of the parsing layer. What the *detection* rules
deliberately leave out is covered in
[`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md).

- **Syslog year inference.** auth.log lines carry no year. The tool uses
  `--year`, or the current year in `--tz`, for every line of the file. A log
  that crosses New Year (Dec → Jan) is not detected: its January lines get the
  same year as its December lines and sort *before* them.
- **DST-ambiguous local times.** With an IANA `--tz`, a local time that
  occurs twice (when clocks go back) or not at all (when they go forward)
  resolves with `fold=0`, the first occurrence. Logs written in UTC, or `--tz`
  with a fixed offset, avoid this.
- **Two formats only.** The tool reads Linux auth.log (sshd and sudo lines in
  syslog format) and the Apache/Nginx *combined* access-log format. Other
  formats are not supported: custom `LogFormat` directives, JSON logs, journald
  exports, RFC 5424 syslog, or Windows event logs. Lines in those formats are
  ignored, and a file with none of the two is rejected.

## 🛡️ Security Considerations

- This tool only **reads** log files — it never modifies logs, blocks
  IPs, or takes any response action. It's a detection/analysis aid, not
  an active defense system.
- Log content is attacker-controlled. Console output escapes every control,
  format and separator character, and JSON output is ASCII-only, so neither
  can inject escape sequences into a terminal. Values stored in SQLite and
  returned in JSON are raw, so downstream tools must still treat them as
  untrusted.
- Detection thresholds are heuristics, not ground truth. Every alert
  here would need human triage in a real environment before action is
  taken — that's true of any detection engine, including commercial
  SIEMs.
- The included sample logs are entirely synthetic (hand-written attack
  scenarios with fixed timestamps) and use only RFC 5737 documentation IP
  ranges, as do the tests. No real IP addresses, usernames, or system data
  are included.
- Repository-level controls (secret scanning, push protection, CodeQL,
  Dependabot) are documented in [`SECURITY.md`](SECURITY.md), including
  which of them are repo-setting toggles rather than files.

## 📚 Detection Methodology

See [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md) for the
reasoning behind every rule and threshold, plus an explicit list of what
this tool does *not* attempt to detect (and why).

## 🗺️ Roadmap

- [x] Cross-source correlation (tie a web scan to a later SSH attempt
      from the same actor) — see the Recon-to-Intrusion rule above
- [x] Allow-list for known-good IPs / accounts to suppress expected noise
- [x] Versioned JSON output contract for downstream tools
- [ ] Year-rollover handling for syslog files that cross New Year
- [ ] IP reputation enrichment (AbuseIPDB / VirusTotal lookups)
- [ ] GeoIP tagging on alerts
- [ ] Sigma rule import so detections aren't hardcoded in Python
- [ ] Windows Event Log (EVTX) parser

See [`CHANGELOG.md`](CHANGELOG.md) for what's already shipped, including a
detection-accuracy fix pass with regression tests.

## 🤝 Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
guidelines on adding new parsers, detection rules, or tests.

## 📜 License

MIT — see [`LICENSE`](LICENSE).
