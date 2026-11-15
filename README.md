# 🛡️ SOC Log Analyzer

A Python-based security log parsing and rule-based threat detection tool,
built as a SOC analyst training project. It reads Linux `auth.log` and
Apache/Nginx access logs, normalizes them into structured events, runs a
small detection engine over them, and reports findings as readable
console alerts, JSON, or a queryable SQLite database.

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
- Console output with severity color-coding, JSON output for scripting,
  and optional SQLite persistence — including a `--show-alerts --severity`
  query mode to inspect a saved database without re-parsing a log file
- Zero third-party dependencies for core functionality
- 60-test suite covering parsers, detectors, the allow-list, and the
  database layer independently, including false-positive and stale-data
  edge cases
- CodeQL scanning and Dependabot configured (see [`SECURITY.md`](SECURITY.md))

## 🏗️ Architecture

```text
        auth.log / access.log (any number of --file, mixed formats)
                          │
                          ▼
                 ┌─────────────────┐
                 │    parsers.py    │   raw lines → normalized LogEvent objects
                 └────────┬─────────┘
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

`models.py` holds the shared `LogEvent` and `Alert` dataclasses so the
parsing, detection, storage, and reporting layers stay decoupled from
each other — you could swap in a new log parser or a new storage backend
without touching the detection logic. Allow-listing runs strictly *after*
detection: every event is still parsed (and still stored to `--db` if
used) so the underlying history stays intact for audit even when an
alert is suppressed from the console/JSON output.

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

```bash
git clone https://github.com/<your-username>/soc-log-analyzer.git
cd soc-log-analyzer
# no dependencies needed to run the tool itself
pip install -r requirements.txt  # only needed to run the test suite
```

Requires Python 3.9+.

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

# Suppress alerts from a known-good IP or account (a monitoring box, a
# vuln scanner, a service account) without touching detection thresholds
python analyzer.py --file auth.log --allow-ip 198.51.100.50 --allow-user healthcheck
python analyzer.py --file auth.log --allowlist-file examples/sample_allowlist.txt

# Get JSON for piping into another tool
python analyzer.py --file auth.log --json

# Persist events + alerts to SQLite for later querying
python analyzer.py --file auth.log --db findings.db

# Query a previously-populated database without re-parsing anything
python analyzer.py --show-alerts --db findings.db
python analyzer.py --show-alerts --db findings.db --severity CRITICAL
```

Run `python analyzer.py --help` for the full flag list.

## 📊 Example Output

Running against the included sample (`examples/sample_auth.log`, which
simulates an attacker brute-forcing SSH, guessing `root`'s password, then
attempting privilege escalation as a different account):

```text
$ python analyzer.py --file examples/sample_auth.log

[*] Parsed 40 event(s) from examples/sample_auth.log

[!] SECURITY ALERT

Source IP: 203.0.113.7
User: root
Event: Possible Compromised Credential
Preceding Failures: 30
Window Minutes: 5
Time: 2026-08-10 09:06:10
Severity: CRITICAL
----------------------------------------
[!] SECURITY ALERT

Source IP: 203.0.113.7
Event: Possible Brute Force
Failed Attempts: 5
Window Minutes: 5
Usernames Tried: ['admin', 'oracle', 'root', 'test', 'ubuntu']
Time: 2026-08-10 09:02:32
Severity: HIGH
----------------------------------------
[!] SECURITY ALERT

User: webapp
Event: Privilege Escalation Attempt
Failed Attempts: 3
Window Minutes: 5
Time: 2026-08-10 09:07:50
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

## 🧪 Testing

```bash
pip install -r requirements.txt
pytest -v
```

60 tests cover parsers (correct field extraction, malformed-line handling,
format auto-detection, IPv6 sources), all six detectors (threshold
boundaries, time-window edge cases, multi-IP/multi-user independence, true
negatives, false-positive regression cases, correlation ordering), the
allow-list (IP/user suppression, file parsing, malformed-input errors),
and the SQLite layer (round-tripping every field including `extra`,
severity filtering). See [`CHANGELOG.md`](CHANGELOG.md) for the specific
bugs this suite was built to catch.

## 🛡️ Security Considerations

- This tool only **reads** log files — it never modifies logs, blocks
  IPs, or takes any response action. It's a detection/analysis aid, not
  an active defense system.
- Detection thresholds are heuristics, not ground truth. Every alert
  here would need human triage in a real environment before action is
  taken — that's true of any detection engine, including commercial
  SIEMs.
- The included sample logs are entirely synthetic (generated for this
  repo, seeded for reproducibility) and use RFC 5737 documentation IP
  ranges. No real IP addresses, usernames, or system data are included.
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
