# Changelog

## v1.0.0 — 2026-11-15

A hardening release that makes the output safe to read and safe to parse, makes
one bad line non-fatal, and adds development guardrails (a commit gate, CI on
Windows and Linux). It changes the JSON output and the parser API (see "Breaking").

### Security
- **Terminal escape injection fixed.** Usernames, source IPs, request paths and
  other log-derived fields were printed raw. Because the parsers match them
  with `\S+`, a crafted log line could inject ANSI/OSC escape sequences, C1
  controls or bidi characters into the analyst's terminal. Every control,
  format and separator character is now escaped before it reaches the console
  (`soc_analyzer.sanitize`). This covers file paths, error messages, and alerts
  read back from a database. Tests cover ANSI CSI, OSC title and OSC 8
  hyperlink, C1 CSI, NUL, BEL, DEL, CR, LF, TAB, bidi overrides and isolates,
  zero-width space, BOM, and line and paragraph separators in every
  log-derived field.
- stdout and stderr use `errors="backslashreplace"`, so text the console
  encoding cannot represent no longer crashes the run.

### Fixed
- **One bad line no longer kills the run.** An impossible date (`Feb 29` in a
  non-leap year, `31/Feb` in an access log) used to raise and abort. Such lines
  are now skipped and counted; the count is reported on the console and in
  JSON (`skipped_lines`).
- **Timestamps are timezone-aware.**
  - New `--tz` flag (default `UTC`): `UTC`, a fixed offset such as `+05:30`,
    or an IANA name.
  - auth.log times are read in that zone; access-log offsets are honored.
  - All output uses ISO 8601 with an offset.
  - SQLite stores UTC, so ordering is correct.
- **File handling.**
  - Logs and the allow-list are read as UTF-8 with `errors="replace"`, and a
    leading BOM is dropped.
  - Files are streamed instead of read whole with `readlines()`.
  - `--max-file-mb` (default 100) and a 1 MB allow-list cap are checked
    before reading.
  - Missing, unreadable or non-regular files and database errors give a
    clear message and exit code 1 instead of a traceback.
- `--json --db` printed a status line after the JSON on stdout, making it
  invalid JSON. With `--json`, status lines now go to stderr.
- Detectors no longer group events that lack a source IP or username under a
  `None` key.
- `__version__` was out of sync with the packaged version.

### Changed
- **Versioned JSON output contract.**
  - `--json` prints one object: `schema_version` (`"1.0"`), `tool_version`,
    `kind`, `timezone`, `sources`, `summary` and `alerts`.
  - `--show-alerts --json` uses the same envelope with `kind: "stored_alerts"`.
  - Every field is documented in `docs/OUTPUT_SCHEMA.md`, including a Trust
    section on log-derived fields. A golden test and a doc-vs-output test keep
    the two in sync.
- **Python 3.11+** (3.9 and 3.10 are end of life).
  - Modern typing throughout; `Severity` is a `StrEnum`.
  - ruff, ruff format and `mypy --strict` on `src/` are enforced.
- **Data honesty.**
  - Tests and samples use only RFC 5737 documentation addresses: `1.2.3.4`,
    `5.6.7.8`, `8.8.8.8`, `9.9.9.9` and `10.0.0.5` were replaced.
  - A gate check now enforces this.
  - SECURITY.md no longer claims the samples were generated with
    `random.seed(42)`: they are hand-written scenarios.
- **Packaging.**
  - Built with hatchling; adds a `soc-log-analyzer` console script and a
    `py.typed` marker.
  - Dev tools are in the `dev` extra; `requirements.txt` was removed.

### Breaking
- `--json` output shape: an object instead of a bare list of alerts.
- `parse_auth_log`, `parse_apache_log` and `parse_log_file` return a
  `ParseResult` (`.events`, `.skipped_lines`, `.log_type`) instead of a list.
- `reporting.alerts_to_json` is replaced by `analysis_document` /
  `stored_alerts_document` plus `to_json`.
- Python 3.9 and 3.10 are no longer supported.

### Tooling
- `scripts/gate.py` (stdlib only, Windows and Linux) runs on every commit and
  in CI. It runs:
  - ruff and ruff format;
  - mypy;
  - pytest with at least 90% branch coverage;
  - an AST ban on execution primitives in `src/`;
  - an email/secret scan;
  - the RFC 5737 check;
  - the CLI smoke test;
  - a README test-count check.
- CI: Windows and Ubuntu × Python 3.11–3.14, `permissions: contents: read`,
  actions pinned by commit SHA. CodeQL actions are pinned too; Dependabot
  covers pip and GitHub Actions.
- Claude Code guardrails: `CLAUDE.md`, a fail-closed PreToolUse hook with
  tests, and `.gitattributes` forcing LF.
- LICENSE copyright holder and repository links updated.

## v0.2.0 — Cross-source correlation and allow-listing

### Added
- **`detect_recon_to_intrusion`**: a sixth detection rule, and the first
  one that reasons across log sources. Flags an IP whose web recon
  (matched via the existing `detect_web_scanning` / `detect_suspicious_paths`
  rules) is followed by SSH authentication activity from that same IP
  within `--correlation-window` minutes (default 60). Severity CRITICAL —
  see `docs/DETECTION_RULES.md` rule 6 for the full reasoning.
- **`--file` is now repeatable** (`--file access.log --file auth.log`),
  required for the correlation rule above to have more than one source to
  correlate. Each file's format is still auto-detected independently.
  Single-`--file` usage is fully backward compatible and unaffected.
- **Allow-listing**: `--allow-ip`, `--allow-user`, and `--allowlist-file`
  suppress alerts from known-good IPs/accounts as a post-detection filter
  (events are still parsed and still persisted to `--db`; only the
  console/JSON/stored alert output is filtered). New `allowlist.py`
  module; see `docs/DETECTION_RULES.md` for the design rationale.
- Two new example files (`examples/sample_recon_apache.log` +
  `examples/sample_recon_auth.log`) demonstrating a scan-then-attack
  scenario for the correlation rule, plus `examples/sample_allowlist.txt`
  demonstrating the allow-list file format.
- 20 additional tests: 7 for `detect_recon_to_intrusion` (ordering,
  window boundaries, multi-source requirement, one-alert-per-IP dedup)
  and 13 for the allow-list (IP/user suppression, combined-source
  behavior, file-format parsing and error handling).

### Changed
- `run_all_detectors()` gained a `correlation_window` parameter
  (default 60) and now also runs `detect_recon_to_intrusion`.
- Console output for a suppressed run now reports how many alerts were
  suppressed by the allow-list, so suppression is visible rather than
  silent.

## v0.1.1 — Detection accuracy and security hardening pass

A round of review turned up real issues in the initial v0.1.0 detection
logic. Fixed here, with regression tests for each:

### Fixed
- **`detect_compromised_credential`**: replaced an unbounded running
  failure counter with a true sliding window. Previously, a failure from
  hours earlier could combine with a single fresh failure to falsely reach
  the alert threshold, inflating the reported `preceding_failures` count.
- **`detect_privilege_escalation`**: added the same sliding-window logic
  used by brute-force detection. Previously this rule had no time bound at
  all, so sudo failures spread across weeks could trigger a false alert.
- **`--window` CLI flag**: now actually governs privilege-escalation
  detection as its help text claims (previously only brute-force and
  compromised-credential detection received it).
- **Suspicious-path false positives**: `SUSPICIOUS_PATH_PATTERNS` used raw
  substring matching, so `/admin` matched unrelated paths like
  `/administrative-tools`. Replaced with three explicit matching strategies
  (sensitive-file suffix, path-prefix, injection-payload substring) — see
  `docs/DETECTION_RULES.md` rule 5.
- **Dead pattern entries**: `select+*+from` and `%2e%2e%2f` could never
  match post-decoding once the path normalization step was added; replaced
  with working equivalents (`select * from`, `../`).
- **`LogEvent.extra`** (e.g. sudo command/reason text) was parsed but never
  persisted — SQLite schema now has an `extra` column (JSON-encoded).

### Added
- `--show-alerts` / `--severity` CLI flags to query a previously-populated
  `--db` without re-parsing a log file.
- `permissions: contents: read` on the CI workflow (least-privilege).
- CodeQL security-scanning workflow and Dependabot config.
- `SECURITY.md` documenting which security controls are repo-setting
  toggles (secret scanning, push protection) vs. files in this repo.
- 22 additional tests: window-boundary cases, multi-IP/multi-user
  independence, empty-input handling, IPv6 source addresses, malformed
  log lines, and the specific false-positive/stale-window scenarios above.

### Changed
- Parser docs now specify the *combined* Apache/Nginx access-log format
  precisely, rather than "Apache/Nginx logs" generally.
