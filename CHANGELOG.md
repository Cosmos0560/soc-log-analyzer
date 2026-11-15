# Changelog

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
