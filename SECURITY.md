# Security

## Scope

This is a training/portfolio project. It only **reads** log files and never
takes any active response action (no IP blocking, no account changes). See
[`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md) for what the detection
engine does and does not attempt to catch.

## Untrusted log content

Every field the parsers extract from a log line (usernames, source IPs, request
paths, sudo commands) can be chosen by whoever writes to that log. The tool
handles that content like this:

- **Console**: every control, format and separator character (ANSI/OSC escape
  sequences, C1 controls, bidi overrides and isolates, zero-width characters,
  line separators) is replaced with a visible escape such as `\x1b` before it
  is printed. This also applies to alerts read back from a database.
- **JSON**: the output is ASCII-only, so the raw document cannot inject anything
  into a terminal. After parsing, the values are the original raw strings.
  [`docs/OUTPUT_SCHEMA.md`](docs/OUTPUT_SCHEMA.md) marks which fields are
  log-derived; consumers must treat them as untrusted. In particular,
  `source_ip` is not guaranteed to be a valid IP address.
- **Input files**: they are read as UTF-8 with undecodable bytes replaced,
  streamed line by line after a size check (`--max-file-mb`, default 100 MB;
  1 MB for allow-lists). A malformed line is skipped and counted, never fatal.
- **SQLite**: values are stored raw, through parameterized queries only.

## Repository security settings

The following are enabled via **GitHub repo Settings → Security**, not by
any file in this repo, and should be turned on for this project:

- **Secret scanning** — scans commits for accidentally committed credentials.
- **Push protection** — blocks pushes that contain detectable secrets before
  they ever land in history.
- **Dependabot alerts** — flags known-vulnerable dependencies (config for
  version *updates* is already in [`.github/dependabot.yml`](.github/dependabot.yml);
  alerts are a separate toggle).

Code scanning (CodeQL) is already configured as a workflow —
[`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) — and will
start reporting results under the Security tab once it runs.

## Handling of log data

Never commit real system logs, tokens, API keys, or credentials to this
repository. The sample logs in `examples/` are entirely synthetic —
hand-written attack scenarios with fixed timestamps, so the documented
output is reproducible — and use only IANA-reserved documentation IP ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, per RFC 5737)
specifically so nothing resembling a real address ever appears in this
codebase. The tests follow the same rule, and `scripts/gate.py` fails any
commit that adds another IPv4 literal under `tests/`, `examples/`, `docs/` or
`README.md`.

If you fork this project to run against real logs locally, keep them out of
version control — the `.gitignore` already excludes `*.log` files outside
`examples/` and `*.db` files for exactly this reason.

## Reporting an issue

This is a personal portfolio project without a formal disclosure program.
If you spot a real security issue (as opposed to a detection-accuracy
limitation, which is just a GitHub issue), open a private security advisory
via the repo's Security tab rather than a public issue.
