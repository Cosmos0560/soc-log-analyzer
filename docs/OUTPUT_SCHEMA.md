# JSON output schema

`--json` prints exactly one JSON document to stdout. This document is a public contract:
other tools (for example ai-security-assistant) parse it. This page describes every field.
`tests/test_output_schema.py` fails if the tool emits a field that is not listed here, or
if this page lists a field the tool no longer emits.

Current version: **`schema_version` `"1.0"`**.

## Trust: log-derived fields are untrusted data

Several fields are copied straight from the log files. The tool does **not** validate
them, and anyone who can write to a log can choose their content:

- `alerts[].source_ip` is whatever the parser's `\S+` matched in the "from ..." part of
  an auth.log line or the first field of an access-log line. It is usually an IPv4 or
  IPv6 address, but **it is not guaranteed to be a valid IP address**. It can be any run
  of non-whitespace characters, including control characters.
- `alerts[].username` is the `\S+` user field of an sshd or sudo line.
- `alerts[].details` values that come from the log: `details.path` (the raw request path
  and query string), `details.method`, and the entries of `details.usernames_tried`.
- `sources[].path` is the file path exactly as it was given on the command line.

Consumers must treat these values as **untrusted input**:

- never execute or evaluate them;
- never splice them into prompts, shell commands, SQL or HTML without escaping for that
  context;
- never print them raw to a terminal.

The JSON itself is safe to view, because the output is ASCII-only: every control
character and every non-ASCII character in a string is written as a JSON Unicode escape
(a backslash, `u`, then four hex digits). After `json.loads` the original characters,
including any ESC or bidi-override characters, are back in the strings.

All other fields (`alert_type`, `severity`, `description`, counts, timestamps, the
remaining `details` keys) are produced by the tool itself.

## Two document kinds

| `kind` | Produced by | Contents |
|---|---|---|
| `"analysis"` | `--file ... --json` | Sources, summary and alerts of one run |
| `"stored_alerts"` | `--show-alerts --db F --json` | Alerts read back from a SQLite database |

## Fields

"Both" means the field appears in both document kinds.

| Field | Type | Kind | Meaning |
|---|---|---|---|
| `schema_version` | string | both | Contract version, `"MAJOR.MINOR"`. See [Versioning](#versioning). |
| `tool_version` | string | both | soc-log-analyzer version that produced the document. |
| `kind` | string | both | `"analysis"` or `"stored_alerts"`. |
| `timezone` | string | analysis | The `--tz` zone every timestamp is expressed in: `"UTC"`, a fixed offset such as `"+05:30"`, or an IANA name such as `"Europe/Berlin"`. |
| `sources` | array | analysis | One entry per `--file`, in command-line order. |
| `sources[].path` | string | analysis | The path as given on the command line. Untrusted. |
| `sources[].log_type` | string | analysis | `"auth"` or `"apache"` (auto-detected or forced with `--type`). |
| `sources[].events` | integer | analysis | Events parsed from this file. |
| `sources[].skipped_lines` | integer | analysis | Lines that matched a known format but could not be parsed (for example `Feb 29` in a non-leap year). Lines that match no known format are ignored and not counted. |
| `summary` | object | both | Totals. |
| `summary.events` | integer | analysis | Sum of `sources[].events`. |
| `summary.skipped_lines` | integer | analysis | Sum of `sources[].skipped_lines`. |
| `summary.alerts` | integer | both | Number of entries in `alerts`. |
| `summary.suppressed_alerts` | integer | analysis | Alerts removed by the allow-list (`--allow-ip`, `--allow-user`, `--allowlist-file`). They are not in `alerts`. |
| `summary.by_severity` | object | both | Alert count per severity. All four keys are always present, in this order. |
| `summary.by_severity.CRITICAL` | integer | both | |
| `summary.by_severity.HIGH` | integer | both | |
| `summary.by_severity.MEDIUM` | integer | both | |
| `summary.by_severity.LOW` | integer | both | No rule emits LOW in 1.0; reserved, always present. |
| `alerts` | array | both | Alerts, highest severity first, then newest first. |
| `alerts[].id` | integer | stored_alerts | Row id in the database. |
| `alerts[].alert_type` | string | both | One of the six types in [Alert details by type](#alert-details-by-type). |
| `alerts[].severity` | string | both | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"` or `"LOW"`. |
| `alerts[].description` | string | both | Fixed human-readable sentence per rule. For `suspicious_request` it names the matched pattern. |
| `alerts[].timestamp` | string | both | ISO 8601 with offset, for example `"2026-08-10T09:06:10+00:00"`. See [Timestamps](#timestamps). |
| `alerts[].source_ip` | string or null | both | Untrusted. `null` when the rule has no source address (see below). |
| `alerts[].username` | string or null | both | Untrusted. `null` when the rule has no user (see below). |
| `alerts[].details` | object | both | Rule-specific fields. Keys depend on `alert_type`. |

### Null rules

| `alert_type` | `source_ip` | `username` |
|---|---|---|
| `brute_force` | set | `null` |
| `possible_compromised_credential` | set | set |
| `privilege_escalation_attempt` | `null` | set |
| `web_scanning` | set | `null` |
| `suspicious_request` | set | `null` |
| `recon_to_intrusion` | set | set |

## Alert details by type

Every key listed for a type is always present for that type.

### `brute_force`

| Key | Type | Meaning |
|---|---|---|
| `failed_attempts` | integer | Failed logins from `source_ip` inside the window when the threshold was reached. |
| `window_minutes` | integer | The `--window` value. |
| `usernames_tried` | array of strings | Distinct usernames in that window, sorted, at most 10. Untrusted. |

### `possible_compromised_credential`

| Key | Type | Meaning |
|---|---|---|
| `preceding_failures` | integer | Failures from the same IP inside the window before the successful login. |
| `window_minutes` | integer | The `--window` value. |

### `privilege_escalation_attempt`

| Key | Type | Meaning |
|---|---|---|
| `failed_attempts` | integer | Failed sudo attempts by `username` inside the window. |
| `window_minutes` | integer | The `--window` value. |

### `web_scanning`

| Key | Type | Meaning |
|---|---|---|
| `requests_404` | integer | 404 responses to `source_ip` inside the window. |
| `window_minutes` | integer | The `--scan-window` value. |

### `suspicious_request`

| Key | Type | Meaning |
|---|---|---|
| `path` | string | The raw request path including the query string. Untrusted. |
| `method` | string | The HTTP method (`[A-Z]+` from the log). Untrusted. |
| `status` | integer | The HTTP status code. |

### `recon_to_intrusion`

| Key | Type | Meaning |
|---|---|---|
| `recon_alert_type` | string | `"web_scanning"` or `"suspicious_request"`: the earliest recon alert for this IP. |
| `recon_first_seen` | string | Timestamp of that recon alert, ISO 8601 with offset. |
| `auth_activity_type` | string | `"failed_login"`, `"invalid_user"` or `"accepted_login"`. |
| `minutes_between` | number | Minutes from the recon alert to the auth event, one decimal place. |
| `correlation_window_minutes` | integer | The `--correlation-window` value. |

## Timestamps

- **analysis**: every timestamp (`alerts[].timestamp`, `details.recon_first_seen`) is
  ISO 8601 with an offset, expressed in the `--tz` zone named by `timezone`.
  - auth.log lines carry no zone, so they are interpreted in `--tz`.
  - Access-log lines carry their own offset, which is honored and then converted.
- **stored_alerts**: `alerts[].timestamp` is the stored text.
  - Databases written by 1.0 store UTC (`+00:00`).
  - Databases written by 0.x store a naive timestamp with no offset.

## stdout, stderr and exit codes

- With `--json`, stdout holds exactly one document and nothing else. Status messages
  (skipped lines, "saved to database", errors) go to stderr.
- Exit code `0`: the document was printed. Exit code `1`: an input error (unreadable,
  oversized or unrecognized file, bad allow-list, database error), and no document is
  printed. Exit code `2`: a command-line usage error.
- An analysis with no alerts is still exit code `0`, with `"alerts": []`.
- The output is deterministic: the same input and options give byte-identical output.
  It contains no generation time.

## Versioning

`schema_version` is `"MAJOR.MINOR"`.

- **MINOR** bumps only add fields (a new top-level field, a new `details` key, a new
  `alert_type`). Consumers must ignore fields they do not know.
- **MAJOR** bumps remove or rename a field, change its type, or change its meaning.
  Consumers should check the major version and refuse a major version they do not know.

Changes are listed in [`CHANGELOG.md`](../CHANGELOG.md).
