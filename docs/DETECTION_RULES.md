# Detection Methodology

Every rule below is written to answer a single question a SOC analyst
actually asks when triaging an alert: **"why did this fire, and what does
it mean?"** The thresholds are configurable via CLI flags — the defaults
here reflect reasonable starting points, not hard truths. Real tuning
always depends on your environment's baseline traffic.

## 1. Brute Force (`brute_force`)

**Trigger:** ≥5 failed SSH logins from the same source IP within a 5-minute
sliding window (`--failed-threshold`, `--window`).

**Reasoning:** Legitimate users mistype passwords once or twice, rarely
more, and rarely against multiple different usernames. A sustained burst
of failures — especially against usernames like `root`, `admin`, or
`oracle` that were never valid on the box — is the signature of an
automated credential-stuffing or dictionary attack, not a human.

**Severity:** HIGH.

## 2. Possible Compromised Credential (`possible_compromised_credential`)

**Trigger:** A successful login on an IP where ≥3 failed attempts occurred
within the preceding window (`--window`, `--failed-threshold`).

**Reasoning:** This is the single most important escalation in the whole
tool. A brute force that *fails* is noise. A brute force immediately
followed by a *success* means the attacker likely guessed a valid
password — this is no longer a perimeter event, it's a live compromise
that needs immediate response (disable the account, force a password
reset, check what that session did next).

**Implementation note:** this uses a true sliding window — failures older
than `--window` relative to the success are dropped before the threshold
check runs. An earlier version of this rule accumulated a running failure
count that never expired, which meant a single fresh failure could combine
with unrelated stale failures from hours earlier to falsely reach the
threshold. Tests for this specific scenario live in
`tests/test_detectors.py` (`test_compromised_credential_does_not_combine_stale_and_fresh_failures`).

**Severity:** CRITICAL.

## 3. Privilege Escalation Attempt (`privilege_escalation_attempt`)

**Trigger:** ≥3 failed `sudo` attempts by the same user within a 5-minute
sliding window (`--privesc-threshold`, `--window`).

**Reasoning:** A user hitting "not in sudoers" or a wrong sudo password
repeatedly *in a short burst* is either a confused admin who gives up
quickly, or someone who's landed a foothold on a low-privilege account and
is now trying to escalate. The time window matters here specifically: a
handful of sudo typos scattered across unrelated days is normal
human behavior and should NOT be flagged the same way a rapid burst is.

**Severity:** MEDIUM.

## 4. Web Scanning / Enumeration (`web_scanning`)

**Trigger:** ≥10 HTTP 404 responses to the same IP within a 2-minute
window (`--scan-threshold`, `--scan-window`).

**Reasoning:** Humans browsing a site don't generate ten 404s in two
minutes. Automated content-discovery tools (dirb, gobuster, ffuf, or a
hand-rolled scanner) do exactly this while probing for hidden admin
panels, backup files, or forgotten endpoints.

**Severity:** MEDIUM.

## 5. Suspicious Request (`suspicious_request`)

**Trigger:** one of three independent match strategies, chosen deliberately
per category rather than a single blanket substring search:

- **Sensitive files** (`.env`, `.git/config`, `.aws/credentials`,
  `.ssh/id_rsa`, `config.php`, `wp-login.php`) — matched as a full trailing
  path segment. `/app/.env` matches; a path that merely *contains* those
  characters elsewhere does not.
- **Sensitive path prefixes** (`/admin`, `/administrator`, `/wp-admin`,
  `/phpmyadmin`) — matched as the request path starting with the prefix
  followed by `/` or end-of-string. `/admin/panel` matches; `/administrator`
  is its own separate prefix entry precisely so it's detected on its own
  merits rather than accidentally, and unrelated paths like
  `/my-admin-panel` or `/administrative-tools` do NOT match.
- **Injection payload signatures** (`union select`, `<script`, `' or 1=1`,
  path traversal `../`, etc.) — matched as a substring anywhere in the
  URL-decoded path *and* query string, since these can legitimately appear
  embedded in any parameter. The path is decoded (including treating `+`
  as a space) before matching, so `union+select` and `%27+or+1%3D1` are
  still caught.

**Honest scope:** this is pattern/signature matching against a request
path, not a real SQL-injection or XSS detection engine, and it isn't
marketed as one. It will catch obvious, single-layer-encoded probes and
will miss anything more sophisticated (double encoding, comment-based
obfuscation, blind/time-based injection with no telltale syntax in the
URL). A real detection stack would pair this kind of surface signature
matching with a WAF and actual request/response behavioral analysis.

**Severity:** HIGH.

## 6. Recon-to-Intrusion — Cross-Source Correlation (`recon_to_intrusion`)

**Trigger:** an IP that produced a web-recon alert (rule 4 or rule 5)
is later seen performing SSH authentication activity (`--correlation-window`,
default 60 min) — the SAME `source_ip` in both an access log and an
`auth.log`, in that order.

**Reasoning:** rules 1–5 each look at one log source in isolation. A
single web scan is noise-level common (automated internet-wide scanners
probe everything, unrelated to any specific target); a single SSH brute
force is already handled by rule 1. What genuinely escalates the picture
is the SAME actor doing both, in order: recon first (mapping what's
exposed), then a direct authentication attack against the thing they
found — that's a much stronger signal of deliberate, targeted intent than
either behavior alone. This is why it's the highest severity in the tool.

**Implementation note:** this rule deliberately does *not* re-implement
"what counts as recon." It reuses `detect_web_scanning()` and
`detect_suspicious_paths()` as its recon signal and only adds the
cross-source, cross-time correlation on top — so a threshold change to
either of those rules automatically flows through here too, and there's
only one place that defines "recon" in the codebase. Only the earliest
recon alert and the first qualifying auth event per IP produce an alert
(one correlated incident per actor, not one alert per event pair).

**Requires:** events from both a web access log and an `auth.log` parsed
in the *same run* — pass `--file` more than once
(`--file access.log --file auth.log`). With a single `--file`, this rule
has nothing to correlate against and will not fire.

**Severity:** CRITICAL.

## What this tool intentionally does NOT do

- **No IP reputation / threat intel enrichment** (GeoIP, known-bad-IP
  lists). Deliberately out of scope here to keep this tool dependency-free
  and offline-runnable; that enrichment is a natural next feature.
- **Correlation is IP-based only.** Rule 6 ties events together by an
  exact `source_ip` match. It won't catch an actor who scans from one IP
  and attacks from another (e.g. behind a rotating proxy) — that needs
  actual threat-actor fingerprinting (user-agent, timing patterns, TLS
  fingerprints), which is out of scope for a signature-based tool like
  this one.
- **Not a real SQLi/XSS detection engine** — see the honest-scope note
  under rule 5 above.

## Allow-listing (not a detection rule — a suppression layer)

`--allow-ip`, `--allow-user`, and `--allowlist-file` (see
[`src/soc_analyzer/allowlist.py`](../src/soc_analyzer/allowlist.py)) let
an analyst suppress alerts from known-good IPs or accounts — an internal
vulnerability scanner, a monitoring box that intentionally fails logins
to test alerting, a service account with expected retry behavior — without
touching any detection threshold.

This is deliberately implemented as a **post-detection filter**, not a
pre-parse exclusion: every event is still parsed and still written to
`--db` if used, so the audit trail is complete even for alerts that never
reach the console. Raising a rule's threshold to quiet one noisy IP would
also blind the tool to a real attacker operating at that same volume;
allow-listing avoids that trade-off by naming the specific actor that's
expected, rather than changing what "suspicious" means for everyone.
