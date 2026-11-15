"""Allow-listing: suppress alerts from known-good IPs / accounts.

Real environments always have expected noise that would otherwise trip the
detectors — an internal vulnerability scanner that hammers the web server,
a monitoring box that fails SSH logins on purpose to test alerting, a
service account that legitimately retries. Rather than raise every
threshold until those go quiet (which also blinds the tool to real
attacks at the same volume), an allow-list lets an analyst say "alerts
from this IP / this account are expected — don't show them" without
touching detection logic or thresholds at all.

Suppression happens AFTER detection, not before parsing or before
detection. Every event is still parsed and can still be stored to
--db for audit purposes; only the resulting alerts are filtered. This
matters: if an allow-listed IP's behavior ever escalates in a way that
would trip a DIFFERENT, unexpected rule, or if the allow-list needs to be
audited later, the underlying event history is still intact.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Alert
from .parsers import check_input_file, iter_text_lines

# An allow-list is a short hand-written file; anything bigger is a mistake.
MAX_ALLOWLIST_BYTES = 1024 * 1024


@dataclass
class AllowList:
    """A set of source IPs and usernames whose alerts should be suppressed.

    An alert is suppressed if EITHER its source_ip is allow-listed OR its
    username is allow-listed — allow-listing an IP is meant to cover every
    account touching it (e.g. a scanner box), and allow-listing a user is
    meant to cover that account regardless of which IP it logs in from.
    """

    ips: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.ips or self.usernames)

    def is_allowed(self, alert: Alert) -> bool:
        ip_allowed = alert.source_ip is not None and alert.source_ip in self.ips
        user_allowed = alert.username is not None and alert.username in self.usernames
        return ip_allowed or user_allowed

    def filter_alerts(self, alerts: list[Alert]) -> tuple[list[Alert], list[Alert]]:
        """Split alerts into (kept, suppressed)."""
        kept: list[Alert] = []
        suppressed: list[Alert] = []
        for a in alerts:
            (suppressed if self.is_allowed(a) else kept).append(a)
        return kept, suppressed


def load_allowlist_file(path: str) -> AllowList:
    """Parse a simple allow-list file.

    Format: one entry per line, ``ip:<value>`` or ``user:<value>``.
    Blank lines and lines starting with ``#`` are ignored. The file is read as
    UTF-8 and may be at most 1 MB. Example::

        # our internal vuln scanner
        ip:198.51.100.50
        ip:2001:db8::5
        # health-check account, retries by design
        user:healthcheck
    """
    check_input_file(path, MAX_ALLOWLIST_BYTES)
    result = AllowList()
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(iter_text_lines(f), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                raise ValueError(
                    f"{path}:{lineno}: expected 'ip:<value>' or 'user:<value>', got {raw.strip()!r}"
                )
            kind, _, value = line.partition(":")
            kind = kind.strip().lower()
            value = value.strip()
            if not value:
                raise ValueError(f"{path}:{lineno}: empty value for {kind!r}")
            if kind == "ip":
                result.ips.add(value)
            elif kind == "user":
                result.usernames.add(value)
            else:
                raise ValueError(
                    f"{path}:{lineno}: unknown entry type {kind!r} (expected 'ip' or 'user')"
                )
    return result


def build_allowlist(
    cli_ips: list[str] | None = None,
    cli_users: list[str] | None = None,
    file_path: str | None = None,
) -> AllowList:
    """Combine allow-list entries from --allow-ip/--allow-user flags and an
    optional --allowlist-file into a single AllowList."""
    allowlist = load_allowlist_file(file_path) if file_path else AllowList()
    allowlist.ips.update(cli_ips or [])
    allowlist.usernames.update(cli_users or [])
    return allowlist
