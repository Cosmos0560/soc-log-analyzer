"""The JSON output contract: golden output, documented fields, envelope details.

Regenerate the golden file after an intended output change (then review the diff):

    python analyzer.py --file examples/sample_auth.log --file examples/sample_apache.log \
        --file examples/sample_recon_apache.log --file examples/sample_recon_auth.log \
        --year 2026 --tz UTC --json

and save stdout with LF line endings to tests/golden/analysis_all_samples.json.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from soc_analyzer import __version__, cli
from soc_analyzer.reporting import SCHEMA_VERSION
from tests.conftest import ROOT

GOLDEN = ROOT / "tests" / "golden" / "analysis_all_samples.json"
SCHEMA_DOC = ROOT / "docs" / "OUTPUT_SCHEMA.md"
ALL_SAMPLES = [
    "--file", "examples/sample_auth.log",
    "--file", "examples/sample_apache.log",
    "--file", "examples/sample_recon_apache.log",
    "--file", "examples/sample_recon_auth.log",
]  # fmt: skip
GOLDEN_ARGS = [*ALL_SAMPLES, "--year", "2026", "--tz", "UTC", "--json"]


def normalize_lf(text: str) -> str:
    return text.replace("\r\n", "\n")


@pytest.fixture
def in_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)  # sources[].path echoes the relative paths


def run_json(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[str, dict[str, Any]]:
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    return out, json.loads(out)


# ---------------------------------------------------------------- golden


@pytest.mark.usefixtures("in_root")
def test_golden_output(capsys: pytest.CaptureFixture[str]) -> None:
    out, _ = run_json(GOLDEN_ARGS, capsys)
    expected = normalize_lf(GOLDEN.read_bytes().decode("utf-8"))
    assert normalize_lf(out) == expected


def test_golden_covers_every_alert_type() -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert {a["alert_type"] for a in golden["alerts"]} == {
        "brute_force",
        "possible_compromised_credential",
        "privilege_escalation_attempt",
        "web_scanning",
        "suspicious_request",
        "recon_to_intrusion",
    }


def test_envelope_versions() -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["schema_version"] == SCHEMA_VERSION == "1.0"
    assert golden["tool_version"] == __version__
    assert golden["kind"] == "analysis"


@pytest.mark.usefixtures("in_root")
def test_output_is_ascii_and_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    first, _ = run_json(GOLDEN_ARGS, capsys)
    second, _ = run_json(GOLDEN_ARGS, capsys)
    assert first == second
    assert first.isascii()


# ---------------------------------------------------------------- envelope behaviour


@pytest.mark.usefixtures("in_root")
def test_tz_offset_in_every_timestamp(capsys: pytest.CaptureFixture[str]) -> None:
    _, doc = run_json([*ALL_SAMPLES, "--year", "2026", "--tz", "+05:30", "--json"], capsys)
    assert doc["timezone"] == "+05:30"
    stamps = [a["timestamp"] for a in doc["alerts"]]
    stamps += [a["details"]["recon_first_seen"] for a in doc["alerts"] if "recon_first_seen" in a["details"]]
    assert stamps and all(s.endswith("+05:30") for s in stamps)


@pytest.mark.usefixtures("in_root")
def test_suppressed_alerts_are_counted(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["--file", "examples/sample_apache.log", "--json",
            "--allowlist-file", "examples/sample_allowlist.txt"]  # fmt: skip
    _, doc = run_json(argv, capsys)
    assert doc["alerts"] == []
    assert doc["summary"]["alerts"] == 0
    assert doc["summary"]["suppressed_alerts"] == 12
    assert doc["summary"]["by_severity"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_skipped_lines_in_sources_and_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    line = "{} 09:00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
    log = tmp_path / "auth.log"
    log.write_text("\n".join([line.format("Aug 10"), line.format("Feb 29")]) + "\n", "utf-8")
    _, doc = run_json(["--file", str(log), "--year", "2026", "--json"], capsys)
    assert doc["sources"] == [
        {"path": str(log), "log_type": "auth", "events": 1, "skipped_lines": 1}
    ]
    assert doc["summary"]["events"] == 1 and doc["summary"]["skipped_lines"] == 1


@pytest.mark.usefixtures("in_root")
def test_json_with_db_keeps_stdout_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main([*GOLDEN_ARGS, "--db", str(tmp_path / "x.db")]) == 0
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert "Saved" in captured.err


@pytest.mark.usefixtures("in_root")
def test_stored_alerts_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "s.db")
    _, analysis = run_json([*GOLDEN_ARGS, "--db", db], capsys)
    capsys.readouterr()
    _, stored = run_json(["--show-alerts", "--db", db, "--json"], capsys)
    assert stored["schema_version"] == "1.0" and stored["kind"] == "stored_alerts"
    assert stored["summary"] == {
        "alerts": analysis["summary"]["alerts"],
        "by_severity": analysis["summary"]["by_severity"],
    }
    assert sorted(a["id"] for a in stored["alerts"]) == list(range(1, len(stored["alerts"]) + 1))
    assert all(isinstance(a["details"], dict) for a in stored["alerts"])
    assert all(a["timestamp"].endswith("+00:00") for a in stored["alerts"])


# ---------------------------------------------------------------- the schema document


def field_paths(value: Any, prefix: str = "") -> set[str]:
    """Dotted paths of every key; lists add ``[]``. ``details`` is documented per type."""
    paths: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = prefix + key
            paths.add(path)
            if key == "details":
                continue
            if isinstance(child, dict):
                paths |= field_paths(child, path + ".")
            elif isinstance(child, list):
                for item in child:
                    paths |= field_paths(item, path + "[].")
    return paths


def documented_fields() -> tuple[set[str], dict[str, set[str]]]:
    """(paths from the field tables, {alert_type: detail keys}) parsed from the doc."""
    text = SCHEMA_DOC.read_text(encoding="utf-8")
    fields = text.split("\n## Fields\n", 1)[1].split("\n### Null rules", 1)[0]
    details = text.split("\n## Alert details by type\n", 1)[1].split("\n## ", 1)[0]
    row = re.compile(r"^\| `([^`]+)` \|", re.MULTILINE)
    paths = set(row.findall(fields))
    per_type: dict[str, set[str]] = {}
    for block in details.split("### ")[1:]:
        heading, _, body = block.partition("\n")
        per_type[heading.strip().strip("`")] = set(row.findall(body))
    return paths, per_type


@pytest.mark.usefixtures("in_root")
def test_every_emitted_field_is_documented_and_vice_versa(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = str(tmp_path / "d.db")
    _, analysis = run_json([*GOLDEN_ARGS, "--db", db], capsys)
    capsys.readouterr()
    _, stored = run_json(["--show-alerts", "--db", db, "--json"], capsys)
    emitted = field_paths(analysis) | field_paths(stored)
    documented, _ = documented_fields()
    assert emitted - documented == set(), "emitted but not documented"
    assert documented - emitted == set(), "documented but never emitted"


def test_detail_keys_per_alert_type_match_the_doc() -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    emitted: dict[str, set[str]] = defaultdict(set)
    for alert in golden["alerts"]:
        emitted[alert["alert_type"]] |= set(alert["details"])
    _, documented = documented_fields()
    assert documented == dict(emitted)


def test_doc_has_the_trust_section() -> None:
    text = SCHEMA_DOC.read_text(encoding="utf-8")
    trust = text.split("## Trust", 1)[1].split("\n## ", 1)[0]
    for needle in ("source_ip", "username", "details.path", "sources[].path", "untrusted",
                   "not guaranteed to be a valid IP address"):  # fmt: skip
        assert needle in trust
