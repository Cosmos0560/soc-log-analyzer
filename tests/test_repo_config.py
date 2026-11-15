"""Guardrail configuration files: Claude Code settings, ignore and attribute files."""

from __future__ import annotations

import json
import re

from tests.conftest import ROOT


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_settings_hook_registration() -> None:
    settings = json.loads(read(".claude/settings.json"))
    entries = settings["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["matcher"] == "Bash|PowerShell"
    command = entries[0]["hooks"][0]["command"]
    assert "pre_tool_use.py" in command
    assert command.endswith("|| exit 2")  # a crash (exit 1) must still block
    assert (ROOT / ".claude" / "hooks" / "pre_tool_use.py").is_file()


def test_settings_attribution_disabled_and_push_tag_denied() -> None:
    settings = json.loads(read(".claude/settings.json"))
    assert settings["attribution"]["commit"] == ""
    assert settings["attribution"]["pr"] == ""
    deny = set(settings["permissions"]["deny"])
    for tool in ("Bash", "PowerShell"):
        for verb in ("push", "tag"):
            assert f"{tool}(git {verb})" in deny
            assert f"{tool}(git {verb} *)" in deny


def test_gitattributes_forces_lf() -> None:
    assert read(".gitattributes").strip() == "* text=auto eol=lf"


def test_gitignore_covers_required_paths() -> None:
    lines = set(read(".gitignore").splitlines())
    for entry in (".venv/", ".venv-wsl/", ".venv-release/", "build/", "dist/", "*.egg-info/",
                  "graphify-out/", ".graphifyignore", "*.db"):  # fmt: skip
        assert entry in lines


def test_pyproject_guardrails() -> None:
    import tomllib

    data = tomllib.loads(read("pyproject.toml"))
    assert data["project"]["requires-python"] == ">=3.11"
    assert data["project"]["dependencies"] == []  # the tool itself is stdlib-only
    assert {"pytest", "pytest-cov", "ruff", "mypy", "tzdata"} <= set(
        data["project"]["optional-dependencies"]["dev"]
    )
    assert data["tool"]["ruff"]["target-version"] == "py311"
    assert data["tool"]["ruff"]["extend-exclude"] == [".venv-wsl", ".venv-release"]
    assert data["tool"]["mypy"] == {"strict": True, "files": ["src"], "python_version": "3.11"}
    assert data["tool"]["coverage"]["run"] == {"source": ["soc_analyzer"], "branch": True}
    assert (ROOT / "src" / "soc_analyzer" / "py.typed").is_file()


def test_ci_workflow() -> None:
    ci = read(".github/workflows/ci.yml")
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1" in ci
    assert "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0" in ci
    assert re.search(r"^permissions:\n  contents: read$", ci, re.MULTILINE)
    assert "os: [windows-latest, ubuntu-latest]" in ci
    assert 'python-version: ["3.11", "3.12", "3.13", "3.14"]' in ci
    assert 'pip install -e ".[dev]"' in ci
    assert "run: python scripts/gate.py" in ci
    assert "soc-log-analyzer --file examples/sample_auth.log" in ci  # installed entry point
    for forbidden in ("secrets.", "pull_request_target", "upload-artifact", "write"):
        assert forbidden not in ci
    uses = re.findall(r"uses:\s*(\S+)", ci)
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses)
    assert not (ROOT / ".github" / "workflows" / "tests.yml").exists()


def test_codeql_workflow() -> None:
    codeql = read(".github/workflows/codeql.yml")
    sha = "33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3"
    assert f"github/codeql-action/init@{sha}" in codeql
    assert f"github/codeql-action/analyze@{sha}" in codeql
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1" in codeql
    assert re.search(r"^permissions:\n  contents: read$", codeql, re.MULTILINE)
    assert "      security-events: write" in codeql  # job level only
    uses = re.findall(r"uses:\s*(\S+)", codeql)
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses)


def test_dependabot_covers_pip_and_actions() -> None:
    dependabot = read(".github/dependabot.yml")
    assert 'package-ecosystem: "pip"' in dependabot
    assert 'package-ecosystem: "github-actions"' in dependabot


def test_license_and_metadata() -> None:
    text = read("LICENSE")
    assert text.startswith("MIT License")
    assert "Copyright (c) 2026 Otabek Yakubov\n" in text
    for doc in ("README.md", "CONTRIBUTING.md"):
        content = read(doc)
        assert "<your-username>" not in content
        assert "github.com/Cosmos0560/soc-log-analyzer" in content


def test_changelog_has_the_release() -> None:
    from soc_analyzer import __version__

    assert __version__ == "1.0.0"
    first_heading = next(
        line for line in read("CHANGELOG.md").splitlines() if line.startswith("## ")
    )
    assert re.fullmatch(r"## v1\.0\.0 — \d{4}-\d{2}-\d{2}", first_heading)
