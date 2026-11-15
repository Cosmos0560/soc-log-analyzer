"""Guardrail configuration files: Claude Code settings, ignore and attribute files."""

from __future__ import annotations

import json

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
