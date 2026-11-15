"""Unit tests for .claude/hooks/pre_tool_use.py (rules: CLAUDE.md).

Email-shaped strings are built at runtime from parts; none is written as a literal.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from types import ModuleType

import pytest

from tests.conftest import ROOT

HOOK_PATH = ROOT / ".claude" / "hooks" / "pre_tool_use.py"
GATE = ".venv/Scripts/python scripts/gate.py && "
EMAIL = "".join(["jane", ".", "doe", "@", "example", ".", "com"])
COAUTHOR = "Co-Authored" + "-By: Someone"


def blocked(hook: ModuleType, command: str, tool: str = "Bash") -> bool:
    return hook.evaluate({"tool_name": tool, "tool_input": {"command": command}}) is not None


BLOCKED_BASH = [
    # git push, in every form
    "git push",
    "git push origin main",
    "git push --force",
    "git -C . push",
    "git -c safe.directory=/x push",
    "echo ok && git push",
    "echo ok; git push",
    "bash -c 'git push'",
    'sh -c "git push origin main"',
    "echo $(git push)",
    "env FOO=1 git push",
    "FOO=1 git push",
    "eval 'git push'",
    "/usr/bin/git push",
    "pwsh -Command git push",
    "cmd /c git push",
    "wsl git push",
    # git tag creating or deleting
    "git tag v1",
    "git tag -a v1 -m msg",
    "git tag -am msg v1",
    "git tag -d v1",
    "git tag --delete v1",
    "git tag -s v1",
    # staging everything
    "git add -A",
    "git add --all",
    "git add .",
    "git add *",
    "git add -Av",
    "git add -- .",
    # git identity
    "git config user.name someone",
    "git config --global user.name someone",
    "git config --local user.signingkey abc",
    "git -c user.name=someone status",
    # commit forms
    "git commit -m msg",
    "git commit -am msg",
    "git commit -a -m msg",
    GATE + "git commit -a -m msg",
    GATE + "git commit --all -m msg",
    GATE + "git commit -m '" + COAUTHOR + "'",
    GATE + "git commit -m 'co-authored-by: x'",
    GATE + "git commit -m 'fix " + EMAIL + "'",
    "python scripts/gate.py ; git commit -m msg",
    "python scripts/gate.py || git commit -m msg",
    "python scripts/gate.py && true ; git commit -m msg",
    "python scripts/gate.py | git commit -m msg",
    "git add x && python scripts/gate.py && git commit -m msg",
    "python3 scripts/gate.py && git commit -m msg",
    "./.venv/Scripts/python scripts/gate.py && git commit -m msg",
    # only the Windows project venv is an accepted gate prefix, with no extra flags
    "python scripts/gate.py && git commit -m msg",
    ".venv/bin/python scripts/gate.py && git commit -m msg",
    ".venv/Scripts/python scripts/gate.py --full && git commit -m msg",
    # history rewriting, re-init, direct ref moves
    GATE + "git commit --amend -m msg",
    GATE + "git commit --amend --no-edit",
    "git rebase -i HEAD~2",
    "git rebase main",
    "git filter-branch --tree-filter x HEAD",
    "git filter-repo --path x",
    "git init",
    "git init -b main",
    "git replace HEAD abc",
    "git update-ref refs/heads/main HEAD~1",
    "git update-ref refs/tags/v1 HEAD",
    "git reset --hard HEAD~1",
    # git config writes
    "git config core.autocrlf false",
    "git config --global init.defaultBranch main",
    "git config --unset core.autocrlf",
    "git config --add safe.directory /x",
    "git config set core.autocrlf false",
    "git config -e",
    # graphify: install, integration, network and LLM commands
    "graphify install",
    "graphify install --platform claude",
    "graphify uninstall",
    "graphify claude install",
    "graphify hook install",
    "graphify codex install",
    "graphify clone x",
    "graphify add x",
    "graphify label .",
    "graphify extract .",
    "graphify extract . --code-only --global",
    "graphify cluster-only .",
    "graphify global add graph.json",
    "graphify provider add x",
    "bash -c 'python scripts/gate.py && git commit -m msg'",
    GATE + "echo $(git commit -m msg)",
    # piping the gate
    "python scripts/gate.py | tee out.txt",
    "python scripts/gate.py 2>&1 | tail -5",
    ".venv/Scripts/python scripts/gate.py | cat",
    # docker
    "docker system prune",
    "docker container prune -f",
    "docker stop wordpress",
    "docker logs dvwa",
    "docker exec -it DVWA sh",
    # host port 8080
    "docker run -p 8080:80 nginx",
    "docker run -p 192.0.2.1:8080:80 nginx",
    "python -m http.server 8080",
    "uvicorn app:app --port 8080",
    "uvicorn app:app --port=8080",
    "curl http://localhost:8080/",
    "flask run -p 8080",
    # killing by name
    "taskkill /IM chrome.exe /F",
    "taskkill /im chrome.exe",
    "pkill python",
    "killall node",
    "bash -c 'pkill python'",
    "Get-Process chrome | Stop-Process",
    # WSL distribution
    "wsl --install",
    "wsl --unregister Ubuntu",
    "wsl --set-version Ubuntu 2",
    "wsl --update",
    "wsl sudo apt install x",
    "wsl -d Ubuntu -- apt-get update",
    "wsl -- dpkg -i x.deb",
    "wsl -d Ubuntu -- bash -c 'sudo apt-get install -y python3-venv'",
    # not inspectable
    "powershell -EncodedCommand AAAA",
    "echo 'unterminated",
]

BLOCKED_POWERSHELL = [
    "Stop-Process -Name chrome",
    "Stop-Process -Na chrome",
    "git commit -m msg",
    GATE.replace("&&", ";") + "git commit -m msg",
    "git push",
    "& git push",
    "& 'C:\\Program Files\\Git\\cmd\\git.exe' push",
    "Get-Process chrome | Stop-Process",
    'pwsh -Command "git push"',
]

ALLOWED_BASH = [
    "git status",
    "git log --oneline -5",
    "git log --grep push",
    "git log --grep 'git push'",
    "git diff --cached --stat",
    "git show HEAD:README.md",
    "git tag",
    "git tag -l",
    "git tag -l 'v*'",
    "git tag --list",
    "git tag --contains HEAD",
    "git add src/a.py tests/b.py",
    "git add .gitignore",
    "git add .github/workflows/ci.yml",
    "git add -- src/x.py",
    "git add -u",
    "git config --get user.name",
    "git config core.autocrlf",
    "git config --get core.autocrlf",
    "git config --list",
    "git config get core.autocrlf",
    "git config list",
    "git -c safe.directory=/mnt/c/x status",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/mnt/c/x git status",
    "git log --grep rebase",
    "git log --grep 'reset --hard'",
    "git reset HEAD src/a.py",
    "git show HEAD --stat",
    "git check-ignore -v graphify-out",
    "echo 'git push'",
    'echo "pkill is banned"',
    "grep -rn pkill src",
    "docker ps",
    "docker images",
    "docker run -p 8081:80 nginx",
    "curl http://localhost:18080/",
    "python -m http.server 8000",
    "taskkill /PID 123 /F",
    "kill 123",
    "wsl -l -v",
    "wsl --list --verbose",
    "wsl -d Ubuntu -- python3 -m venv .venv-wsl",
    "wsl -d Ubuntu -- bash -c 'cd /mnt/c/x && .venv-wsl/bin/python scripts/gate.py'",
    "bash -c 'git status'",
    "echo 'h\u00e9llo \u65e5\u672c\u8a9e' && ls",
    "graphify --help",
    "graphify",
    "graphify extract . --code-only",
    "graphify cluster-only . --no-label --no-viz",
    "graphify update .",
    "graphify query 'where are alerts printed'",
    "graphify path cli reporting",
    "graphify explain parse_log_file",
    "graphify affected Alert",
    "graphify god-nodes",
    "python scripts/gate.py",
    "python scripts/gate.py && echo done",
    "python scripts/gate.py 2>&1",
    "python scripts/gate.py || echo failed",
    "ls | head",
    "echo ok # git push in a comment",
    "git add src/a.py && git status",
]

ALLOWED_COMMITS = [
    '.venv/Scripts/python scripts/gate.py && git commit -m "chore: scaffold"',
    '.venv/Scripts/python.exe scripts/gate.py && git commit -m "chore: scaffold"',
    GATE + 'git commit -m "docs: mention git push, pkill and port 8080"',
    GATE + "git commit -m 'fix -a handling'",
    GATE + 'git commit -m "docs: never use --amend or git rebase"',
    GATE + "git commit -m \"$(cat <<'EOF'\nfeat: x\n\ndon't push (yet)\nEOF\n)\"",
]


@pytest.mark.parametrize("command", BLOCKED_BASH)
def test_blocked_bash(hook: ModuleType, command: str) -> None:
    assert blocked(hook, command), command


@pytest.mark.parametrize("command", BLOCKED_POWERSHELL)
def test_blocked_powershell(hook: ModuleType, command: str) -> None:
    assert blocked(hook, command, tool="PowerShell"), command


@pytest.mark.parametrize("command", ALLOWED_BASH)
def test_allowed_bash(hook: ModuleType, command: str) -> None:
    assert not blocked(hook, command), command


@pytest.mark.parametrize("command", ALLOWED_COMMITS)
def test_accepted_gate_prefixes_allow_commit(hook: ModuleType, command: str) -> None:
    assert not blocked(hook, command), command


@pytest.mark.parametrize(
    "command",
    ["Get-ChildItem", "Stop-Process -Id 123", "git status", "git log --grep push"],
)
def test_allowed_powershell(hook: ModuleType, command: str) -> None:
    assert not blocked(hook, command, tool="PowerShell"), command


def test_other_tools_are_not_inspected(hook: ModuleType) -> None:
    assert hook.evaluate({"tool_name": "Read", "tool_input": {"file_path": "x"}}) is None


# ---------------------------------------------------------------- fail closed: shape and main()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "text",
        {},
        {"tool_name": ""},
        {"tool_name": 5},
        {"tool_name": "Bash"},
        {"tool_name": "Bash", "tool_input": []},
        {"tool_name": "Bash", "tool_input": {}},
        {"tool_name": "Bash", "tool_input": {"command": 5}},
        {"tool_name": "PowerShell", "tool_input": {"command": None}},
    ],
)
def test_unknown_shapes_raise(hook: ModuleType, payload: object) -> None:
    with pytest.raises(ValueError):
        hook.evaluate(payload)


def run_main(hook: ModuleType, data: bytes) -> int:
    return int(hook.main(io.BytesIO(data)))


@pytest.mark.parametrize(
    "data",
    [b"", b"not json", b"{", b"\xff\xfe\x00", b"[]", b'{"tool_name": "Bash"}', b"null"],
)
def test_main_fails_closed_on_bad_input(hook: ModuleType, data: bytes) -> None:
    assert run_main(hook, data) == 2


def test_main_fails_closed_on_internal_exception(
    hook: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_payload: object) -> str | None:
        raise RuntimeError("boom")

    monkeypatch.setattr(hook, "evaluate", boom)
    assert (
        run_main(hook, json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}).encode())
        == 2
    )


def test_main_allows_and_blocks(hook: ModuleType) -> None:
    ok = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
    bad = {"tool_name": "Bash", "tool_input": {"command": "git push"}}
    assert run_main(hook, json.dumps(ok).encode()) == 0
    assert run_main(hook, json.dumps(bad).encode()) == 2


def test_main_accepts_utf8_bom(hook: ModuleType) -> None:
    payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
    assert run_main(hook, b"\xef\xbb\xbf" + json.dumps(payload).encode()) == 0


def test_block_message_does_not_echo_the_command(
    hook: ModuleType, capfd: pytest.CaptureFixture[str]
) -> None:
    secret_ish = "git push origin SECRETMARKER"
    payload = {"tool_name": "Bash", "tool_input": {"command": secret_ish}}
    assert run_main(hook, json.dumps(payload).encode()) == 2
    assert "SECRETMARKER" not in capfd.readouterr().err


# ---------------------------------------------------------------- real process, real bytes


def run_hook(stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", str(HOOK_PATH)],
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_process_exit_codes() -> None:
    allow = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}})
    block = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push"}})
    assert run_hook(allow.encode()).returncode == 0
    result = run_hook(block.encode())
    assert result.returncode == 2
    assert b"BLOCKED" in result.stderr


def test_process_bad_json_exits_two_not_one() -> None:
    assert run_hook(b"{ not json").returncode == 2
    assert run_hook(b"").returncode == 2


def test_process_non_ascii_input_is_handled() -> None:
    text = "echo '\u00e9\u00e8 \u65e5\u672c\u8a9e \U0001f600'"
    allow = json.dumps({"tool_name": "Bash", "tool_input": {"command": text}}, ensure_ascii=False)
    assert run_hook(allow.encode("utf-8")).returncode == 0
    escaped = json.dumps({"tool_name": "Bash", "tool_input": {"command": text}})
    assert run_hook(escaped.encode("ascii")).returncode == 0
    block = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "git push \u65e5\u672c"}},
        ensure_ascii=False,
    )
    result = run_hook(block.encode("utf-8"))
    assert result.returncode == 2
    result.stderr.decode("utf-8")  # the reason is valid UTF-8


def test_process_invalid_utf8_exits_two() -> None:
    assert run_hook(b'{"tool_name": "Bash", "tool_input": {"command": "\xff"}}').returncode == 2


# ---------------------------------------------------------------- parser internals


def test_split_segments_tracks_separators(hook: ModuleType) -> None:
    segs = hook.split_segments("a && b; c | d || e\nf")
    assert [s.text for s in segs] == ["a", "b", "c", "d", "e", "f"]
    assert [s.sep_before for s in segs] == ["", "&&", ";", "|", "||", "\n"]


def test_split_segments_keeps_redirects_and_quotes(hook: ModuleType) -> None:
    segs = hook.split_segments("cmd 2>&1 && echo 'a ; b' \"c && d\"")
    assert [s.text for s in segs] == ["cmd 2>&1", "echo 'a ; b' \"c && d\""]


def test_heredoc_body_is_not_parsed_as_commands(hook: ModuleType) -> None:
    segs = hook.split_segments("cat <<'EOF'\ngit push it's\nEOF\necho done")
    assert [s.text for s in segs] == ["cat <<'EOF'", "echo done"]


def test_tokenize_keeps_windows_backslashes(hook: ModuleType) -> None:
    assert hook.tokenize(r'git add "C:\a b\c.py" x') == ["git", "add", r"C:\a b\c.py", "x"]


def test_deep_nesting_is_refused(hook: ModuleType) -> None:
    command = "echo hi"
    for _ in range(10):
        command = "bash -c " + json.dumps(command)
    assert blocked(hook, command)
