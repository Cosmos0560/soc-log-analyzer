"""Tests for scripts/gate.py helpers. Key-like and email-shaped strings are built at runtime."""

from __future__ import annotations

from types import ModuleType

import pytest

EMAIL = "".join(["jane", ".", "doe", "@", "example", ".", "com"])
AWS_KEY = "AK" + "IA" + "A" * 16
GH_TOKEN = "gh" + "p_" + "a" * 36
SK_KEY = "sk" + "-" + "a" * 30
PEM = "-----" + "BEGIN RSA PRIVATE" + " KEY" + "-----"


# ---------------------------------------------------------------- LF helper


def test_normalize_lf(gate: ModuleType) -> None:
    assert gate.normalize_lf(b"one\r\ntwo\r\n") == b"one\ntwo\n"
    assert gate.normalize_lf(b"a\rb") == b"a\rb"  # a lone CR is data, not a line ending


# ---------------------------------------------------------------- AST ban


def test_ast_ban_flags_bad_sample(gate: ModuleType) -> None:
    bad = "\n".join(
        [
            "import subprocess",
            "import subprocess as sp",
            "from subprocess import run",
            "import os",
            "import os as o",
            "from os import system",
            "os.system('x')",
            "os.popen('x')",
            "os.execv('x', [])",
            "os.spawnl(0, 'x')",
            "o.system('x')",
            "eval('1')",
            "exec('1')",
            "compile('1', 'f', 'eval')",
            "__import__('x')",
        ]
    )
    problems = gate.check_source(bad, "bad.py")
    # 3 subprocess imports, 1 from-os import, 5 os attribute uses (one via alias), 4 builtins
    assert len(problems) == 13
    text = "\n".join(problems)
    for needle in ("subprocess", "os.system", "os.popen", "os.execv", "os.spawnl", "eval", "exec"):
        assert needle in text


def test_ast_ban_allows_re_compile_and_safe_code(gate: ModuleType) -> None:
    ok = "\n".join(
        [
            "import os",
            "import re",
            "pattern = re.compile('x')",
            "path = os.path.join('a', 'b')",
            "class Thing:",
            "    def compile(self) -> int:",
            "        return 1",
            "Thing().compile()",
        ]
    )
    assert gate.check_source(ok, "ok.py") == []


def test_ast_ban_on_the_real_src_tree(gate: ModuleType) -> None:
    assert gate.check_ast_ban() == []


# ---------------------------------------------------------------- scan patterns


@pytest.mark.parametrize(
    ("text", "name"),
    [
        (f"contact {EMAIL} today", "email address"),
        (f"key = {AWS_KEY}", "aws access key id"),
        (f"token {GH_TOKEN}", "github token"),
        (f"export K={SK_KEY}", "api key (sk- prefix)"),
        (PEM, "private key header"),
    ],
)
def test_scan_catches_runtime_built_strings(gate: ModuleType, text: str, name: str) -> None:
    hits = gate.scan_text("first line\n" + text)
    assert (2, name) in hits


@pytest.mark.parametrize(
    "text",
    [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1",
        "stash@{0} and @pytest.fixture and user@host",
        "a risk-assessment-framework-that-is-long-enough-to-matter",
        "AKIA is a prefix but not a key",
        "plain text",
    ],
)
def test_scan_ignores_near_misses(gate: ModuleType, text: str) -> None:
    assert gate.scan_text(text) == []


def test_scan_never_reports_the_matched_text(gate: ModuleType) -> None:
    hits = gate.scan_text(f"x {AWS_KEY}")
    assert all(AWS_KEY not in repr(hit) for hit in hits)


def test_gate_source_does_not_match_its_own_patterns(gate: ModuleType) -> None:
    source = gate.ROOT.joinpath("scripts", "gate.py").read_text(encoding="utf-8")
    assert gate.scan_text(source) == []


def test_tracked_files_are_clean(gate: ModuleType) -> None:
    assert gate.check_secret_scan() == []


# ---------------------------------------------------------------- RFC 5737 data rule

# Non-documentation addresses are built at runtime so this file passes its own check.
PUBLIC_IP = ".".join(["8"] * 4)
PRIVATE_IP = ".".join(["10", "0", "0", "5"])
LOOPBACK_IP = ".".join(["127", "0", "0", "1"])


def test_documentation_ips_pass(gate: ModuleType) -> None:
    text = "203.0.113.7 and 198.51.100.77, then 192.0.2.66.\nIPv6 2001:db8::1"
    assert gate.non_documentation_ips(text) == []


@pytest.mark.parametrize("addr", [PUBLIC_IP, PRIVATE_IP, LOOPBACK_IP])
def test_non_documentation_ips_are_reported(gate: ModuleType, addr: str) -> None:
    assert gate.non_documentation_ips(f"line one\nfrom {addr} port 22") == [(2, addr)]


def test_version_like_strings_are_not_addresses(gate: ModuleType) -> None:
    assert gate.non_documentation_ips("version 1.2.3, build 999.1.1.1, 1.2.3.4.5") == []


def test_data_paths(gate: ModuleType) -> None:
    for rel in ("tests/test_x.py", "examples/a.log", "docs/X.md", "README.md"):
        assert gate.is_data_path(rel)
    for rel in ("src/soc_analyzer/cli.py", "CHANGELOG.md", "scripts/gate.py"):
        assert not gate.is_data_path(rel)


def test_repo_uses_only_documentation_ips(gate: ModuleType) -> None:
    assert gate.check_documentation_ips() == []


# ---------------------------------------------------------------- graph and hygiene


def test_graph_problems(gate: ModuleType) -> None:
    assert gate.graph_problems(["src/a.py", "graphify-out/graph.json", ".graphifyignore"]) == [
        "graphify file is tracked or staged: graphify-out/graph.json",
        "graphify file is tracked or staged: .graphifyignore",
    ]
    assert gate.graph_problems(["src/a.py", "docs/graphify-out.md"]) == []


def test_graph_files_are_ignored(gate: ModuleType) -> None:
    assert gate.check_graph() == []


def test_hygiene_problems(gate: ModuleType) -> None:
    assert len(gate.hygiene_problems(["AGENTS.md"])) == 1
    assert len(gate.hygiene_problems(["sub/agents.md"])) == 1
    assert len(gate.hygiene_problems([".codex/config.toml"])) == 1
    assert len(gate.hygiene_problems(["a/.codex/x"])) == 1
    assert gate.hygiene_problems(["README.md", "src/codex.py", "docs/agents-notes.md"]) == []


# ---------------------------------------------------------------- CLI smoke and runner


def test_cli_smoke_passes_on_the_real_samples(gate: ModuleType) -> None:
    assert gate.check_cli_smoke() == []


def test_cli_smoke_reports_a_missing_line(gate: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gate, "SMOKE_RUNS", [(["--file", "examples/sample_auth.log"], "no such text")]
    )
    problems = gate.check_cli_smoke()
    assert len(problems) == 1 and "expected" in problems[0]


def test_cli_smoke_reports_a_failing_exit(gate: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "SMOKE_RUNS", [(["--file", "no/such/file.log"], "x")])
    problems = gate.check_cli_smoke()
    assert len(problems) == 1 and "exit code 1" in problems[0]


def test_runner_stops_at_first_failure(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    def failing() -> list[str]:
        calls.append("failing")
        return ["broken"]

    def crashing() -> list[str]:
        raise RuntimeError("boom")

    def never() -> list[str]:
        calls.append("never")
        return []

    monkeypatch.setattr(gate, "CHECKS", [("first", failing), ("second", never)])
    assert gate.main([]) == 1
    assert calls == ["failing"]
    assert "FAILED at: first" in capsys.readouterr().out

    monkeypatch.setattr(gate, "CHECKS", [("crash", crashing)])
    assert gate.main([]) == 1
    assert "check crashed: RuntimeError: boom" in capsys.readouterr().out

    monkeypatch.setattr(gate, "CHECKS", [("ok", never)])
    assert gate.main([]) == 0


def test_gate_accepts_no_flags(gate: ModuleType) -> None:
    with pytest.raises(SystemExit) as exc:
        gate.main(["--skip-tests"])
    assert exc.value.code == 2
