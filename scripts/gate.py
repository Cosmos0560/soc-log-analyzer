#!/usr/bin/env python3
"""Project gate: every commit goes through this script (see CLAUDE.md).

Stdlib only. No shell pipes. Same behaviour on Windows and in WSL.
Prints one line per check and exits non-zero on the first failing group.

The gate grows with the project: a check is added in the commit that creates what it
checks, and there is no "skip if file missing" logic. The scan patterns are assembled at
runtime from parts, so this file never matches itself. Byte-exact comparisons go through
``normalize_lf`` because Windows checkouts may use CRLF.
"""

from __future__ import annotations

import argparse
import ast
import ipaddress
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# --------------------------------------------------------------------------- LF helper


def normalize_lf(data: bytes) -> bytes:
    """Normalize CRLF to LF. Every byte-exact comparison goes through this."""
    return data.replace(b"\r\n", b"\n")


# --------------------------------------------------------------------------- AST ban

BANNED_BUILTIN_CALLS = frozenset({"eval", "exec", "compile", "__import__"})
BANNED_OS_EXACT = frozenset({"system", "popen"})
BANNED_OS_PREFIXES = ("exec", "spawn")
BANNED_MODULES = frozenset({"subprocess"})


def _banned_os_attr(name: str) -> bool:
    return name in BANNED_OS_EXACT or name.startswith(BANNED_OS_PREFIXES)


def check_source(source: str, filename: str = "<src>") -> list[str]:
    """Return one message per execution primitive found in ``source``."""
    tree = ast.parse(source, filename=filename)
    os_aliases = {"os"}
    problems: list[str] = []

    def add(node: ast.AST, what: str) -> None:
        problems.append(f"{filename}:{getattr(node, 'lineno', 0)}: {what}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BANNED_MODULES:
                    add(node, f"import of {root}")
                if root == "os" and alias.asname:
                    os_aliases.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in BANNED_MODULES:
                add(node, f"import from {root}")
            if root == "os":
                for alias in node.names:
                    if _banned_os_attr(alias.name):
                        add(node, f"import of os.{alias.name}")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases
            and _banned_os_attr(node.attr)
        ):
            add(node, f"use of os.{node.attr}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in BANNED_BUILTIN_CALLS
        ):
            add(node, f"call to builtin {node.func.id}")
    return problems


def check_ast_ban() -> list[str]:
    files = sorted(SRC.rglob("*.py"))
    if not files:
        return [f"no Python files found under {SRC}"]
    problems: list[str] = []
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        try:
            problems.extend(check_source(path.read_text(encoding="utf-8"), rel))
        except SyntaxError as exc:
            problems.append(f"{rel}: cannot parse ({exc.msg})")
    return problems


# --------------------------------------------------------------------------- secret and email scan

# Patterns are built from parts so that this file never contains a match.
_AT = "@"
SCAN_PATTERNS: dict[str, re.Pattern[str]] = {
    "email address": re.compile(
        r"[A-Za-z0-9._%+-]+" + _AT + r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    ),
    "aws access key id": re.compile(r"\b(?:AK" + "IA|AS" + r"IA)[0-9A-Z]{16}\b"),
    "github token": re.compile(r"\bgh[pousr]" + "_" + r"[A-Za-z0-9]{36,}"),
    "api key (sk- prefix)": re.compile(r"\bsk" + "-" + r"[A-Za-z0-9_-]{20,}"),
    "slack token": re.compile(r"\bxox[baprs]" + "-" + r"[A-Za-z0-9-]{10,}"),
    "google api key": re.compile(r"\bAI" + "za" + r"[0-9A-Za-z_-]{35}"),
    "private key header": re.compile(
        "-----" + "BEGIN " + r"(?:[A-Z]+ )?PRIVATE" + " KEY" + "-----"
    ),
}


def scan_text(text: str) -> list[tuple[int, str]]:
    """Return (line number, pattern name) for each hit. Never returns the matched text."""
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in SCAN_PATTERNS.items():
            if pattern.search(line):
                hits.append((lineno, name))
    return hits


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.decode("utf-8", "replace")


def tracked_paths() -> list[str]:
    """Tracked files, which includes anything staged. Paths use forward slashes."""
    out = git("ls-files", "-z", "--cached")
    return [p for p in out.split("\0") if p]


def read_tracked_text(rel: str) -> str | None:
    """Text of a tracked file, or None for a binary or deleted file."""
    path = ROOT / rel
    if not path.is_file():
        return None  # tracked but deleted in the working tree
    data = path.read_bytes()
    if b"\0" in data:
        return None  # binary file
    return data.decode("utf-8", "replace")


def check_secret_scan() -> list[str]:
    problems: list[str] = []
    for rel in tracked_paths():
        text = read_tracked_text(rel)
        if text is None:
            continue
        for lineno, name in scan_text(text):
            problems.append(f"{rel}:{lineno}: {name}")
    return problems


# --------------------------------------------------------------------------- RFC 5737 data rule

# Test data, samples and docs may only use documentation addresses (RFC 5737).
DOC_NETWORKS = tuple(
    ipaddress.IPv4Network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
DATA_PREFIXES = ("tests/", "examples/", "docs/")
DATA_FILES = frozenset({"README.md"})
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")


def non_documentation_ips(text: str) -> list[tuple[int, str]]:
    """Return (line number, address) for each valid IPv4 literal outside RFC 5737."""
    found: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in IPV4_RE.finditer(line):
            try:
                addr = ipaddress.IPv4Address(match.group(1))
            except ValueError:
                continue  # not an address (an octet over 255): a version string or similar
            if not any(addr in net for net in DOC_NETWORKS):
                found.append((lineno, str(addr)))
    return found


def is_data_path(rel: str) -> bool:
    return rel in DATA_FILES or rel.startswith(DATA_PREFIXES)


def check_documentation_ips() -> list[str]:
    problems: list[str] = []
    for rel in tracked_paths():
        if not is_data_path(rel):
            continue
        text = read_tracked_text(rel)
        if text is None:
            continue
        for lineno, addr in non_documentation_ips(text):
            problems.append(f"{rel}:{lineno}: {addr} is not an RFC 5737 documentation address")
    return problems


# --------------------------------------------------------------------------- graph and hygiene

# Graphify output and its local ignore file are tool state, never committed.
GRAPH_PATHS = ("graphify-out", ".graphifyignore")


def graph_problems(paths: Iterable[str]) -> list[str]:
    return [
        f"graphify file is tracked or staged: {p}"
        for p in paths
        if p.split("/")[0] in GRAPH_PATHS
    ]


def check_graph() -> list[str]:
    problems = graph_problems(tracked_paths())
    for probe_path in ("graphify-out/probe.json", ".graphifyignore"):
        probe = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", probe_path],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if probe.returncode == 1:
            problems.append(f"{probe_path} is not git-ignored")
        elif probe.returncode != 0:
            problems.append(f"git check-ignore failed (exit {probe.returncode})")
    return problems


def hygiene_problems(paths: Iterable[str]) -> list[str]:
    problems: list[str] = []
    for p in paths:
        parts = p.split("/")
        if parts[-1].lower() == "agents.md":
            problems.append(f"AGENTS.md must not be tracked or staged: {p}")
        if ".codex" in parts[:-1] or parts[0] == ".codex":
            problems.append(f".codex/ must not be tracked or staged: {p}")
    return problems


def check_hygiene() -> list[str]:
    return hygiene_problems(tracked_paths())


# --------------------------------------------------------------------------- external tools


def run_tool(args: Sequence[str]) -> list[str]:
    print(f"     $ {' '.join(args[1:])}", flush=True)
    result = subprocess.run(list(args), cwd=ROOT, check=False)
    return [] if result.returncode == 0 else [f"exit code {result.returncode}"]


COVERAGE_MIN = 90


def check_tests() -> list[str]:
    return run_tool(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--cov",
            "--cov-report=term-missing",
            f"--cov-fail-under={COVERAGE_MIN}",
        ]
    )


# --------------------------------------------------------------------------- CLI smoke test

# (arguments, text that must appear on stdout)
SMOKE_RUNS: list[tuple[list[str], str]] = [
    (["--file", "examples/sample_auth.log", "--no-color"], "Summary: 3 alert(s)"),
    (["--file", "examples/sample_apache.log", "--no-color"], "Summary: 12 alert(s)"),
]


def run_cli(args: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, "analyzer.py", *args],
        cwd=ROOT,
        capture_output=True,
        env=env,
        timeout=120,
        check=False,
    )


def check_cli_smoke() -> list[str]:
    problems: list[str] = []
    for args, expected in SMOKE_RUNS:
        result = run_cli(args)
        out = result.stdout.decode("utf-8", "replace")
        label = " ".join(args)
        if result.returncode != 0:
            problems.append(f"analyzer.py {label}: exit code {result.returncode}")
        elif expected not in out:
            problems.append(f"analyzer.py {label}: expected {expected!r} in output")
    return problems


# --------------------------------------------------------------------------- runner

CHECKS: list[tuple[str, Callable[[], list[str]]]] = [
    (f"pytest + coverage >= {COVERAGE_MIN}%", check_tests),
    ("AST ban (execution primitives in src/)", check_ast_ban),
    ("secret and email scan", check_secret_scan),
    ("RFC 5737 addresses only in tests, samples, docs", check_documentation_ips),
    ("graphify files not staged, ignored", check_graph),
    ("commit hygiene", check_hygiene),
    ("CLI smoke test", check_cli_smoke),
]


def main(argv: Sequence[str] | None = None) -> int:
    # No options on purpose: there is no flag that skips a check.
    argparse.ArgumentParser(prog="gate.py", description="Run the project gate.").parse_args(argv)
    for name, check in CHECKS:
        print(f"[gate] {name}", flush=True)
        try:
            problems = check()
        except Exception as exc:  # a crashing check is a failing check
            problems = [f"check crashed: {type(exc).__name__}: {exc}"]
        if problems:
            for problem in problems:
                print(f"  FAIL {problem}")
            print(f"[gate] FAILED at: {name}")
            return 1
        print(f"  ok   {name}", flush=True)
    print("[gate] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
