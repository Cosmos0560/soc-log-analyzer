#!/usr/bin/env python3
"""PreToolUse hook for the Bash and PowerShell tools (rules: CLAUDE.md). Stdlib only.

Contract with Claude Code: tool input arrives as JSON on stdin. Exit 0 allows the call,
exit 2 blocks it and the reason on stderr is shown to the model. Exit 1 is NON-blocking,
so this hook FAILS CLOSED: bad bytes, bad JSON, an unknown shape or any internal error
all end in exit 2, never in exit 1.

The hook is a guard rail for a cooperating assistant, not a sandbox. It parses commands
well enough to tell `git log --grep push` from `git push`, and it looks inside the common
shell wrappers (bash -c, pwsh -Command, cmd /c, eval, $(...), wsl, sudo, env, ...).
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import IO

MAX_DEPTH = 6
SHELL_TOOLS = ("Bash", "PowerShell")

# Accepted gate prefixes (CLAUDE.md, "Commit form"): the project venv on Windows only.
GATE_PYTHONS = (
    ".venv/Scripts/python",
    ".venv/Scripts/python.exe",
)
GATE_SCRIPT = "scripts/gate.py"

# Git subcommands that rewrite history, re-initialize the repo or move refs directly.
GIT_HISTORY_REWRITE = frozenset(
    {"rebase", "filter-branch", "filter-repo", "init", "replace", "update-ref"}
)
# `git config` write forms (both the classic flags and the git 2.46+ subcommands).
CONFIG_WRITE_FLAGS = frozenset(
    {"--unset", "--unset-all", "--add", "--replace-all", "--rename-section",
     "--remove-section", "-e", "--edit"}
)  # fmt: skip
CONFIG_READ_SUBCOMMANDS = frozenset({"get", "list"})

# Graphify: only local, read-only or code-only commands. No install/integration commands,
# nothing that fetches from the network or calls an LLM backend.
GRAPHIFY_ALLOWED = frozenset({"query", "path", "explain", "affected", "god-nodes", "update"})
GRAPHIFY_HELP = frozenset({"--help", "-h", "help"})

# Patterns that look like secrets or emails are assembled from parts.
_AT = "@"
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+" + _AT + r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)
COAUTHOR_RE = re.compile(r"co[-\s]?authored[-\s]?by", re.IGNORECASE)

WRAPPERS = frozenset(
    {
        "env", "sudo", "doas", "time", "nohup", "command", "builtin", "exec", "nice", "timeout",
        "xargs", "start", "call", "watch", "stdbuf", "setsid", "ionice", "chroot",
    }
)  # fmt: skip
POSIX_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})
PS_SHELLS = frozenset({"pwsh", "powershell"})
# Commands whose arguments are prose or search text, not something that binds a port.
NO_PORT_CHECK = frozenset(
    {"git", "echo", "printf", "grep", "rg", "cat", "write-host", "select-string", "findstr"}
)

LIST_TAG_FLAGS = frozenset(
    {"-l", "--list", "--contains", "--no-contains", "--points-at", "--merged", "--no-merged",
     "-v", "--verify"}
)  # fmt: skip
TAG_WRITE_LONG = frozenset({"--delete", "--annotate", "--sign", "--force", "--local-user",
                            "--message", "--file", "--create-reflog"})  # fmt: skip
TAG_WRITE_SHORT = frozenset("daufsmF")
CONFIG_READ_FLAGS = frozenset({"--get", "--get-all", "--get-regexp", "--list", "-l"})

GIT_VALUE_OPTIONS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
)
GIT_COMMIT_VALUE_SHORT = frozenset("mFCctu")  # short options that take a value in `git commit`

WSL_BAD_FLAGS = frozenset(
    {"--install", "--unregister", "--set-version", "--update", "--uninstall",
     "--import", "--import-in-place"}
)  # fmt: skip
WSL_VALUE_OPTIONS = frozenset({"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"})
WSL_PKG_RE = re.compile(r"(?<![\w.-])(?:apt-get|apt|aptitude|dpkg)(?![\w-])", re.IGNORECASE)
GET_PROCESS_KILL_RE = re.compile(
    r"get-process(?![^|]*\s-id\b)[^|]*\|\s*stop-process", re.IGNORECASE | re.DOTALL
)
PS_STOP_NAME_RE = re.compile(r"^-n(?:a(?:m(?:e)?)?)?$", re.IGNORECASE)
PORT_RES = (
    re.compile(r"(?:^|\s)(?:-p|--publish|-publish)[=\s]*(?:[\d.]+:)?8080(?!\d)"),
    re.compile(r"--port[=\s]+8080(?!\d)"),
    re.compile(r":8080(?!\d)"),
    re.compile(r"http\.server\s+(?:\S+\s+)*8080(?!\d)"),
)


class BlockError(Exception):
    """Raised internally to carry a block reason out of nested checks."""


@dataclass
class Segment:
    text: str
    sep_before: str  # separator run that preceded this segment ("" for the first)
    sep_after: str = ""


# --------------------------------------------------------------------------- splitting


def _skip_heredoc_body(command: str, start: int, delimiter: str, strip_tabs: bool) -> int:
    """Return the index just after the heredoc terminator line, scanning from ``start``."""
    pos = start
    while pos < len(command):
        end = command.find("\n", pos)
        line = command[pos:] if end == -1 else command[pos:end]
        if (line.lstrip("\t") if strip_tabs else line).rstrip("\r") == delimiter:
            return len(command) if end == -1 else end + 1
        if end == -1:
            return len(command)
        pos = end + 1
    return len(command)


_HEREDOC_RE = re.compile(r"<<(-?)\s*(?:'([^'\n]+)'|\"([^\"\n]+)\"|([A-Za-z_][A-Za-z0-9_]*))")


def split_segments(command: str) -> list[Segment]:
    """Split a command on shell separators, respecting quotes, comments and heredocs.

    Raises BlockError on unterminated quotes: a command whose quoting cannot be
    followed cannot be inspected, so it is refused (fail closed).
    """
    segments: list[Segment] = []
    buf: list[str] = []
    pending = ""  # separator run waiting for the next non-empty segment
    i, n = 0, len(command)
    quote = ""
    pending_heredocs: list[tuple[str, bool]] = []

    def flush_segment() -> None:
        nonlocal pending
        text = "".join(buf).strip()
        buf.clear()
        if text:
            segments.append(Segment(text, pending))
            pending = ""

    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if quote == '"' and ch == "\\" and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\":
            if i + 1 < n and command[i + 1] == "\n":
                i += 2
                continue
            if i + 1 < n and command[i + 1] in "'\"":
                buf.append(command[i : i + 2])
                i += 2
                continue
            buf.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or command[i - 1].isspace()):
            while i < n and command[i] != "\n":
                i += 1
            continue
        if ch == "<" and command.startswith("<<", i) and not command.startswith("<<<", i):
            match = _HEREDOC_RE.match(command, i)
            if match:
                delim = match.group(2) or match.group(3) or match.group(4)
                pending_heredocs.append((delim, match.group(1) == "-"))
                buf.append(match.group(0))
                i = match.end()
                continue
        if ch == "\n":
            flush_segment()
            pending += ch
            i += 1
            for delim, strip_tabs in pending_heredocs:
                i = _skip_heredoc_body(command, i, delim, strip_tabs)
            pending_heredocs.clear()
            continue
        if ch in ";(){}`":
            flush_segment()
            pending += ch
            i += 1
            continue
        if ch == "|":
            flush_segment()
            run = "|"
            if i + 1 < n and command[i + 1] in "|&":
                run += command[i + 1]
                i += 1
            pending += run
            i += 1
            continue
        if ch == "&":
            prev = command[i - 1] if i else ""
            nxt = command[i + 1] if i + 1 < n else ""
            if (prev and prev in "<>") or nxt == ">":
                buf.append(ch)  # redirect such as 2>&1 or &>
                i += 1
                continue
            flush_segment()
            if nxt == "&":
                pending += "&&"
                i += 2
            else:
                pending += "&"
                i += 1
            continue
        buf.append(ch)
        i += 1
    if quote:
        raise BlockError("unterminated quote: the command cannot be inspected")
    flush_segment()
    for k in range(len(segments) - 1):
        segments[k].sep_after = segments[k + 1].sep_before
    return segments


def tokenize(text: str) -> list[str]:
    """Split a segment into words with quotes removed. Backslashes are literal (Windows paths)."""
    tokens: list[str] = []
    cur: list[str] = []
    has = False
    quote = ""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
            elif quote == '"' and ch == "\\" and i + 1 < n and text[i + 1] in '"\\$`':
                cur.append(text[i + 1])
                i += 1
            else:
                cur.append(ch)
        elif ch in "'\"":
            quote = ch
            has = True
        elif ch == "\\" and i + 1 < n and text[i + 1] in "'\"":
            cur.append(text[i + 1])
            i += 1
            has = True
        elif ch.isspace():
            if has or cur:
                tokens.append("".join(cur))
                cur, has = [], False
        else:
            cur.append(ch)
            has = True
        i += 1
    if has or cur:
        tokens.append("".join(cur))
    return tokens


def find_substitutions(command: str) -> list[str]:
    """Inner text of `$( ... )` and backtick substitutions that the shell would expand."""
    found: list[str] = []
    i, n = 0, len(command)
    in_single = False
    while i < n:
        ch = command[i]
        if in_single:
            in_single = ch != "'"
            i += 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if ch == "$" and command.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if command[j] == "(":
                    depth += 1
                elif command[j] == ")":
                    depth -= 1
                j += 1
            found.append(command[i + 2 : j - 1 if depth == 0 else j])
            i += 2  # keep scanning inside for nested substitutions
            continue
        if ch == "`":
            j = command.find("`", i + 1)
            if j == -1:
                found.append(command[i + 1 :])
                break
            found.append(command[i + 1 : j])
            i = j + 1
            continue
        i += 1
    return found


# --------------------------------------------------------------------------- helpers


def base_name(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def strip_assignments(tokens: list[str]) -> list[str]:
    k = 0
    while k < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[k]):
        k += 1
    return tokens[k:]


def short_cluster(token: str) -> str | None:
    """Letters of a short-option cluster like -am, or None if token is not one."""
    if len(token) >= 2 and token[0] == "-" and token[1] != "-":
        return token[1:]
    return None


def gate_prefix_ok(segments: list[Segment]) -> bool:
    if not segments:
        return False
    first = tokenize(segments[0].text)
    return len(first) == 2 and first[0] in GATE_PYTHONS and first[1] == GATE_SCRIPT


# --------------------------------------------------------------------------- git rules


def git_subcommand(args: list[str]) -> tuple[str, list[str], list[str]]:
    """Return (subcommand, its args, global -c values) from the tokens after `git`."""
    config_values: list[str] = []
    k = 0
    while k < len(args):
        tok = args[k]
        if tok in GIT_VALUE_OPTIONS:
            if tok == "-c" and k + 1 < len(args):
                config_values.append(args[k + 1])
            k += 2
            continue
        if tok.startswith("-"):
            if tok.startswith("-c") and len(tok) > 2 and not tok.startswith("--"):
                config_values.append(tok[2:])
            k += 1
            continue
        return tok, args[k + 1 :], config_values
    return "", [], config_values


def check_git(
    args: list[str],
    tool: str,
    segments: list[Segment],
    index: int,
    raw: str,
    nested: bool,
) -> None:
    sub, rest, cfg = git_subcommand(args)
    for value in cfg:
        low = value.lower()
        if low.startswith("user."):
            raise BlockError("git identity must not be changed (git -c user.*)")
        if low.startswith("alias."):
            raise BlockError("git aliases on the command line hide the real subcommand")
    if sub == "push":
        raise BlockError("git push is blocked: the owner pushes")
    if sub in {"mktag", "tag"}:
        check_git_tag(sub, rest)
    if sub in GIT_HISTORY_REWRITE:
        raise BlockError(f"git {sub} is blocked: history, refs and the repo are not rewritten")
    if sub == "reset" and "--hard" in rest:
        raise BlockError("git reset --hard is blocked: it discards work")
    if sub == "add":
        check_git_add(rest)
    if sub == "config":
        check_git_config(rest)
    if sub == "commit":
        check_git_commit(rest, tool, segments, index, raw, nested)


def check_git_tag(sub: str, rest: list[str]) -> None:
    if sub == "mktag":
        raise BlockError("creating or deleting tags is blocked: the owner tags")
    positional = False
    listing = False
    for a in rest:
        if a == "--":
            continue
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if name in TAG_WRITE_LONG:
                raise BlockError("creating or deleting tags is blocked: the owner tags")
            if name in LIST_TAG_FLAGS:
                listing = True
        elif (cluster := short_cluster(a)) is not None:
            if any(c in TAG_WRITE_SHORT for c in cluster):
                raise BlockError("creating or deleting tags is blocked: the owner tags")
            if a in LIST_TAG_FLAGS or cluster[0] in "ln":
                listing = True
        else:
            positional = True
    if positional and not listing:
        raise BlockError("creating or deleting tags is blocked: the owner tags")


def check_git_config(rest: list[str]) -> None:
    """Allow only reads: `--get`/`--list`/..., `git config get|list ...`, `git config <key>`."""
    if any(a.lower().startswith("user.") for a in rest) and not any(
        a in CONFIG_READ_FLAGS for a in rest
    ):
        raise BlockError("git config user.* is blocked: do not touch git identity")
    if any(a in CONFIG_READ_FLAGS for a in rest):
        return
    if any(a.split("=", 1)[0] in CONFIG_WRITE_FLAGS for a in rest):
        raise BlockError("git config writes are blocked: do not touch git config")
    positional = [a for a in rest if not a.startswith("-")]
    if positional and positional[0] in CONFIG_READ_SUBCOMMANDS:
        return
    if len(positional) == 1:
        return  # `git config core.autocrlf` reads one key
    raise BlockError("git config writes are blocked: do not touch git config")


def check_graphify(args: list[str]) -> None:
    if not args or args[0] in GRAPHIFY_HELP:
        return
    sub = args[0]
    if sub in GRAPHIFY_ALLOWED:
        return
    if sub == "extract" and "--code-only" in args and "--global" not in args:
        return
    if sub == "cluster-only" and "--no-label" in args:
        return
    raise BlockError(
        f"graphify {sub} is blocked: only local code-only and read commands are allowed "
        "(no install, integration, network or LLM commands)"
    )


def check_git_add(rest: list[str]) -> None:
    for a in rest:
        if a in {"--all", ".", "./", "*", ":/"}:
            raise BlockError("git add of everything is blocked: stage files by explicit path")
        cluster = short_cluster(a)
        if cluster is not None and "A" in cluster:
            raise BlockError("git add -A is blocked: stage files by explicit path")


def check_git_commit(
    rest: list[str],
    tool: str,
    segments: list[Segment],
    index: int,
    raw: str,
    nested: bool,
) -> None:
    if tool == "PowerShell":
        raise BlockError("git commit through the PowerShell tool is blocked: use the Bash tool")
    skip_next = False
    for a in rest:
        if skip_next:  # the value of a preceding -m / -F / -C ...
            skip_next = False
            continue
        if a == "--all":
            raise BlockError("git commit -a is blocked: stage files by explicit path")
        if a.startswith("--amend"):
            raise BlockError("git commit --amend is blocked: existing commits are not rewritten")
        cluster = short_cluster(a)
        if cluster is None:
            continue
        for pos, c in enumerate(cluster):
            if c == "a":
                raise BlockError("git commit -a is blocked: stage files by explicit path")
            if c in GIT_COMMIT_VALUE_SHORT:
                skip_next = pos == len(cluster) - 1  # value is the next token, not attached
                break
    if COAUTHOR_RE.search(raw):
        raise BlockError("commit text must not contain a Co-Authored-By trailer")
    if EMAIL_RE.search(raw):
        raise BlockError("commit text must not contain an email address")
    if nested:
        raise BlockError("git commit must be issued directly, not inside a wrapper or substitution")
    if index == 0 or not gate_prefix_ok(segments):
        raise BlockError("git commit must start with '.venv/Scripts/python scripts/gate.py &&'")
    if any(seg.sep_before != "&&" for seg in segments[1 : index + 1]):
        raise BlockError("the gate must be chained to the commit with && only")


# --------------------------------------------------------------------------- other rules


def check_wsl(args: list[str]) -> list[str]:
    """Validate wsl flags; return the tokens of the command run inside the distribution."""
    k = 0
    while k < len(args):
        tok = args[k]
        low = tok.lower()
        if low in WSL_BAD_FLAGS:
            raise BlockError("modifying the WSL distribution is blocked")
        if low in WSL_VALUE_OPTIONS:
            k += 2
            continue
        if low in {"-e", "--exec", "--", "--system"}:
            k += 1
            continue
        if low.startswith("-"):
            k += 1
            continue
        break
    inner = args[k:]
    if WSL_PKG_RE.search(" ".join(args)):
        raise BlockError("apt/apt-get/dpkg through wsl is blocked: do not modify the distribution")
    return inner


def check_port(segment_text: str) -> None:
    for pattern in PORT_RES:
        if pattern.search(segment_text):
            raise BlockError("host port 8080 must not be used")


def check_tokens(
    tokens: list[str],
    tool: str,
    segments: list[Segment],
    index: int,
    raw: str,
    nested: bool,
    depth: int,
) -> None:
    tokens = strip_assignments(tokens)
    if not tokens:
        return
    cmd = base_name(tokens[0])
    args = tokens[1:]
    low_args = [a.lower() for a in args]

    if cmd in WRAPPERS:
        for j in range(1, len(tokens)):
            check_tokens(tokens[j:], tool, segments, index, raw, True, depth)
        return
    if cmd == "eval":
        check_command(" ".join(args), tool, depth + 1, True)
        return
    if cmd in POSIX_SHELLS:
        for j, a in enumerate(args):
            cluster = short_cluster(a)
            if cluster is not None and "c" in cluster:
                check_command(" ".join(args[j + 1 :]), tool, depth + 1, True)
                return
        return
    if cmd in PS_SHELLS:
        for j, a in enumerate(low_args):
            if a in {"-e", "-ec", "-enc", "-encodedcommand"}:
                raise BlockError("encoded PowerShell commands cannot be inspected")
            if a in {"-c", "-cmd", "-command"}:
                check_command(" ".join(args[j + 1 :]), tool, depth + 1, True)
                return
        return
    if cmd == "cmd":
        for j, a in enumerate(low_args):
            if a in {"/c", "/k", "/r"}:
                check_command(" ".join(args[j + 1 :]), tool, depth + 1, True)
                return
        return
    if cmd == "wsl":
        inner = check_wsl(args)
        if inner:
            check_tokens(inner, tool, segments, index, raw, True, depth)
        return
    if cmd == "git":
        check_git(args, tool, segments, index, raw, nested)
        return
    if cmd == "graphify":
        check_graphify(args)
        return
    if cmd in {"docker", "docker-compose", "podman"}:
        if "prune" in low_args:
            raise BlockError("docker prune is blocked")
        if any("wordpress" in a or "dvwa" in a for a in low_args):
            raise BlockError("the wordpress and dvwa containers must not be touched")
    if cmd in {"pkill", "killall"}:
        raise BlockError("killing processes by name is blocked: kill by PID, own processes only")
    if cmd == "taskkill" and any(a in {"/im", "-im"} for a in low_args):
        raise BlockError("taskkill /IM is blocked: kill by PID, own processes only")
    if cmd == "stop-process" and any(PS_STOP_NAME_RE.match(a) for a in args):
        raise BlockError("Stop-Process -Name is blocked: kill by PID, own processes only")
    if cmd not in NO_PORT_CHECK:
        check_port(" ".join(tokens))


def check_command(command: str, tool: str, depth: int = 0, nested: bool = False) -> None:
    """Raise BlockError when ``command`` breaks a rule. Returns None when allowed."""
    if depth > MAX_DEPTH:
        raise BlockError("command nesting is too deep to inspect")
    segments = split_segments(command)
    for inner in find_substitutions(command):
        check_command(inner, tool, depth + 1, True)
    if GET_PROCESS_KILL_RE.search(command):
        raise BlockError("Get-Process | Stop-Process kills by name: kill by PID instead")
    for k, seg in enumerate(segments):
        if "gate.py" in seg.text and seg.sep_after == "|":
            raise BlockError("do not pipe the gate: a pipe hides its exit code")
        check_tokens(tokenize(seg.text), tool, segments, k, command, nested, depth)


def evaluate(payload: object) -> str | None:
    """Return a block reason, or None to allow. Raises ValueError on an unknown shape."""
    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise ValueError("missing tool_name")
    if tool not in SHELL_TOOLS:
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("missing tool_input")
    command = tool_input.get("command")
    if not isinstance(command, str):
        raise ValueError("missing command")
    try:
        check_command(command, tool)
    except BlockError as exc:
        return str(exc)
    return None


# --------------------------------------------------------------------------- entry point


def _emit(message: str, stream: IO[str] | None = None) -> None:
    stream = stream or sys.stderr
    data = (message + "\n").encode("utf-8", "replace")
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:
        stream.write(data.decode("ascii", "replace"))
        stream.flush()


def main(stdin: IO[bytes] | None = None) -> int:
    try:
        raw = (stdin if stdin is not None else sys.stdin.buffer).read()
        payload = json.loads(raw.decode("utf-8-sig"))
        reason = evaluate(payload)
    except Exception as exc:  # fail closed on anything unexpected
        _emit(f"pre_tool_use hook: BLOCKED (fail closed): {type(exc).__name__}: {exc}")
        return 2
    if reason is not None:
        _emit(f"pre_tool_use hook: BLOCKED: {reason}")
        return 2
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:  # last line of defence: never exit 1
        code = 2
    sys.exit(code)
