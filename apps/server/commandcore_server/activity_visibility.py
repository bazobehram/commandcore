"""Ephemeral safe operation detail; never store raw commands, file contents or patches."""

from __future__ import annotations

import posixpath
import re
import shlex
from typing import Any
from urllib.parse import urlsplit

_PATH_FIELDS = ("path", "root", "repo", "source", "destination", "cwd")
_RESTRICTED = re.compile(
    r"(^|[/\\])(?:\.ssh|\.aws|\.kube|\.gnupg|\.env(?:\.[^/\\]+)?|"
    r"credentials?(?:\.[^/\\]+)?|secrets?|tokens?|passwords?|"
    r"id_(?:rsa|ed25519)|\.git-credentials|cookies?)(?:[/\\]|$)",
    re.IGNORECASE,
)
_SAFE_EXEC = {
    "pwd",
    "ls",
    "find",
    "cat",
    "grep",
    "rg",
    "head",
    "tail",
    "stat",
    "du",
    "df",
    "git",
    "python",
    "python3",
    "pytest",
    "npm",
    "node",
    "cargo",
    "docker",
    "systemctl",
    "sed",
    "awk",
    "wc",
    "cp",
    "mv",
    "mkdir",
    "touch",
    "date",
    "uname",
    "bash",
    "sh",
    "curl",
    "tar",
}
_SAFE_GIT = {"status", "diff", "log", "show", "branch", "rev-parse"}


def safe_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 768:
        return None
    if (
        "://" in value
        or any(c in value for c in ("?", "#"))
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        return None
    # Paths are hints, not verified filesystem effects. Reject URLs, traversal,
    # control characters and arbitrary literals before keeping a bounded hint.
    if not re.fullmatch(r"[\w/\\. :+@-]{1,240}", value):
        return None
    portable = value.replace("\\", "/")
    if "://" in portable or ".." in portable.split("/"):
        return None
    normalized = posixpath.normpath(portable)
    if _RESTRICTED.search(portable) or re.search(
        r"secret|credential|password|token|private[._-]?key|cookie",
        portable,
        re.IGNORECASE,
    ):
        return "[restricted path]"
    return normalized


def visible_public_url(value: Any) -> str | None:
    """Reduce a Browser URL to an explicitly public HTTPS *origin*.

    Browsing history, userinfo, query strings and fragments can carry secrets.
    Neither paths nor typed form data belong in cross-session Activity hints.
    Internal names, numeric IPs, ports and IDN/unicode hosts stay withheld.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return None
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or chr(92) in value:
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or not parsed.netloc
        ):
            return None
    except ValueError:
        return None
    if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", host):
        return None
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or any(
            not label or len(label) > 48 or label.startswith("-") or label.endswith("-")
            for label in labels
        )
        or not re.fullmatch(r"[a-z]{2,24}", labels[-1])
        or labels[-1] in {"local", "lan", "internal", "localhost", "home", "arpa"}
        or re.search(
            r"secret|credential|password|passwd|token|bearer|auth|"
            r"cookie|private|api[_.-]?key|access[_.-]?key|session",
            host,
            re.IGNORECASE,
        )
    ):
        return None
    return "https://" + host + "/"



# Only a finite developer command grammar can appear in Activity hints.
# Execution receipts use a different request-local redaction policy.
_ACTIVITY_EXEC = frozenset({
    "pwd", "uname", "cd", "mkdir", "ls", "stat", "df", "du",
    "git", "python", "python3", "pytest", "npm", "cargo", "pip", "pip3",
})
_ACTIVITY_SENSITIVE = re.compile(
    r"secret|credential|password|passwd|token|bearer|auth|cookie|private|"
    r"api[_.-]?key|access[_.-]?key|session|\.env|\.ssh|\.aws|\.kube|"
    r"\.gnupg|id_rsa|id_ed25519|-----BEGIN|AKIA[A-Z0-9]{16}|eyJ",
    re.IGNORECASE,
)
# Even a syntactically valid path may be an opaque credential literal.
_ACTIVITY_OPAQUE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9])")
_ACTIVITY_FORBIDDEN = re.compile(r"[=$\x60\\%<>\x00-\x1f\x7f]")
_ACTIVITY_TOKEN = re.compile(
    r"""(?P<space> +)|(?P<operator>&&|\|\||[;|])|"""
    r"""(?P<word>'[^']*'|"[^"]*"|[^ ;&|'"]+)"""
)


def _activity_target(value: str) -> bool:
    if (
        not re.fullmatch(r"[A-Za-z0-9_./ @+-]{1,120}", value)
        or value.startswith("-")
    ):
        return False
    return safe_path(value) not in (None, "[restricted path]")


def _approved_activity_step(words: list[str]) -> bool:
    """Allow only known commands and bounded, non-secret argument patterns."""
    if not words or words[0] not in _ACTIVITY_EXEC:
        return False
    name, *args = words
    if name == "pwd":
        return not args
    if name == "uname":
        return all(x in {"-a", "-s", "-r", "-m"} for x in args)
    if name in {"cd", "mkdir", "ls", "stat", "df", "du"}:
        flags = {
            "cd": set(),
            "mkdir": {"-p"},
            "ls": {"-l", "-a", "-la", "-al", "-h"},
            "stat": set(),
            "df": {"-h"},
            "du": {"-h", "-s", "-sh"},
        }[name]
        return all(x in flags or _activity_target(x) for x in args) and (
            name != "cd" or len(args) == 1
        )
    if name == "git":
        flags = {
            "status": {"--short", "--porcelain", "-sb"},
            "diff": {"--stat", "--name-only", "--check", "--cached", "--staged"},
            "log": {"--oneline", "-1", "-5", "-10"},
            "branch": {"--show-current"},
            "rev-parse": {"--show-toplevel", "--is-inside-work-tree"},
        }
        return bool(args) and args[0] in flags and all(
            x in flags[args[0]] for x in args[1:]
        )
    if name in {"python", "python3"}:
        if args == ["--version"]:
            return True
        if args[:2] == ["-m", "pytest"]:
            return _approved_activity_step(["pytest", *args[2:]])
        if args[:2] == ["-m", "pip"]:
            return _approved_activity_step(["pip", *args[2:]])
        return False
    if name in {"pip", "pip3"}:
        return args in (["--version"], ["list"])
    if name == "pytest":
        return all(
            x in {"-q", "-v", "-x", "--collect-only"}
            or (_activity_target(x) and (x.endswith(".py") or x in {"tests", "tests/"}))
            for x in args
        )
    if name == "npm":
        return args in (["test"], ["ci"], ["run", "build"], ["run", "lint"])
    if name == "cargo":
        return args in (["test"], ["build"], ["check"], ["fmt", "--check"])
    return False


def command_projection(value: Any) -> dict[str, Any]:
    """Show only validated developer commands or non-sensitive step structure.

    Input strings are never copied to output unless the entire command is
    accepted by the fixed grammar. Unsupported arguments stay withheld.
    """
    withheld = {
        "command_visibility": "withheld",
        "redaction_reason": (
            "Command arguments withheld: credentials, code or unsupported syntax may be present."
        ),
    }
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return withheld
    if (_ACTIVITY_SENSITIVE.search(value) or _ACTIVITY_FORBIDDEN.search(value)
            or _ACTIVITY_OPAQUE.search(value)):
        return withheld
    tokens = []
    position = 0
    previous_word = False
    for match in _ACTIVITY_TOKEN.finditer(value):
        if match.start() != position:
            return withheld
        position = match.end()
        if match.lastgroup == "space":
            previous_word = False
            continue
        if match.lastgroup == "word":
            if previous_word:
                return withheld
            try:
                word = shlex.split(match.group())
            except ValueError:
                return withheld
            if len(word) != 1:
                return withheld
            tokens.append(("word", word[0]))
            previous_word = True
        else:
            tokens.append(("operator", match.group()))
            previous_word = False
    if position != len(value) or not tokens or len(tokens) > 96:
        return withheld
    steps: list[list[str]] = [[]]
    operators: list[str] = []
    for kind, token in tokens:
        if kind == "operator":
            if not steps[-1]:
                return withheld
            operators.append(token)
            steps.append([])
        elif any(char in token for char in ";&|"):
            return withheld
        else:
            steps[-1].append(token)
    if not steps[-1] or len(steps) > 12:
        return withheld
    if all(_approved_activity_step(step) for step in steps):
        displays = [shlex.join(step) for step in steps]
        command_display = displays[0]
        for operator, display in zip(operators, displays[1:]):
            command_display += " " + operator + " " + display
        return {
            "command_display": command_display,
            "command_steps": displays,
            "command_visibility": "validated",
            "step_operators": operators,
        }
    structure = [
        step[0] if step[0] in _ACTIVITY_EXEC else "unrecognized command"
        for step in steps
    ]
    return {
        **withheld,
        "command_visibility": "structure",
        "command_steps": [name + " (arguments withheld)" for name in structure],
        "step_operators": operators,
        "redaction_reason": "Only command structure shown; unsupported arguments withheld.",
    }


def safe_command_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 32768:
        return None
    try:
        parts = shlex.split(value)
    except ValueError:
        return None
    if (
        not parts
        or "=" in parts[0]
        or any(c in parts[0] for c in ("$", "`", ";", "|", ">", "<"))
    ):
        return None
    name = posixpath.basename(parts[0].replace("\\", "/"))
    return name if name in _SAFE_EXEC else None


def safe_operation_detail(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"operation": tool[:64]}
    for key in _PATH_FIELDS:
        path = safe_path(arguments.get(key))
        if path is not None:
            result[key] = path
    if tool in {"shell.exec", "process.start"}:
        result.update(command_projection(arguments.get("command") if not arguments.get("env") else None))
        result["command_name"] = (
            safe_command_name(arguments.get("command")) or "[hidden]"
        )
    elif tool.startswith("browser."):
        origin = visible_public_url(arguments.get("url"))
        if origin is not None:
            result["public_url"] = origin
        result["url_visibility"] = (
            "HTTPS origin only; path, query and fragment withheld."
        )
    elif tool == "git.run":
        argv = arguments.get("args")
        if isinstance(argv, list) and argv and isinstance(argv[0], str):
            result["git_subcommand"] = argv[0] if argv[0] in _SAFE_GIT else "[hidden]"
    if tool in {
        "fs.write",
        "fs.patch",
        "fs.delete",
        "fs.move",
        "fs.copy",
        "transfer.upload",
    }:
        result["effect"] = "write"
    elif tool.startswith(
        ("fs.read", "fs.list", "fs.stat", "fs.search", "git.diff", "git.status")
    ):
        result["effect"] = "read"
    if tool == "fs.patch" and isinstance(arguments.get("patches"), list):
        result["patch_count"] = min(len(arguments["patches"]), 10000)
    if tool in {"fs.write", "fs.patch"}:
        result["preview"] = "Content hidden. Request an authorized diff explicitly."
    return result
