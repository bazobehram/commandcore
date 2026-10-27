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
_SAFE_GIT = {"status", "diff", "log", "show", "branch", "rev-parse"}
_DISPLAY_SENSITIVE = re.compile(
    r"secret|credential|password|passwd|token|bearer|auth|cookie|private|"
    r"api[_.-]?key|access[_.-]?key|session|\.env|\.ssh|\.aws|\.kube|"
    r"\.gnupg|id_rsa|id_ed25519|-----BEGIN|AKIA[A-Z0-9]{16}|eyJ",
    re.IGNORECASE,
)
_DISPLAY_EXEC = {
    "pwd",
    "uname",
    "ls",
    "mkdir",
    "stat",
    "df",
    "du",
    "git",
    "python",
    "python3",
    "pytest",
    "npm",
    "cargo",
    "cd",
    "pip",
    "pip3",
}


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
    if _RESTRICTED.search(portable) or _DISPLAY_SENSITIVE.search(portable):
        return "[restricted path]"
    # Do not display long opaque components that may be identifiers or secrets.
    if any(len(component) > 48 for component in portable.split("/")):
        return None
    return normalized


def _display_target(word: str) -> bool:
    return bool(
        re.fullmatch(r"[A-Za-z0-9_./ @+-]{1,120}", word)
        and not word.startswith("-")
        and safe_path(word) not in (None, "[restricted path]")
    )


def _display_step_allowed(words: list[str]) -> bool:
    name, *args = words
    if name not in _DISPLAY_EXEC:
        return False
    if name == "pwd":
        return not args
    if name == "uname":
        return all(arg in {"-a", "-s", "-r", "-m"} for arg in args)
    if name in {"cd", "mkdir", "ls", "stat", "df", "du"}:
        flags = {
            "cd": set(),
            "mkdir": {"-p"},
            "ls": {"-l", "-a", "-la", "-al", "-h"},
            "stat": set(),
            "df": {"-h"},
            "du": {"-h", "-s", "-sh"},
        }[name]
        return all(arg in flags or _display_target(arg) for arg in args) and (
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
        return bool(
            args and args[0] in flags and all(arg in flags[args[0]] for arg in args[1:])
        )
    if name in {"python", "python3"}:
        if args == ["--version"]:
            return True
        if args[:2] in (["-m", "pytest"], ["-m", "pip"]):
            return _display_step_allowed([args[1], *args[2:]])
        return False
    if name in {"pip", "pip3"}:
        return args in (["--version"], ["list"], ["install", "oci-cli"])
    if name == "pytest":
        return all(
            arg in {"-q", "-v", "-x", "--collect-only"}
            or (
                _display_target(arg)
                and (arg.endswith(".py") or arg in {"tests", "tests/"})
            )
            for arg in args
        )
    if name == "npm":
        return args in (["test"], ["ci"], ["run", "build"], ["run", "lint"])
    if name == "cargo":
        return args in (["test"], ["build"], ["check"], ["fmt", "--check"])
    return False


def command_projection(value: Any) -> dict[str, Any]:
    withheld = {
        "command_visibility": "withheld",
        "redaction_reason": "Command arguments withheld: credentials, code or unsupported syntax may be present.",
    }
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return withheld
    if _DISPLAY_SENSITIVE.search(value) or re.search(r"[=$`\\%<>\x00-\x1f\x7f]", value):
        return withheld
    pattern = re.compile(
        r"(?P<space> +)|(?P<operator>&&|\|\||[;|])|(?P<word>'[^']*'|\"[^\"]*\"|[^ ;&|'\"]+)"
    )
    tokens: list[tuple[str, str]] = []
    end = 0
    previous_word = False
    for match in pattern.finditer(value):
        if match.start() != end:
            return withheld
        end = match.end()
        if match.lastgroup == "space":
            previous_word = False
        elif match.lastgroup == "word":
            if previous_word:
                return withheld
            try:
                decoded = shlex.split(match.group())
            except ValueError:
                return withheld
            if len(decoded) != 1:
                return withheld
            tokens.append(("word", decoded[0]))
            previous_word = True
        else:
            tokens.append(("operator", match.group()))
            previous_word = False
    if end != len(value) or not tokens or len(tokens) > 96:
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
    if all(_display_step_allowed(step) for step in steps):
        displays = [shlex.join(step) for step in steps]
        display = displays[0]
        for operator, step in zip(operators, displays[1:]):
            display += " " + operator + " " + step
        return {
            "command_display": display,
            "command_steps": displays,
            "command_visibility": "validated",
            "step_operators": operators,
        }
    structure = [
        step[0] if step[0] in _DISPLAY_EXEC else "unrecognized command"
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
    steps = command_projection(value).get("command_steps", [])
    name = steps[0].split(" ", 1)[0] if steps else None
    return name if name in _DISPLAY_EXEC else None


def visible_public_url(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return None
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
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
        ):
            return None
    except ValueError:
        return None
    if not re.fullmatch(
        r"[a-z0-9]+(?:[.-][a-z0-9]+)*", host
    ) or _DISPLAY_SENSITIVE.search(host):
        return None
    if any(len(label) > 48 for label in host.split(".")):
        return None
    return "https://" + host + "/"


def safe_operation_detail(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"operation": tool[:64]}
    for key in _PATH_FIELDS:
        path = safe_path(arguments.get(key))
        if path is not None:
            result[key] = path
    if tool in {"shell.exec", "process.start"}:
        result.update(command_projection(arguments.get("command")))
        result["command_name"] = (
            safe_command_name(arguments.get("command")) or "Shell operation"
        )
    elif tool.startswith("browser."):
        public_url = visible_public_url(arguments.get("url"))
        if public_url:
            result["public_url"] = public_url
        result["url_visibility"] = (
            "HTTPS origin only; path, query, fragment and typed values withheld."
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
