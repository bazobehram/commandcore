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
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\\\" in value:
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
        or any(not label or len(label) > 48 or label.startswith("-")
               or label.endswith("-") for label in labels)
        or not re.fullmatch(r"[a-z]{2,24}", labels[-1])
        or labels[-1] in {"local", "lan", "internal", "localhost", "home", "arpa"}
        or re.search(r"secret|credential|password|passwd|token|bearer|auth|"
                     r"cookie|private|api[_.-]?key|access[_.-]?key|session",
                     host, re.IGNORECASE)
    ):
        return None
    return "https://" + host + "/"


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
        result["command_name"] = (
            safe_command_name(arguments.get("command")) or "[hidden]"
        )
    elif tool.startswith("browser."):
        origin = visible_public_url(arguments.get("url"))
        if origin is not None:
            result["public_url"] = origin
        result["url_visibility"] = "HTTPS origin only; path, query and fragment withheld."
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
