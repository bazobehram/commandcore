"""Volatile operation hints. Never raw argv, file contents or browser values."""

from __future__ import annotations
from typing import Any
from .activity_visibility import safe_operation_detail

_ACTIONS = {
    "fs.read": "Read file",
    "fs.write": "Write file",
    "fs.patch": "Patch file",
    "fs.delete": "Delete file",
    "fs.copy": "Copy file",
    "fs.move": "Move file",
    "fs.list": "List directory",
    "fs.stat": "Inspect file",
    "fs.search": "Search files",
    "git.status": "Inspect Git status",
    "git.diff": "Inspect Git diff",
    "git.log": "Read Git history",
    "git.run": "Run Git operation",
    "shell.exec": "Execute shell",
    "process.start": "Start process",
    "process.output": "Read process output",
    "process.stop": "Stop process",
    "transfer.upload": "Upload file",
    "transfer.download": "Download file",
}


def safe_trace(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    detail = safe_operation_detail(tool, args if isinstance(args, dict) else {})
    detail["action"] = _ACTIONS.get(tool, "Run " + str(tool)[:48])
    if tool.startswith("browser."):
        detail["note"] = (
            "Browser action; only a validated HTTPS origin may be shown. Page content and typed values omitted"
        )
    elif tool in {"shell.exec", "process.start"}:
        detail["note"] = "Tool operation; shell filesystem effects not inspected"
    return detail
