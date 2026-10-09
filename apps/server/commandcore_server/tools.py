from __future__ import annotations

import time
import json
from typing import Any

from .agent_gateway import AgentManager
from .auth import READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE, scope_allows
from .db import Database
from .models import Principal
from .permissions import allowed, risk_class
from .activity import argument_summary, source
from .browser_gateway import BROWSER_TOOL_NAMES, BrowserError, BrowserGateway
from .live_activity import LiveActivity


def _device_ref_schema() -> dict[str, Any]:
    return {
        "device_id": {
            "type": "string",
            "description": "Explicit immutable CommandCore device ID. Overrides selection_id.",
        },
        "selection_id": {
            "type": "string",
            "description": "Selection handle returned by devices.select.",
        },
    }


def _obj(
    properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "auth.whoami",
        "title": "My identity and access",
        "description": "Show only the verified identity, issuer, OAuth scopes and effective device grants. Never returns credentials.",
        "inputSchema": _obj({}),
    },
    {
        "name": "devices.list",
        "title": "List devices",
        "description": "List devices authorized for the current owner, including online status, immutable ID, platform, capabilities, and permission profile.",
        "inputSchema": _obj({}),
    },
    {
        "name": "devices.info",
        "title": "Device information",
        "description": "Get one device. Pass device_id, selection_id, or device_ref (exact display name/hostname).",
        "inputSchema": _obj({**_device_ref_schema(), "device_ref": {"type": "string"}}),
    },
    {
        "name": "devices.select",
        "title": "Select device",
        "description": "Resolve an exact device ID/name/hostname and mint a logical selection handle. MCP 2026 is stateless, so pass returned selection_id to later tools. Explicit device_id always overrides selection_id.",
        "inputSchema": _obj(
            {
                "device": {
                    "type": "string",
                    "description": "Immutable ID, exact display name, or exact hostname.",
                }
            },
            ["device"],
        ),
    },
    {
        "name": "fs.list",
        "title": "List directory",
        "description": "List directory entries on a selected device.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
            ["path"],
        ),
    },
    {
        "name": "fs.stat",
        "title": "File status",
        "description": "Return file or directory metadata.",
        "inputSchema": _obj(
            {**_device_ref_schema(), "path": {"type": "string"}}, ["path"]
        ),
    },
    {
        "name": "fs.read",
        "title": "Read file",
        "description": "Read a bounded portion of a text or binary file. Binary data is returned base64 when encoding=base64.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "path": {"type": "string"},
                "offset": {"type": "integer", "minimum": 0},
                "length": {"type": "integer", "minimum": 1, "maximum": 1048576},
                "encoding": {"type": "string", "enum": ["text", "base64"]},
            },
            ["path"],
        ),
    },
    {
        "name": "fs.write",
        "title": "Write file",
        "description": "Write or append text/base64 data using the Agent user's OS privileges. Requires STANDARD or FULL_CONTROL.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "path": {"type": "string"},
                "data": {"type": "string"},
                "mode": {"type": "string", "enum": ["rewrite", "append"]},
                "encoding": {"type": "string", "enum": ["text", "base64"]},
                "create_parents": {"type": "boolean"},
            },
            ["path", "data"],
        ),
    },
    {
        "name": "fs.patch",
        "title": "Patch text file",
        "description": "Apply exact search/replace patches to a UTF-8 regular file. Symlinks are refused unless follow_symlinks=true. Fails if a search block is missing or ambiguous unless replace_all=true.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "path": {"type": "string"},
                "patches": {
                    "type": "array",
                    "items": _obj(
                        {
                            "search": {"type": "string"},
                            "replace": {"type": "string"},
                            "replace_all": {"type": "boolean"},
                        },
                        ["search", "replace"],
                    ),
                },
                "follow_symlinks": {"type": "boolean"},
            },
            ["path", "patches"],
        ),
    },
    {
        "name": "fs.search",
        "title": "Search files",
        "description": "Search names and optionally UTF-8 text below a root without following symlink directories. On capable Agents, exclude_dirs skips exact directory names (for example target, node_modules, .git); max_file_bytes bounds text scanning. Defaults preserve existing searches; .gitignore is not interpreted.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "root": {"type": "string"},
                "query": {"type": "string"},
                "content": {"type": "boolean"},
                "regex": {"type": "boolean"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 1000},
                "exclude_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 100,
                },
                "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 2097152},
            },
            ["root", "query"],
        ),
    },
    {
        "name": "fs.copy",
        "title": "Copy file",
        "description": "Copy a file or directory on one device.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "source": {"type": "string"},
                "destination": {"type": "string"},
                "overwrite": {"type": "boolean"},
            },
            ["source", "destination"],
        ),
    },
    {
        "name": "fs.move",
        "title": "Move file",
        "description": "Move or rename a file or directory on one device.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "source": {"type": "string"},
                "destination": {"type": "string"},
                "overwrite": {"type": "boolean"},
            },
            ["source", "destination"],
        ),
    },
    {
        "name": "fs.delete",
        "title": "Delete path",
        "description": "Delete a file or directory. Recursive directory deletion requires recursive=true.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            ["path"],
        ),
    },
    {
        "name": "shell.exec",
        "title": "Execute shell command",
        "description": "Execute a command through the device's default shell. This is intentionally powerful and requires STANDARD/FULL_CONTROL. Output is bounded and audited; secrets should not be passed in command text.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "command": {"type": "string"},
                "cwd": {"type": "string"},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 3600000},
                "env": {"type": "object", "additionalProperties": {"type": "string"}},
            },
            ["command"],
        ),
    },
    {
        "name": "process.start",
        "title": "Start managed process",
        "description": "Start a shell command and return a process_id. Native Linux Rust Agents retain bounded job output and reconcile jobs across transport and Agent restarts. Legacy Agents retain output while running. Host reboot ends jobs; it does not automatically resume them.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "command": {"type": "string"},
                "cwd": {"type": "string"},
                "env": {"type": "object", "additionalProperties": {"type": "string"}},
            },
            ["command"],
        ),
    },
    {
        "name": "process.list",
        "title": "List processes",
        "description": "List OS processes visible to the Agent user. filter is a case-insensitive literal substring, never regex. On capable Linux Agents, contains_any is OR over literals; pid, parent_pid, uid and Linux single-letter state narrow with AND. CPU time is cumulative seconds, RSS is resident host memory, not GPU memory.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
                "filter": {"type": "string"},
                "contains_any": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 100,
                },
                "pid": {"type": "integer", "minimum": 1},
                "parent_pid": {"type": "integer", "minimum": 0},
                "uid": {"type": "integer", "minimum": 0},
                "state": {
                    "type": "string",
                    "enum": ["R", "S", "D", "Z", "T", "t", "I"],
                },
            }
        ),
    },
    {
        "name": "process.status",
        "title": "Process status",
        "description": "Inspect a CommandCore-managed process_id or an OS pid.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "process_id": {"type": "string"},
                "pid": {"type": "integer", "minimum": 1},
            }
        ),
    },
    {
        "name": "process.output",
        "title": "Process output",
        "description": "Read captured stdout/stderr for a process started by CommandCore. Existing external OS processes generally do not expose historical stdout and return output_unavailable. New native Linux captures expose per-stream retained/observed bytes, truncated, complete and last_output_at. Legacy truncation is unknown; incomplete capture cannot prove complete output.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "process_id": {"type": "string"},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1048576},
            },
            ["process_id"],
        ),
    },
    {
        "name": "process.stop",
        "title": "Stop process",
        "description": "Terminate a CommandCore-managed process; may also signal an OS pid when permitted.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "process_id": {"type": "string"},
                "pid": {"type": "integer", "minimum": 1},
                "force": {"type": "boolean"},
            }
        ),
    },
    {
        "name": "system.info",
        "title": "System information",
        "description": "Return hostname, OS, architecture, Python/Agent versions, boot time and hardware summary.",
        "inputSchema": _obj(_device_ref_schema()),
    },
    {
        "name": "system.metrics",
        "title": "System metrics",
        "description": "Return current CPU, memory, disk and load metrics. Capable Linux Agents also return health with contextual pressure conditions, Linux PSI, and optional accelerator utilization/memory plus compute PIDs. Unsupported metrics are explicit; unified/GPU memory can overlap host RAM. No automatic cleanup or termination.",
        "inputSchema": _obj(_device_ref_schema()),
    },
    {
        "name": "transfer.upload",
        "title": "Upload file",
        "description": "Upload base64 data to a file on the selected device. Phase 1 payloads are bounded by server configuration.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "path": {"type": "string"},
                "data_base64": {"type": "string"},
                "overwrite": {"type": "boolean"},
            },
            ["path", "data_base64"],
        ),
    },
    {
        "name": "transfer.download",
        "title": "Download file",
        "description": "Download a bounded file as base64. For large files a future streaming transfer capability will replace this Phase 1 mechanism.",
        "inputSchema": _obj(
            {**_device_ref_schema(), "path": {"type": "string"}}, ["path"]
        ),
    },
    {
        "name": "git.status",
        "title": "Git status",
        "description": "Return porcelain Git status for a repository without invoking a shell.",
        "inputSchema": _obj(
            {**_device_ref_schema(), "repo": {"type": "string"}}, ["repo"]
        ),
    },
    {
        "name": "git.diff",
        "title": "Git diff",
        "description": "Return a bounded Git diff. Supports staged and path filters.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "repo": {"type": "string"},
                "staged": {"type": "boolean"},
                "paths": {"type": "array", "items": {"type": "string"}},
                "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 1048576},
            },
            ["repo"],
        ),
    },
    {
        "name": "git.log",
        "title": "Git log",
        "description": "Return recent Git commits as structured records.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "repo": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            ["repo"],
        ),
    },
    {
        "name": "git.run",
        "title": "Run Git",
        "description": "Run a Git subcommand using argv (no shell interpolation). Requires STANDARD or FULL_CONTROL.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "repo": {"type": "string"},
                "args": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 600000},
            },
            ["repo", "args"],
        ),
    },
    {
        "name": "docker.ps",
        "title": "List containers",
        "description": "List Docker containers. Docker daemon access is treated as FULL_CONTROL because it is root-equivalent on typical Linux hosts.",
        "inputSchema": _obj({**_device_ref_schema(), "all": {"type": "boolean"}}),
    },
    {
        "name": "docker.inspect",
        "title": "Inspect Docker object",
        "description": "Inspect a Docker container/image/network/volume by ID or name. FULL_CONTROL required.",
        "inputSchema": _obj(
            {**_device_ref_schema(), "object": {"type": "string"}}, ["object"]
        ),
    },
    {
        "name": "docker.logs",
        "title": "Docker logs",
        "description": "Read bounded Docker container logs. FULL_CONTROL required.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "container": {"type": "string"},
                "tail": {"type": "integer", "minimum": 1, "maximum": 10000},
                "timestamps": {"type": "boolean"},
            },
            ["container"],
        ),
    },
    {
        "name": "docker.exec",
        "title": "Docker exec",
        "description": "Execute argv in a running container without shell interpolation. FULL_CONTROL required.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "container": {"type": "string"},
                "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 600000},
            },
            ["container", "argv"],
        ),
    },
    {
        "name": "docker.run",
        "title": "Docker run",
        "description": "Run a Docker container with explicit argv. FULL_CONTROL required and audited.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "image": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "remove": {"type": "boolean"},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 3600000},
            },
            ["image"],
        ),
    },
    {
        "name": "services.manage",
        "title": "Manage system service",
        "description": "FULL_CONTROL Linux service management through the local privileged helper. Supports status/start/stop/restart/reload/enable/disable.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "service": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": [
                        "status",
                        "start",
                        "stop",
                        "restart",
                        "reload",
                        "enable",
                        "disable",
                    ],
                },
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 600000},
            },
            ["service", "action"],
        ),
    },
    {
        "name": "package.install",
        "title": "Install packages",
        "description": "FULL_CONTROL package installation through the local privileged helper. Package names are passed as argv, not interpolated into a shell command.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "packages": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                },
                "manager": {
                    "type": "string",
                    "enum": [
                        "auto",
                        "apt-get",
                        "dnf",
                        "yum",
                        "zypper",
                        "pacman",
                        "apk",
                    ],
                },
                "update": {"type": "boolean"},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 3600000},
            },
            ["packages"],
        ),
    },
    {
        "name": "system.reboot",
        "title": "Reboot system",
        "description": "FULL_CONTROL reboot through the local privileged helper. Requires confirm=true. dry_run=true validates the path without rebooting.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "confirm": {"type": "boolean"},
                "dry_run": {"type": "boolean"},
                "delay_seconds": {"type": "integer", "minimum": 0, "maximum": 3600},
            },
            ["confirm"],
        ),
    },
    {
        "name": "system.shutdown",
        "title": "Shutdown system",
        "description": "FULL_CONTROL shutdown through the local privileged helper. Requires confirm=true. dry_run=true validates the path without powering off.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "confirm": {"type": "boolean"},
                "dry_run": {"type": "boolean"},
                "delay_seconds": {"type": "integer", "minimum": 0, "maximum": 3600},
            },
            ["confirm"],
        ),
    },
    {
        "name": "desktop.windows",
        "title": "List desktop windows",
        "description": "List visible top-level desktop windows when the device has an interactive GUI session.",
        "inputSchema": _obj(_device_ref_schema()),
    },
    {
        "name": "screen.capture",
        "title": "Capture screen",
        "description": "Capture the current interactive desktop as PNG/base64. Requires an active desktop session on the target device.",
        "inputSchema": _obj(_device_ref_schema()),
    },
    {
        "name": "mouse.click",
        "title": "Click desktop",
        "description": "Move the pointer to absolute screen coordinates and click. Requires STANDARD/FULL_CONTROL and an interactive desktop session.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "x": {"type": "integer"},
                "y": {"type": "integer"},
                "button": {"type": "string", "enum": ["left", "middle", "right"]},
                "double": {"type": "boolean"},
            },
            ["x", "y"],
        ),
    },
    {
        "name": "keyboard.type",
        "title": "Type text",
        "description": "Type text into the focused desktop application. Requires STANDARD/FULL_CONTROL.",
        "inputSchema": _obj(
            {**_device_ref_schema(), "text": {"type": "string"}}, ["text"]
        ),
    },
    {
        "name": "keyboard.keypress",
        "title": "Press keys",
        "description": "Send a key or key chord to the focused desktop application.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "keys": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            },
            ["keys"],
        ),
    },
    {
        "name": "clipboard.read",
        "title": "Read clipboard",
        "description": "Read text from the interactive user's clipboard.",
        "inputSchema": _obj(_device_ref_schema()),
    },
    {
        "name": "clipboard.write",
        "title": "Write clipboard",
        "description": "Replace the interactive user's clipboard text. Requires STANDARD/FULL_CONTROL.",
        "inputSchema": _obj(
            {**_device_ref_schema(), "text": {"type": "string"}}, ["text"]
        ),
    },
    {
        "name": "agent.update.status",
        "title": "Agent update status",
        "description": "Read the device-local signed rollout state and whether a trusted release key is configured.",
        "inputSchema": _obj(_device_ref_schema()),
    },
    {
        "name": "agent.update.stage",
        "title": "Stage signed Agent update",
        "description": "FULL_CONTROL: fetch and stage an HTTPS Agent release manifest. The release signing key is device-local/root-owned and cannot be supplied by the MCP caller.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "manifest_url": {"type": "string", "format": "uri"},
            },
            ["manifest_url"],
        ),
    },
    {
        "name": "agent.update.activate",
        "title": "Activate staged Agent update",
        "description": "FULL_CONTROL: re-verify and activate a staged Agent release through the privileged helper. A fresh authenticated health marker is required or the local updater rolls back automatically.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "stage_metadata_path": {"type": "string"},
                "health_timeout_seconds": {
                    "type": "number",
                    "minimum": 5,
                    "maximum": 300,
                },
            },
            ["stage_metadata_path"],
        ),
    },
    {
        "name": "agent.update.rollback",
        "title": "Rollback Agent update",
        "description": "FULL_CONTROL: roll back to the previous committed Agent release and require fresh health before reporting success.",
        "inputSchema": _obj(
            {
                **_device_ref_schema(),
                "health_timeout_seconds": {
                    "type": "number",
                    "minimum": 5,
                    "maximum": 300,
                },
            }
        ),
    },
]

# Optional server-local visual browser; disabled unless explicitly configured.
# No device Agent or FULL_CONTROL permission is required for these tools.
TOOL_DEFINITIONS.extend(
    [
        {
            "name": "browser.open",
            "title": "Open visual browser page",
            "description": "Open an allowlisted HTTPS page in an isolated, owner-scoped browser session. Returns a screenshot and untrusted page text.",
            "inputSchema": _obj(
                {"url": {"type": "string", "minLength": 12, "maxLength": 2048}}, ["url"]
            ),
        },
        {
            "name": "browser.observe",
            "title": "Observe visual browser",
            "description": "Capture the current browser viewport and read limited visible text; webpage text is untrusted.",
            "inputSchema": _obj({}),
        },
        {
            "name": "browser.move",
            "title": "Move browser mouse",
            "description": "Move the browser mouse to viewport coordinates and observe the result.",
            "inputSchema": _obj(
                {
                    "x": {"type": "integer", "minimum": 0, "maximum": 1280},
                    "y": {"type": "integer", "minimum": 0, "maximum": 800},
                },
                ["x", "y"],
            ),
        },
        {
            "name": "browser.click",
            "title": "Click visual browser",
            "description": "Click a point in the browser viewport; can activate website actions.",
            "inputSchema": _obj(
                {
                    "x": {"type": "integer", "minimum": 0, "maximum": 1280},
                    "y": {"type": "integer", "minimum": 0, "maximum": 800},
                },
                ["x", "y"],
            ),
        },
        {
            "name": "browser.type",
            "title": "Type in visual browser",
            "description": "Type text into the focused web input, potentially submitting sensitive information to the current website.",
            "inputSchema": _obj(
                {"text": {"type": "string", "minLength": 1, "maxLength": 2000}},
                ["text"],
            ),
        },
        {
            "name": "browser.keypress",
            "title": "Press browser key",
            "description": "Send a supported key (Enter, Tab, Escape, Backspace or Arrow key) to the focused page.",
            "inputSchema": _obj(
                {
                    "key": {
                        "type": "string",
                        "enum": [
                            "Enter",
                            "Tab",
                            "Escape",
                            "Backspace",
                            "ArrowUp",
                            "ArrowDown",
                            "ArrowLeft",
                            "ArrowRight",
                        ],
                    }
                },
                ["key"],
            ),
        },
        {
            "name": "browser.scroll",
            "title": "Scroll visual browser",
            "description": "Scroll the browser viewport in pixels.",
            "inputSchema": _obj(
                {"delta_y": {"type": "integer", "minimum": -1000, "maximum": 1000}},
                ["delta_y"],
            ),
        },
        {
            "name": "browser.watch",
            "title": "Show browser in chat",
            "description": "After browser.open, render a read-only interactive visual browser viewer inside ChatGPT. The user can optionally refresh screenshots, enable low-rate auto-refresh or request authenticated human control.",
            "inputSchema": _obj({}),
        },
        {
            "name": "browser.handoff",
            "title": "Pause browser for human control",
            "description": "Pause AI browser actions and issue a 10-minute authenticated operator console link; a matching CommandCore account must sign in to use it.",
            "inputSchema": _obj({}),
        },
        {
            "name": "browser.close",
            "title": "Close visual browser session",
            "description": "Release only this authenticated caller's browser session.",
            "inputSchema": _obj({}),
        },
    ]
)

# Read-only owner-scoped CommandCore tool activity, not a browser screen.
ACTIVITY_TOOL_NAMES = {"activity.feed", "activity.watch", "commandcore.watch"}
TOOL_DEFINITIONS.extend(
    [
        {
            "name": "activity.feed",
            "title": "Read live CommandCore activity",
            "description": "Owner-scoped running and recent operations, devices, duration and status. No command text, arguments or output.",
            "inputSchema": _obj(
                {"limit": {"type": "integer", "minimum": 1, "maximum": 50}}
            ),
        },
        {
            "name": "activity.watch",
            "title": "Show CommandCore activity in chat",
            "description": "Read-only Live Activity panel for compatible MCP Apps clients.",
            "inputSchema": _obj({}),
        },
        {
            "name": "commandcore.watch",
            "title": "Show CommandCore Live Views",
            "description": "Combined, read-only MCP Apps dashboard with Live Activity and optional Live Browser monitor. Browser control still requires its own OAuth scope.",
            "inputSchema": _obj({}),
        },
    ]
)

# MCP annotations are UX/risk hints for clients, never security boundaries.
_READ_ONLY_HINTS = {
    "auth.whoami",
    "devices.list",
    "devices.info",
    "fs.list",
    "fs.stat",
    "fs.read",
    "fs.search",
    "activity.feed",
    "activity.watch",
    "commandcore.watch",
    "process.list",
    "process.status",
    "process.output",
    "system.info",
    "system.metrics",
    "transfer.download",
    "git.status",
    "git.diff",
    "git.log",
    "agent.update.status",
    "desktop.windows",
    "screen.capture",
    "clipboard.read",
}
_DESTRUCTIVE_HINTS = {
    "fs.move",
    "fs.delete",
    "shell.exec",
    "process.start",
    "process.stop",
    "transfer.upload",
    "mouse.click",
    "keyboard.type",
    "keyboard.keypress",
    "clipboard.write",
    "services.manage",
    "system.reboot",
    "system.shutdown",
    "git.run",
    "docker.exec",
    "docker.run",
    "agent.update.stage",
    "agent.update.activate",
    "agent.update.rollback",
    "browser.click",
    "browser.type",
    "browser.keypress",
}
_OPEN_WORLD_HINTS = {
    "shell.exec",
    "process.start",
    "package.install",
    "git.run",
    "docker.exec",
    "docker.run",
    "agent.update.stage",
}
for _tool in TOOL_DEFINITIONS:
    _name = _tool["name"]
    _read_only = _name in _READ_ONLY_HINTS or _name == "browser.watch"
    _tool["annotations"] = {
        "title": _tool.get("title", _name),
        "readOnlyHint": _read_only,
        "destructiveHint": False if _read_only else _name in _DESTRUCTIVE_HINTS,
        "idempotentHint": _read_only,
        "openWorldHint": _name in _OPEN_WORLD_HINTS,
    }
    if _name in {
        "services.manage",
        "package.install",
        "system.reboot",
        "system.shutdown",
        "docker.ps",
        "docker.inspect",
        "docker.logs",
        "docker.exec",
        "docker.run",
        "agent.update.stage",
        "agent.update.activate",
        "agent.update.rollback",
    }:
        _scope = FULL_SCOPE
    elif _name in _READ_ONLY_HINTS or _name in {"devices.select"}:
        _scope = READ_SCOPE
    else:
        _scope = STANDARD_SCOPE
    _tool["securitySchemes"] = [{"type": "oauth2", "scopes": [_scope]}]
    # Documented ChatGPT compatibility metadata; generic MCP clients can ignore
    # it. These labels do not prescribe the host's tool orchestration or UI.
    _tool["_meta"] = {
        "securitySchemes": _tool["securitySchemes"],
        "openai/toolInvocation/invoking": f"{_tool['title']}…"[:64],
        "openai/toolInvocation/invoked": f"{_tool['title']}: complete"[:64],
    }

TOOL_NAMES = {x["name"] for x in TOOL_DEFINITIONS}
CORE_TOOL_NAMES = {
    "devices.list",
    "devices.info",
    "devices.select",
    "system.info",
    "system.metrics",
    "fs.list",
    "fs.stat",
    "fs.read",
    "fs.write",
    "fs.patch",
    "fs.search",
    "fs.copy",
    "fs.move",
    "fs.delete",
    "shell.exec",
    "process.list",
    "process.start",
    "process.status",
    "process.output",
    "process.stop",
    "git.status",
    "git.diff",
    "git.log",
    "git.run",
    "transfer.upload",
    "transfer.download",
    "activity.feed",
    "activity.watch",
    "commandcore.watch",
}
CORE_TOOL_DEFINITIONS = [
    tool for tool in TOOL_DEFINITIONS if tool["name"] in CORE_TOOL_NAMES
]
DEVICE_TOOLS = (
    TOOL_NAMES
    - {"devices.list", "devices.info", "devices.select"}
    - BROWSER_TOOL_NAMES
    - ACTIVITY_TOOL_NAMES
)
DEFAULT_TIMEOUT_MS = {
    "services.manage": 120000,
    "package.install": 3600000,
    "system.reboot": 30000,
    "system.shutdown": 30000,
    "git.run": 120000,
    "docker.ps": 30000,
    "docker.inspect": 30000,
    "docker.logs": 30000,
    "docker.exec": 120000,
    "docker.run": 3600000,
    "agent.update.status": 30000,
    "agent.update.stage": 360000,
    "agent.update.activate": 120000,
    "agent.update.rollback": 120000,
}


class ToolError(Exception):
    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


class ToolService:
    def __init__(
        self,
        db: Database,
        agents: AgentManager,
        selection_ttl_seconds: int,
        browser: BrowserGateway | None = None,
    ):
        self.db = db
        self.agents = agents
        self.selection_ttl_seconds = selection_ttl_seconds
        self.browser = browser
        self.live_activity = LiveActivity()

    @staticmethod
    def _profile_rank(profile: str) -> int:
        return {"READ_ONLY": 0, "STANDARD": 1, "FULL_CONTROL": 2}.get(profile, 0)

    @classmethod
    def _min_profile(cls, *profiles: str) -> str:
        rank = min(cls._profile_rank(p) for p in profiles)
        return ("READ_ONLY", "STANDARD", "FULL_CONTROL")[rank]

    @staticmethod
    def _required_scope(name: str) -> str:
        if name in {
            "services.manage",
            "package.install",
            "system.reboot",
            "system.shutdown",
            "docker.ps",
            "docker.inspect",
            "docker.logs",
            "docker.exec",
            "docker.run",
            "agent.update.stage",
            "agent.update.activate",
            "agent.update.rollback",
        }:
            return FULL_SCOPE
        if name in _READ_ONLY_HINTS or name in {"devices.select"}:
            return READ_SCOPE
        return STANDARD_SCOPE

    def _require_scope(self, principal: Principal, name: str) -> None:
        # Bootstrap/panel auth are deployment-admin paths and predate OAuth scopes.
        if principal.auth_kind in {"bootstrap-bearer", "panel-cookie"}:
            return
        required = self._required_scope(name)
        if not scope_allows(principal.scopes, required):
            raise ToolError(
                "insufficient_scope", f"{name} requires OAuth scope {required}"
            )

    def _resolve_device(
        self, principal: Principal, args: dict[str, Any]
    ) -> dict[str, Any]:
        if args.get("device_id"):
            device_id = str(args["device_id"])
        elif args.get("selection_id"):
            try:
                device_id = self.db.resolve_selection(
                    principal.subject, str(args["selection_id"])
                )
            except KeyError as exc:
                raise ToolError("selection_not_found_or_expired") from exc
        else:
            devices = [
                d
                for d in self.db.list_accessible_devices(principal.subject)
                if not d["revoked_at"]
            ]
            if len(devices) == 1:
                return devices[0]
            raise ToolError(
                "device_required",
                "Pass device_id or selection_id when more than one device is registered.",
            )
        device = self.db.get_accessible_device(principal.subject, device_id)
        if not device:
            raise ToolError("device_not_found")
        if device["revoked_at"]:
            raise ToolError("device_revoked")
        return device

    async def call(
        self, principal: Principal, name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        started = time.perf_counter()
        device_id: str | None = None
        execution_id: str | None = None
        status = "ok"
        exit_code: int | None = None
        source_token = source.set(
            {"auth_kind": principal.auth_kind, "client_id": principal.client_id}
        )
        live_key: str | None = None
        try:
            self._require_scope(principal, name)
            if name == "activity.feed":
                limit = args.get("limit", 25)
                if type(limit) is not int or not 1 <= limit <= 50:
                    raise ToolError("invalid_limit")
                return self.live_activity.snapshot(
                    principal,
                    self.db.recent_audit(principal.subject, limit=100),
                    self.db.list_accessible_devices(principal.subject),
                    limit,
                )
            if name == "activity.watch":
                return {"state": "monitor_ready", "mode": "read_only"}
            if name == "commandcore.watch":
                return {
                    "state": "dashboard_ready",
                    "mode": "read_only",
                    "browser_available": self.browser is not None,
                }
            live_key = self.live_activity.begin(principal, name)
            if name == "auth.whoami":
                devices = self.db.list_accessible_devices(principal.subject)
                rank = {"READ_ONLY": 0, "STANDARD": 1, "FULL_CONTROL": 2}
                grants = []
                for d in devices:
                    if d["revoked_at"]:
                        continue
                    oauth_ceiling = (
                        "FULL_CONTROL"
                        if principal.auth_kind in {"bootstrap-bearer", "panel-cookie"}
                        or scope_allows(principal.scopes, FULL_SCOPE)
                        else "STANDARD"
                        if scope_allows(principal.scopes, STANDARD_SCOPE)
                        else "READ_ONLY"
                    )
                    profiles = [
                        d["permission_profile"],
                        d["access_max_permission_profile"],
                        d["capabilities"].get(
                            "local_max_permission_profile", "STANDARD"
                        ),
                        oauth_ceiling,
                    ]
                    effective = min(profiles, key=lambda p: rank.get(p, 0))
                    grants.append(
                        {
                            "device_id": d["id"],
                            "display_name": d["display_name"],
                            "grant_ceiling": d["access_max_permission_profile"],
                            "effective_permission": effective,
                        }
                    )
                return {
                    "subject": principal.subject,
                    "issuer": principal.issuer or None,
                    "oauth_scopes": list(principal.scopes),
                    "device_grants": grants,
                }
            if name == "devices.list":
                return {
                    "devices": [
                        d
                        for d in self.db.list_accessible_devices(principal.subject)
                        if not d["revoked_at"]
                    ]
                }
            if name == "devices.select":
                try:
                    device = self.db.resolve_accessible_device(
                        principal.subject, str(args.get("device", ""))
                    )
                except (KeyError, ValueError, PermissionError) as exc:
                    raise ToolError(str(exc).strip("'")) from exc
                self.live_activity.set_device(live_key, device["id"])
                sel = self.db.create_selection(
                    principal.subject, device["id"], self.selection_ttl_seconds
                )
                return {**sel, "device": device}
            if name == "devices.info":
                if args.get("device_ref"):
                    try:
                        return {
                            "device": self.db.resolve_accessible_device(
                                principal.subject, str(args["device_ref"])
                            )
                        }
                    except (KeyError, ValueError, PermissionError) as exc:
                        raise ToolError(str(exc).strip("'")) from exc
                device = self._resolve_device(principal, args)
                return {"device": device}

            if name in BROWSER_TOOL_NAMES:
                if self.browser is None:
                    raise ToolError("browser_disabled")
                try:
                    return await self.browser.call(
                        subject=principal.subject,
                        issuer=principal.issuer,
                        client_id=principal.client_id,
                        name=name,
                        args=args,
                    )
                except BrowserError as exc:
                    raise ToolError("browser_error", str(exc)) from exc

            if name not in DEVICE_TOOLS:
                raise ToolError("unknown_tool")
            device = self._resolve_device(principal, args)
            device_id = device["id"]
            self.live_activity.set_device(live_key, device_id)
            if device["status"] != "online":
                raise ToolError("device_offline")
            access_max = str(
                device.get(
                    "access_max_permission_profile",
                    "FULL_CONTROL" if device.get("is_owner") else "READ_ONLY",
                )
            )
            oauth_ceiling = (
                "FULL_CONTROL"
                if principal.auth_kind in {"bootstrap-bearer", "panel-cookie"}
                or scope_allows(principal.scopes, FULL_SCOPE)
                else "STANDARD"
                if scope_allows(principal.scopes, STANDARD_SCOPE)
                else "READ_ONLY"
            )
            effective_profile = self._min_profile(
                str(device["permission_profile"]),
                access_max,
                str(
                    device.get("capabilities", {}).get(
                        "local_max_permission_profile", "STANDARD"
                    )
                ),
                oauth_ceiling,
            )
            if not allowed(effective_profile, name):
                raise ToolError(
                    "permission_denied",
                    f"{name} is not allowed by effective profile {effective_profile}",
                )
            device = dict(device)
            device["permission_profile"] = effective_profile
            forwarded = {
                k: v for k, v in args.items() if k not in {"device_id", "selection_id"}
            }
            # Older Agents must not silently ignore a narrowing filter.
            capabilities = device.get("capabilities", {})
            if (
                name == "process.list"
                and any(
                    k in forwarded
                    for k in ("contains_any", "pid", "parent_pid", "uid", "state")
                )
                and not capabilities.get("structured_process_filters")
            ):
                raise ToolError(
                    "unsupported_argument",
                    "This Agent does not support structured process filters; use the literal filter.",
                )
            if (
                name == "fs.search"
                and any(k in forwarded for k in ("exclude_dirs", "max_file_bytes"))
                and not capabilities.get("search_exclusions")
            ):
                raise ToolError(
                    "unsupported_argument",
                    "This Agent does not support search exclusions or size selection.",
                )
            timeout_ms = int(
                forwarded.get("timeout_ms", DEFAULT_TIMEOUT_MS.get(name, 30000))
            )
            result = await self.agents.dispatch(
                owner_id=principal.subject,
                device=device,
                tool=name,
                arguments=forwarded,
                timeout_ms=timeout_ms,
            )
            execution_id = result.execution_id
            status = result.status
            exit_code = result.exit_code
            payload = {
                "execution_id": result.execution_id,
                "status": result.status,
                "exit_code": result.exit_code,
                "result": result.result,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "output_capture": result.output_capture,
                "summary": f"{name} on {device['display_name']}: {result.status}",
            }
            if result.error:
                payload["error"] = result.error
            if result.status not in {"ok", "completed", "started"}:
                raise ToolError("remote_execution_failed", str(payload))
            return payload
        except ToolError:
            status = "error"
            raise
        except Exception as exc:
            status = "error"
            raise ToolError("internal_error", str(exc)) from exc
        finally:
            source.reset(source_token)
            duration_ms = int((time.perf_counter() - started) * 1000)
            try:
                if name != "activity.feed":
                    self.db.add_audit(
                        user_id=principal.subject,
                        client_id=principal.client_id,
                        device_id=device_id,
                        tool=name if name in TOOL_NAMES else "unknown_tool",
                        args_summary=json.dumps(
                            argument_summary(args), separators=(",", ":")
                        ),
                        execution_id=execution_id,
                        status=status,
                        duration_ms=duration_ms,
                        exit_code=exit_code,
                        risk_class=risk_class(name),
                    )
            finally:
                self.live_activity.finish(live_key)
