"""Read-only post-deployment guard for the ChatGPT shell timeout policy.

Use against the actual running CommandCore container. No OAuth token, shell
execution on enrolled devices, database access or secret output is required.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
REQUIRED_TOOLS = {"shell.exec", "process.start", "process.status", "process.output"}
RUNTIME_SNIPPET = """
import json
from commandcore_server import agent_gateway, tools
names = tools.CORE_TOOL_NAMES
print(json.dumps({
    'tool_count': len(names),
    'required_tools': sorted(name for name in ('shell.exec', 'process.start', 'process.status', 'process.output') if name in names),
    'default_ms': getattr(tools, 'OAUTH_SHELL_DEFAULT_TIMEOUT_MS', None),
    'max_ms': getattr(tools, 'OAUTH_SHELL_MAX_TIMEOUT_MS', None),
    'send_seconds': getattr(agent_gateway, 'SHORT_SHELL_SEND_SECONDS', None),
    'cancel_seconds': getattr(agent_gateway, 'SHORT_SHELL_CANCEL_SECONDS', None),
}))
"""


def command_output(args: list[str]) -> str:
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=12, check=False
    )
    if result.returncode != 0:
        raise ValueError("docker_probe_failed")
    return result.stdout


def verify(container: str, expected_tools: int | None = None) -> dict:
    if not CONTAINER_NAME.fullmatch(container):
        raise ValueError("invalid_container_name")
    if expected_tools is not None and (
        type(expected_tools) is not int or expected_tools < 1
    ):
        raise ValueError("invalid_expected_tools")
    inspected = json.loads(command_output(["docker", "inspect", container]))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ValueError("invalid_docker_inspection")
    info = inspected[0]
    if (info.get("State") or {}).get("Health", {}).get("Status") != "healthy":
        raise ValueError("container_not_healthy")
    runtime = json.loads(
        command_output(["docker", "exec", container, "python3", "-c", RUNTIME_SNIPPET])
    )
    for key, expected in (
        ("default_ms", 8000),
        ("max_ms", 10000),
        ("send_seconds", 3.0),
        ("cancel_seconds", 2.0),
    ):
        if runtime.get(key) != expected:
            raise ValueError("timeout_policy_drift")
    if not REQUIRED_TOOLS.issubset(set(runtime.get("required_tools", []))):
        raise ValueError("managed_process_tools_missing")
    count = runtime.get("tool_count")
    if type(count) is not int or count < len(REQUIRED_TOOLS):
        raise ValueError("invalid_tool_count")
    if expected_tools is not None and count != expected_tools:
        raise ValueError("tool_count_drift")
    return {
        "status": "PASS",
        "container": container,
        "tool_count": count,
        "shell_default_ms": 8000,
        "shell_max_ms": 10000,
        "managed_process_tools": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--expected-tools", type=int)
    args = parser.parse_args()
    try:
        result = verify(args.container, args.expected_tools)
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        # Deliberately avoid printing command output, container environment or secrets.
        print(
            "FAIL: "
            + (str(exc) if isinstance(exc, ValueError) else "probe_unavailable"),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
