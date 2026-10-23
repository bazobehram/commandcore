"""Render the real MCP task resource and exercise it in isolated Chromium.

Install tests/ui dependencies with npm ci, then npx playwright install chromium.
CHROMIUM_PATH optionally selects an already installed test-only Chromium.
No signed-in browser or production service is used by these fixtures.
"""

import asyncio
import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

from commandcore_server import browser_gateway
from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.live_activity import LiveActivity
from commandcore_server.mcp import MCPHandler, TASK_UI_URI
from commandcore_server.metrics import Metrics
from commandcore_server.models import Principal


async def render(directory):
    os.environ["COMMANDCORE_UI_TASK_DB"] = str(directory / "tasks.sqlite3")
    handler = MCPHandler(
        SimpleNamespace(live_activity=LiveActivity()), Metrics(), "UI fixture"
    )

    class Request:
        headers = {"mcp-protocol-version": "2025-11-25"}

        async def json(self):
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {"uri": TASK_UI_URI},
            }

    principal = Principal(
        subject="fixture-owner",
        issuer="https://issuer.example",
        client_id="fixture-client",
        auth_kind="oauth2",
        scopes=(READ_SCOPE, STANDARD_SCOPE),
    )
    module = ast.parse(Path(browser_gateway.__file__).read_text())
    links_function = next(
        node
        for node in ast.walk(module)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_visible_links"
    )
    links = next(
        node.value.value
        for node in ast.walk(links_function)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "expression"
            for target in node.targets
        )
    )
    follow = next(
        node.func.value.value
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and "[POSITION]" in node.func.value.value
    )
    (directory / "link-scripts.json").write_text(
        json.dumps({"links": links, "follow": follow})
    )
    response = await handler.handle(Request(), principal)
    resource = json.loads(response.body)["result"]["contents"][0]
    (directory / "task-rendered.html").write_text(resource["text"])
    (directory / "sizing-meta.json").write_text(json.dumps(resource["_meta"]))


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="commandcore-ui-") as temporary:
        directory = Path(temporary)
        asyncio.run(render(directory))
        env = {**os.environ, "COMMANDCORE_UI_FIXTURES": str(directory)}
        for test in sorted((root / "tests/ui").glob("test_*.cjs")):
            subprocess.run(["node", str(test)], env=env, check=True, timeout=120)


if __name__ == "__main__":
    main()
