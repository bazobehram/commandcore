"""Fail closed on changes to the registered ChatGPT MCP tool interface.

Backend-only changes retain tool contracts and therefore need no manual
tool rediscovery. A schema change requires a controlled plugin refresh.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path


def load_definitions():
    source = (
        Path(__file__).resolve().parent.parent
        / "apps/server/commandcore_server/tools.py"
    )
    tree = ast.parse(source.read_text())
    approved = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in {
            "_obj",
            "_device_ref_schema",
        }:
            approved.append(node)
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "TOOL_DEFINITIONS"
        ):
            approved.append(node)
    namespace = {"Any": object}
    exec(
        compile(ast.Module(body=approved, type_ignores=[]), str(source), "exec"),
        {"__builtins__": {}},
        namespace,
    )
    definitions = namespace["TOOL_DEFINITIONS"]
    core_names_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "CORE_TOOL_NAMES" for t in node.targets
        )
    )
    core_names = ast.literal_eval(core_names_node.value)
    return [tool for tool in definitions if tool["name"] in core_names]


TOOL_DEFINITIONS = load_definitions()

BASELINE = Path(__file__).resolve().parent.parent / "docs" / "mcp-tool-contract.json"


def snapshot(definitions):
    return {
        tool["name"]: {
            "inputSchema": tool["inputSchema"],
            "description": tool.get("description", ""),
            "title": tool.get("title", ""),
        }
        for tool in definitions
    }


def fingerprint(contracts):
    return hashlib.sha256(
        json.dumps(contracts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def check(current, baseline):
    old, new = set(baseline), set(current)
    changes = []
    for name in sorted(old - new):
        changes.append(f"REMOVED tool: {name}")
    for name in sorted(new - old):
        changes.append(f"ADDED tool: {name}")
    for name in sorted(old & new):
        if current[name]["inputSchema"] != baseline[name]["inputSchema"]:
            changes.append(f"SCHEMA changed: {name}")
        if any(
            current[name].get(k) != baseline[name].get(k)
            for k in ("title", "description")
        ):
            changes.append(f"METADATA changed: {name}")
    return changes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Explicitly approve the current tool definitions as a baseline",
    )
    args = parser.parse_args()
    current = snapshot(TOOL_DEFINITIONS)
    if args.write_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"Baseline written: {len(current)} tools, sha256={fingerprint(current)}")
        return 0
    if not BASELINE.exists():
        parser.error("Missing baseline; explicit approval required")
    baseline = json.loads(BASELINE.read_text())
    changes = check(current, baseline)
    if changes:
        print("MCP REFRESH REQUIRED: tool registration changed:")
        print("\n".join(changes))
        return 1
    print(
        f"MCP COMPATIBLE: {len(current)} tools; sha256={fingerprint(current)}; no rediscovery needed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
