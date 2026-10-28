"""Protect the stable ChatGPT-facing tool registry."""

import importlib.util
from pathlib import Path


def module():
    path = Path(__file__).resolve().parents[1] / "scripts/mcp_release_gate.py"
    spec = importlib.util.spec_from_file_location("mcp_release_gate", path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def test_baseline_is_unchanged():
    gate = module()
    import json

    baseline = json.loads(gate.BASELINE.read_text())
    assert gate.check(gate.snapshot(gate.TOOL_DEFINITIONS), baseline) == []
    from commandcore_server.tools import CORE_TOOL_NAMES

    assert {tool["name"] for tool in gate.TOOL_DEFINITIONS} == CORE_TOOL_NAMES


def test_added_tool_requires_refresh():
    gate = module()
    prior = {"one": {"inputSchema": {}, "description": "", "title": ""}}
    modified = {**prior, "two": {"inputSchema": {}, "description": "", "title": ""}}
    assert "ADDED tool: two" in gate.check(modified, prior)


def test_schema_change_requires_refresh():
    gate = module()
    old = {"one": {"inputSchema": {"type": "object"}, "description": "", "title": ""}}
    new = {"one": {**old["one"], "inputSchema": {"type": "string"}}}
    assert "SCHEMA changed: one" in gate.check(new, old)


def test_backend_code_change_does_not_require_refresh():
    gate = module()
    before = gate.snapshot(gate.TOOL_DEFINITIONS)
    after = gate.snapshot(gate.TOOL_DEFINITIONS)
    assert gate.check(after, before) == []
