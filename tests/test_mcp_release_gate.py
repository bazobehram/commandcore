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
    assert len(gate.TOOL_DEFINITIONS) == 48
    assert {"activity.feed", "activity.watch", "commandcore.watch"} <= set(baseline)


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


def test_activity_widget_schema_change_requires_refresh():
    gate = module()
    before = gate.snapshot(gate.TOOL_DEFINITIONS)
    modified = {name: dict(contract) for name, contract in before.items()}
    modified["activity.watch"]["inputSchema"] = {"type": "string"}
    assert "SCHEMA changed: activity.watch" in gate.check(modified, before)


def test_activity_widget_description_change_requires_refresh():
    gate = module()
    before = gate.snapshot(gate.TOOL_DEFINITIONS)
    modified = {name: dict(contract) for name, contract in before.items()}
    modified["commandcore.watch"]["description"] += " changed"
    assert "METADATA changed: commandcore.watch" in gate.check(modified, before)


def test_backend_code_change_does_not_require_refresh():
    gate = module()
    before = gate.snapshot(gate.TOOL_DEFINITIONS)
    after = gate.snapshot(gate.TOOL_DEFINITIONS)
    assert gate.check(after, before) == []
