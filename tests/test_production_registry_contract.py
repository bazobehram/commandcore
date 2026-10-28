"""Compatibility gate for the observed private-production MCP registry.

This checks declarations, not the authentication boundary or ChatGPT end-to-end.
The checked-in baseline is a schema-only snapshot; it contains no tenant data.
"""

import json
from pathlib import Path

from commandcore_server.tools import TOOL_DEFINITIONS


BASELINE = Path(__file__).parent / "fixtures/private-production-tool-schemas.json"


def test_existing_production_tool_names_and_schemas_are_preserved():
    expected = json.loads(BASELINE.read_text())
    actual = {tool["name"]: tool["inputSchema"] for tool in TOOL_DEFINITIONS}
    assert len(actual) == len(TOOL_DEFINITIONS), "duplicate tool names"
    missing = sorted(expected.keys() - actual.keys())
    changed = sorted(
        name
        for name in expected.keys() & actual.keys()
        if expected[name] != actual[name]
    )
    assert not missing and not changed, f"missing={missing}, changed_schemas={changed}"


def test_private_production_core_tool_names_are_preserved():
    from commandcore_server.tools import CORE_TOOL_NAMES

    baseline = json.loads(
        (BASELINE.parent / "private-production-core-tools.json").read_text()
    )
    assert set(baseline) == CORE_TOOL_NAMES
