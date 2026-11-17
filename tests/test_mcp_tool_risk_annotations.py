"""MCP directory metadata must describe actual tool risk, not grant permissions."""

import pytest

from commandcore_server.tools import TOOL_DEFINITIONS


TOOLS = {tool["name"]: tool for tool in TOOL_DEFINITIONS}


@pytest.mark.parametrize(
    ("name", "read_only", "open_world", "destructive"),
    [
        ("docker.ps", True, False, False),
        ("docker.inspect", True, False, False),
        ("docker.logs", True, False, False),
        ("fs.read", True, False, False),
        ("fs.write", False, False, True),
        ("fs.patch", False, False, True),
        ("fs.copy", False, False, True),
        ("browser.open", False, True, False),
        ("browser.observe", True, True, False),
        ("browser.elements", True, True, False),
        ("browser.links", True, True, False),
        ("browser.frame", True, True, False),
        ("browser.watch", True, True, False),
        ("browser.follow", False, True, False),
        ("browser.back", False, True, False),
        ("browser.forward", False, True, False),
        ("browser.scroll", False, True, False),
        ("browser.click", False, True, True),
        ("browser.type", False, True, True),
        ("browser.keypress", False, True, True),
        ("browser.close", False, False, True),
        ("browser.handoff", False, False, False),
        ("shell.exec", False, True, True),
        ("system.shutdown", False, False, True),
    ],
)
def test_sensitive_tool_hints_match_actual_risk(
    name, read_only, open_world, destructive
):
    annotations = TOOLS[name]["annotations"]
    assert annotations["readOnlyHint"] is read_only
    assert annotations["openWorldHint"] is open_world
    assert annotations["destructiveHint"] is destructive


def test_all_tool_discovery_annotations_are_explicit_booleans():
    assert len(TOOLS) == len(TOOL_DEFINITIONS)
    for tool in TOOL_DEFINITIONS:
        hints = tool["annotations"]
        assert all(
            isinstance(hints[key], bool)
            for key in ("readOnlyHint", "openWorldHint", "destructiveHint")
        )
        # Client hints must not be accidentally promoted into authorization.
        assert tool["securitySchemes"] == tool["_meta"]["securitySchemes"]


@pytest.mark.parametrize(
    ("name", "scope"),
    [
        ("docker.ps", "commandcore:full"),
        ("docker.inspect", "commandcore:full"),
        ("docker.logs", "commandcore:full"),
        ("browser.observe", "commandcore:standard"),
        ("browser.elements", "commandcore:standard"),
        ("browser.links", "commandcore:standard"),
        ("browser.watch", "commandcore:standard"),
        ("browser.frame", "commandcore:standard"),
    ],
)
def test_read_only_metadata_does_not_downgrade_oauth_scope(name, scope):
    # Docker reads still require FULL; Browser reads still require STANDARD.
    # Risk hints do not change either security boundary.
    assert TOOLS[name]["securitySchemes"] == [
        {"type": "oauth2", "scopes": [scope]}
    ]
