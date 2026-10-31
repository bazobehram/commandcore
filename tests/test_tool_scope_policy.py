"""Published MCP OAuth metadata must match actual authorization scope checks."""

import pytest
from commandcore_server.auth import (
    ADMIN_SCOPE,
    FULL_SCOPE,
    READ_SCOPE,
    STANDARD_SCOPE,
    scope_allows,
)
from commandcore_server.tool_scope_policy import required_oauth_scope
from commandcore_server.tools import TOOL_DEFINITIONS, ToolService

# Independent guard prevents an accidental weakening of this explicit list.
FULL_ONLY = {
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
    "agents.deliver",
}


def test_advertised_tool_scopes_match_runtime_gate():
    names = [tool["name"] for tool in TOOL_DEFINITIONS]
    assert names and len(names) == len(set(names))
    for tool in TOOL_DEFINITIONS:
        actual = ToolService._required_scope(tool["name"])
        assert actual in {READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE}
        assert tool["securitySchemes"] == [{"type": "oauth2", "scopes": [actual]}]
        assert tool["_meta"]["securitySchemes"] == tool["securitySchemes"]


def test_high_privilege_scopes_remain_explicit_and_not_admin():
    names = {tool["name"] for tool in TOOL_DEFINITIONS}
    assert FULL_ONLY <= names
    assert {
        name for name in names if ToolService._required_scope(name) == FULL_SCOPE
    } == FULL_ONLY
    for name in FULL_ONLY:
        assert not scope_allows(
            (READ_SCOPE, STANDARD_SCOPE), ToolService._required_scope(name)
        )
        assert not scope_allows((ADMIN_SCOPE,), ToolService._required_scope(name))


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("devices.select", READ_SCOPE),
        ("auth.whoami", READ_SCOPE),
        ("fs.read", READ_SCOPE),
        ("shell.exec", STANDARD_SCOPE),
        ("fs.write", STANDARD_SCOPE),
        ("docker.ps", FULL_SCOPE),
        ("system.reboot", FULL_SCOPE),
        ("unexpected.future.tool", STANDARD_SCOPE),
    ],
)
def test_known_contract_and_unchanged_unknown_name_fallback(name, expected):
    assert ToolService._required_scope(name) == expected
    assert required_oauth_scope(name, ()) == (
        READ_SCOPE
        if name == "devices.select"
        else FULL_SCOPE
        if name in FULL_ONLY
        else STANDARD_SCOPE
    )
