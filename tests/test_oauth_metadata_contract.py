from commandcore_server.auth import ALL_SCOPES
from commandcore_server.tools import TOOL_DEFINITIONS


def test_every_tool_declares_oauth_security_scheme():
    assert TOOL_DEFINITIONS
    for tool in TOOL_DEFINITIONS:
        schemes = tool.get("securitySchemes")
        assert schemes and schemes[0]["type"] == "oauth2"
        assert schemes[0]["scopes"][0] in ALL_SCOPES
