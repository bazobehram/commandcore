"""Discovery metadata scope list must not change execution authorization."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from commandcore_server.auth import (
    ALL_SCOPES,
    ADMIN_SCOPE,
    FULL_SCOPE,
    READ_SCOPE,
    STANDARD_SCOPE,
    scope_allows,
)
from commandcore_server.config import Settings


def _settings(scopes):
    return Settings(
        api_token="x" * 40,
        panel_session_secret="y" * 40,
        oauth_discovery_scopes=scopes,
    )


def test_default_discovery_preserves_known_scope_list():
    settings = _settings(None)
    settings.validate()
    assert settings.oauth_discovery_scopes is None
    assert ALL_SCOPES == (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE, ADMIN_SCOPE)


@pytest.mark.parametrize(
    "scopes",
    [
        (),
        ("",),
        ("commandcore:unknown",),
        ("commandcore:read", "commandcore:read"),
        ("commandcore:read", ""),
        (" commandcore:admin",),
    ],
)
def test_invalid_discovery_scope_filter_fails_closed(scopes):
    with pytest.raises(RuntimeError, match="COMMANDCORE_OAUTH_DISCOVERY_SCOPES"):
        _settings(scopes).validate()


def test_discovery_scope_filter_does_not_grant_admin_or_full_authority():
    configured = (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    settings = _settings(configured)
    settings.validate()
    assert ADMIN_SCOPE not in configured
    assert not scope_allows(configured, ADMIN_SCOPE)
    assert not scope_allows((ADMIN_SCOPE,), FULL_SCOPE)
    assert scope_allows((FULL_SCOPE,), STANDARD_SCOPE)


@pytest.mark.parametrize(
    "scope_value,expected",
    [
        (None, list(ALL_SCOPES)),
        (
            "commandcore:read, commandcore:standard,commandcore:full",
            [READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE],
        ),
    ],
)
def test_real_protected_resource_metadata_uses_configured_scopes(
    tmp_path: Path,
    scope_value: str | None,
    expected: list[str],
):
    # Import the real server in a subprocess with disposable database and
    # synthetic environment: no real provider, device, or user is contacted.
    env = {
        **os.environ,
        "COMMANDCORE_API_TOKEN": "x" * 40,
        "COMMANDCORE_PANEL_SESSION_SECRET": "y" * 40,
        "COMMANDCORE_DB": str(tmp_path / "server.sqlite3"),
        "COMMANDCORE_OAUTH_ENABLED": "true",
        "COMMANDCORE_OAUTH_ISSUER": "https://issuer.example/",
        "COMMANDCORE_MCP_BASE_URL": "https://mcp.example/mcp",
        "COMMANDCORE_OAUTH_AUDIENCE": "https://mcp.example/mcp",
        "COMMANDCORE_OAUTH_JWKS_URL": "https://issuer.example/jwks",
        "COMMANDCORE_BROWSER_ENABLED": "false",
        "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED": "false",
        "COMMANDCORE_RECOVERY_ENABLED": "false",
    }
    if scope_value is None:
        env.pop("COMMANDCORE_OAUTH_DISCOVERY_SCOPES", None)
    else:
        env["COMMANDCORE_OAUTH_DISCOVERY_SCOPES"] = scope_value
    run = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import asyncio;"
                "from commandcore_server.main import oauth_protected_resource;"
                "r=asyncio.run(oauth_protected_resource());"
                "print(r.body.decode())"
            ),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=True,
        timeout=25,
    )
    metadata = json.loads(run.stdout.strip().splitlines()[-1])
    assert metadata["resource"] == "https://mcp.example/mcp"
    assert metadata["authorization_servers"] == ["https://issuer.example/"]
    assert metadata["scopes_supported"] == expected
