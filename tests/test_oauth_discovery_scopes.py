"""Discovery metadata scope list must not change execution authorization."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from commandcore_server.auth import (
    ADMIN_SCOPE,
    ALL_SCOPES,
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


def test_default_discovery_uses_user_scopes_without_admin():
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
        (None, [READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE]),
        (
            "commandcore:read, commandcore:standard,commandcore:full",
            [READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE],
        ),
        (
            "commandcore:read,commandcore:admin",
            [READ_SCOPE, ADMIN_SCOPE],
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
                "import json;"
                "from fastapi.testclient import TestClient;"
                "from commandcore_server.main import app;"
                "r=TestClient(app).get('/.well-known/oauth-protected-resource');"
                "assert r.status_code==200,r.text;"
                "print(json.dumps(r.json()))"
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


def _live_probe_module():
    path = Path(__file__).resolve().parents[1] / "scripts/public_oauth_readiness.py"
    spec = importlib.util.spec_from_file_location("commandcore_public_oauth_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_live_readiness_expected_scopes_match_public_defaults():
    expected_scopes = _live_probe_module().EXPECTED_SCOPES
    assert expected_scopes == (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    assert ADMIN_SCOPE not in expected_scopes


@pytest.mark.parametrize("include_admin", [False, True])
def test_live_readiness_accepts_only_expected_public_scopes(monkeypatch, include_admin):
    probe = _live_probe_module()

    class Response:
        status = 200
        url = "https://test.example/.well-known/oauth-protected-resource/mcp"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            scopes = [READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE]
            if include_admin:
                scopes.append(ADMIN_SCOPE)
            return json.dumps(
                {
                    "resource": "https://test.example/mcp",
                    "authorization_servers": ["https://id.example/"],
                    "scopes_supported": scopes,
                    "bearer_methods_supported": ["header"],
                }
            ).encode()

    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda request, timeout: Response(),
    )
    if include_admin:
        with pytest.raises(ValueError, match="Unexpected public OAuth scopes"):
            probe.verify_discovery("https://test.example")
    else:
        assert probe.verify_discovery("https://test.example")["status"] == "PASS"
