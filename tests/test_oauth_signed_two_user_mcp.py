"""M1: JWT-authenticated users cannot cross MCP device boundaries.

Offline harness: real OAuthVerifier, MCPHandler, ToolService, SQLite and signed
RSA tokens. Only JWKS network lookup and Agent transport are stubbed.
This is not a substitute for public Auth0 two-account acceptance.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from commandcore_server.auth import FULL_SCOPE, READ_SCOPE, STANDARD_SCOPE, OAuthSettings, OAuthVerifier
from commandcore_server.db import Database
from commandcore_server.mcp import MCPHandler
from commandcore_server.metrics import Metrics
from commandcore_server.tools import CORE_TOOL_DEFINITIONS, ToolService


ISSUER = "https://idp.fixture.invalid/"
AUDIENCE = "https://control.fixture.invalid/mcp"


class FakeAgents:
    def __init__(self):
        self.calls = []

    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        self.calls.append((owner_id, device["id"], device["permission_profile"], tool))
        return SimpleNamespace(
            execution_id="fixture-execution", status="ok", exit_code=0,
            result={"fixture": True}, stdout="", stderr="", error=None,
            output_capture={},
        )


def _device(db, owner):
    enrolled = db.register_device(
        owner_id=owner, display_name=owner+"-vm", hostname=owner+"-vm",
        platform="Linux", architecture="x86_64", agent_version="fixture",
        agent_protocol_version="1", public_key_b64="AA==",
        capabilities={"local_max_permission_profile": "FULL_CONTROL", "privileged_helper": True},
        auto_approve=True,
    )
    device_id = enrolled["device_id"]
    db.mark_online(
        device_id, ip="127.0.0.1", agent_version="fixture", agent_protocol_version="1",
        capabilities={"local_max_permission_profile": "FULL_CONTROL", "privileged_helper": True},
    )
    assert db.set_permission(owner, device_id, "FULL_CONTROL")
    return device_id


@pytest.fixture
def context(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "two-user.sqlite3"))
    ids = {subject: _device(db, subject) for subject in ("alice", "bob")}
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OAuthVerifier(OAuthSettings(ISSUER, AUDIENCE, ISSUER+"jwks"))
    monkeypatch.setattr(
        verifier.jwks, "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=key.public_key()),
    )
    agents = FakeAgents()
    handler = MCPHandler(
        ToolService(db, agents, 60), Metrics(), "fixture",
        definitions=CORE_TOOL_DEFINITIONS, name="CommandCore Core",
    )
    app = FastAPI()

    @app.post("/mcp/core")
    async def mcp(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            principal = verifier.verify(auth.removeprefix("Bearer "))
        except jwt.PyJWTError:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await handler.handle(request, principal)

    def sign(subject, *, scopes=(READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE),
             audience=AUDIENCE, issuer=ISSUER, exp_offset=300, private_key=None):
        now = int(time.time())
        return jwt.encode(
            {"sub": subject, "iss": issuer, "aud": audience, "iat": now-10,
             "exp": now+exp_offset, "scope": " ".join(scopes), "client_id": "fixture-client"},
            private_key or key, algorithm="RS256", headers={"kid": "fixture"},
        )

    with TestClient(app) as client:
        def call(subject, name, args=None, token=None):
            return client.post(
                "/mcp/core",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": name, "arguments": args or {}}},
                headers={"Authorization": "Bearer " + (token or sign(subject))},
            )
        yield SimpleNamespace(db=db, ids=ids, agents=agents, call=call, sign=sign)


@pytest.mark.parametrize("user,foreign", [("alice", "bob"), ("bob", "alice")])
def test_signed_users_cannot_enumerate_or_dispatch_to_foreign_devices(context, user, foreign):
    c = context
    listing = c.call(user, "devices.list")
    assert listing.status_code == 200
    result = listing.json()["result"]
    assert result["isError"] is False
    ids = {device["id"] for device in result["structuredContent"]["devices"]}
    assert c.ids[user] in ids and c.ids[foreign] not in ids
    denied = c.call(user, "shell.exec", {"device_id": c.ids[foreign], "command": "id"})
    assert denied.json()["result"]["isError"] is True
    assert denied.json()["result"]["structuredContent"]["error"] in {
        "device_not_found", "permission_denied",
    }
    assert c.agents.calls == []


def test_signed_selection_handle_is_bound_to_subject(context):
    c = context
    result = c.call("alice", "devices.select", {"device": c.ids["alice"]})
    assert result.json()["result"]["isError"] is False
    handle = result.json()["result"]["structuredContent"]["selection_id"]
    denied = c.call("bob", "shell.exec", {"selection_id": handle, "command": "id"})
    assert denied.json()["result"]["structuredContent"]["error"] == "selection_not_found_or_expired"
    assert c.agents.calls == []


def test_signed_scopes_grants_downgrade_and_revocation(context):
    c = context
    device = c.ids["alice"]
    assert c.db.upsert_device_grant("alice", device, "bob", "STANDARD", "alice")
    full_token = c.sign("bob")
    allowed = c.call("bob", "shell.exec", {"device_id": device, "command": "id"}, full_token)
    assert allowed.json()["result"]["isError"] is False
    assert c.agents.calls[-1] == ("bob", device, "STANDARD", "shell.exec")
    count = len(c.agents.calls)

    read_only = c.sign("bob", scopes=(READ_SCOPE,))
    denied = c.call("bob", "shell.exec", {"device_id": device, "command": "id"}, read_only)
    assert denied.json()["result"]["isError"] is True
    assert len(c.agents.calls) == count

    assert c.db.upsert_device_grant("alice", device, "bob", "READ_ONLY", "alice")
    denied = c.call("bob", "shell.exec", {"device_id": device, "command": "id"}, full_token)
    assert denied.json()["result"]["structuredContent"]["error"] == "permission_denied"
    assert len(c.agents.calls) == count

    assert c.db.revoke_device_grant("alice", device, "bob")
    listing = c.call("bob", "devices.list").json()["result"]["structuredContent"]
    assert device not in {item["id"] for item in listing["devices"]}
    denied = c.call("bob", "shell.exec", {"device_id": device, "command": "id"}, full_token)
    assert denied.json()["result"]["isError"] is True
    assert len(c.agents.calls) == count


@pytest.mark.parametrize("invalid", ["audience", "issuer", "expired", "signature"])
def test_invalid_jwt_is_rejected_before_dispatch(context, invalid):
    c = context
    changes = {
        "audience": {"audience": "https://other.fixture.invalid/mcp"},
        "issuer": {"issuer": "https://other-idp.fixture.invalid/"},
        "expired": {"exp_offset": -90},
        "signature": {"private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048)},
    }
    bad = c.sign("alice", **changes[invalid])
    result = c.call("alice", "shell.exec", {"device_id": c.ids["alice"], "command": "id"}, bad)
    assert result.status_code == 401
    assert c.agents.calls == []
