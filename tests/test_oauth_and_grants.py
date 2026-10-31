from __future__ import annotations

from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from commandcore_server.auth import (
    ADMIN_SCOPE,
    FULL_SCOPE,
    READ_SCOPE,
    STANDARD_SCOPE,
    OAuthSettings,
    OAuthVerifier,
    scope_allows,
)
from commandcore_server.db import Database
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError, ToolService


def _device(db: Database, owner: str = "owner") -> dict:
    enrolled = db.register_device(
        owner_id=owner,
        display_name="box",
        hostname="box",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.4.0",
        agent_protocol_version="1",
        public_key_b64="AA==",
        capabilities={
            "local_max_permission_profile": "FULL_CONTROL",
            "privileged_helper": True,
        },
        auto_approve=True,
    )
    db.mark_online(
        enrolled["device_id"],
        ip="127.0.0.1",
        agent_version="0.4.0",
        agent_protocol_version="1",
        capabilities={
            "local_max_permission_profile": "FULL_CONTROL",
            "privileged_helper": True,
        },
    )
    assert db.set_permission(owner, enrolled["device_id"], "FULL_CONTROL")
    return db.get_device(enrolled["device_id"])


def test_scope_hierarchy():
    assert scope_allows((FULL_SCOPE,), READ_SCOPE)
    assert scope_allows((FULL_SCOPE,), STANDARD_SCOPE)
    assert not scope_allows((ADMIN_SCOPE,), FULL_SCOPE)
    assert not scope_allows((FULL_SCOPE,), ADMIN_SCOPE)
    assert not scope_allows((READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE), ADMIN_SCOPE)
    assert scope_allows((ADMIN_SCOPE,), ADMIN_SCOPE)
    assert not scope_allows((READ_SCOPE,), STANDARD_SCOPE)


def test_oauth_verifier_checks_standard_claims(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    verifier = OAuthVerifier(
        OAuthSettings(
            "https://issuer.example/",
            "https://mcp.example/mcp",
            "https://issuer.example/jwks",
        )
    )
    monkeypatch.setattr(
        verifier.jwks,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=public),
    )
    import time

    token = jwt.encode(
        {
            "sub": "user-1",
            "iss": "https://issuer.example/",
            "aud": "https://mcp.example/mcp",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "scope": f"{READ_SCOPE} {STANDARD_SCOPE}",
            "client_id": "client-7",
        },
        private,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    principal = verifier.verify(token)
    assert principal.subject == "user-1"
    assert principal.client_id == "client-7"
    assert STANDARD_SCOPE in principal.scopes

    bad = jwt.encode(
        {
            "sub": "user-1",
            "iss": "https://issuer.example/",
            "aud": "wrong",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "scope": READ_SCOPE,
        },
        private,
        algorithm="RS256",
    )
    with pytest.raises(jwt.InvalidAudienceError):
        verifier.verify(bad)

    for claims, expected_error in [
        ({"iss": "https://other.example/"}, jwt.InvalidIssuerError),
        ({"exp": int(time.time()) - 120}, jwt.ExpiredSignatureError),
        ({"nbf": int(time.time()) + 120}, jwt.ImmatureSignatureError),
    ]:
        payload = {
            "sub": "user-1",
            "iss": "https://issuer.example/",
            "aud": "https://mcp.example/mcp",
            "iat": int(time.time()) - 120,
            "exp": int(time.time()) + 300,
            "scope": READ_SCOPE,
            **claims,
        }
        with pytest.raises(expected_error):
            verifier.verify(jwt.encode(payload, private, algorithm="RS256"))


class FakeAgents:
    def __init__(self):
        self.calls = []

    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        self.calls.append((owner_id, device["permission_profile"], tool))
        return SimpleNamespace(
            execution_id="e1",
            status="ok",
            exit_code=0,
            result={"ok": True},
            stdout="",
            stderr="",
            error=None,
            output_capture={},
        )


@pytest.mark.asyncio
async def test_grant_ceiling_and_oauth_scope_are_both_enforced(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    assert db.upsert_device_grant("owner", d["id"], "reader", "READ_ONLY", "owner")
    agents = FakeAgents()
    service = ToolService(db, agents, 60)

    reader = Principal("reader", "oauth-client", "oauth2", (READ_SCOPE,))
    listed = await service.call(reader, "devices.list", {})
    assert listed["devices"][0]["access_max_permission_profile"] == "READ_ONLY"
    await service.call(reader, "system.info", {"device_id": d["id"]})
    with pytest.raises(ToolError) as exc:
        await service.call(
            reader, "shell.exec", {"device_id": d["id"], "command": "id"}
        )
    assert exc.value.code in {"insufficient_scope", "permission_denied"}

    # Even a FULL OAuth token cannot exceed the device grant ceiling.
    full_token = Principal(
        "reader", "oauth-client", "oauth2", (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    )
    with pytest.raises(ToolError) as exc2:
        await service.call(
            full_token, "shell.exec", {"device_id": d["id"], "command": "id"}
        )
    assert exc2.value.code == "permission_denied"

    assert db.upsert_device_grant("owner", d["id"], "reader", "STANDARD", "owner")
    await service.call(
        full_token, "shell.exec", {"device_id": d["id"], "command": "id"}
    )
    assert agents.calls[-1][1] == "STANDARD"


def test_grant_revocation_removes_visibility(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    assert db.upsert_device_grant("owner", d["id"], "guest", "READ_ONLY", "owner")
    assert db.get_accessible_device("guest", d["id"]) is not None
    assert db.revoke_device_grant("owner", d["id"], "guest")
    assert db.get_accessible_device("guest", d["id"]) is None


@pytest.mark.asyncio
async def test_distinct_public_accounts_cannot_list_or_dispatch_to_other_devices(
    tmp_path,
):
    """Two-user negative matrix with no real agent or production credentials."""
    db = Database(str(tmp_path / "two-accounts.sqlite3"))
    alice_device = _device(db, owner="alice")
    bob_device = _device(db, owner="bob")
    agents = FakeAgents()
    service = ToolService(db, agents, 60)
    scopes = (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    alice = Principal("alice", "oauth-client-a", "oauth2", scopes)
    bob = Principal("bob", "oauth-client-b", "oauth2", scopes)

    for actor, own_device, foreign_device in (
        (alice, alice_device, bob_device),
        (bob, bob_device, alice_device),
    ):
        listed = await service.call(actor, "devices.list", {})
        visible_ids = {d["id"] for d in listed["devices"]}
        assert own_device["id"] in visible_ids
        assert foreign_device["id"] not in visible_ids

        with pytest.raises(ToolError) as exc:
            await service.call(
                actor,
                "shell.exec",
                {"device_id": foreign_device["id"], "command": "id"},
            )
        assert exc.value.code in {"permission_denied", "device_not_found"}

    # The fake Agent must never receive a command addressed to another owner.
    assert agents.calls == []


@pytest.mark.asyncio
async def test_grant_downgrade_and_revocation_invalidate_prior_selection(tmp_path):
    """An existing selection handle never freezes a guest's old privileges."""
    db = Database(str(tmp_path / "grant-lifecycle.sqlite3"))
    device = _device(db, owner="alice")
    assert db.upsert_device_grant("alice", device["id"], "bob", "FULL_CONTROL", "alice")
    agents = FakeAgents()
    service = ToolService(db, agents, 60)
    bob = Principal(
        "bob", "bob-oauth-client", "oauth2", (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    )
    selected = await service.call(bob, "devices.select", {"device": device["id"]})
    handle = selected["selection_id"]

    await service.call(bob, "shell.exec", {"selection_id": handle, "command": "id"})
    assert len(agents.calls) == 1
    assert agents.calls[-1][1] == "FULL_CONTROL"

    # Downgrades must be enforced even with a handle issued at FULL_CONTROL.
    assert db.upsert_device_grant("alice", device["id"], "bob", "READ_ONLY", "alice")
    for device_args in ({"selection_id": handle}, {"device_id": device["id"]}):
        with pytest.raises(ToolError) as error:
            await service.call(bob, "shell.exec", {**device_args, "command": "id"})
        assert error.value.code == "permission_denied"
    assert len(agents.calls) == 1
    await service.call(bob, "system.info", {"selection_id": handle})
    assert agents.calls[-1][1] == "READ_ONLY"

    assert db.upsert_device_grant("alice", device["id"], "bob", "STANDARD", "alice")
    await service.call(bob, "shell.exec", {"selection_id": handle, "command": "id"})
    assert agents.calls[-1][1] == "STANDARD"
    calls_before_revocation = len(agents.calls)

    assert db.revoke_device_grant("alice", device["id"], "bob")
    for device_args in ({"selection_id": handle}, {"device_id": device["id"]}):
        with pytest.raises(ToolError) as error:
            await service.call(bob, "shell.exec", {**device_args, "command": "id"})
        assert error.value.code == "device_not_found"
    assert len(agents.calls) == calls_before_revocation
    assert (await service.call(bob, "devices.list", {}))["devices"] == []
    assert (await service.call(bob, "auth.whoami", {}))["device_grants"] == []


@pytest.mark.asyncio
async def test_selection_handle_is_subject_bound_and_rechecks_device_revocation(
    tmp_path,
):
    db = Database(str(tmp_path / "device-revocation.sqlite3"))
    alice_device = _device(db, owner="alice")
    _device(db, owner="bob")
    agents = FakeAgents()
    service = ToolService(db, agents, 60)
    scopes = (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    alice = Principal("alice", "alice-client", "oauth2", scopes)
    bob = Principal("bob", "bob-client", "oauth2", scopes)
    selected = await service.call(
        alice, "devices.select", {"device": alice_device["id"]}
    )
    handle = selected["selection_id"]

    with pytest.raises(ToolError) as other_user:
        await service.call(bob, "system.info", {"selection_id": handle})
    assert other_user.value.code == "selection_not_found_or_expired"

    assert db.revoke_device("alice", alice_device["id"])
    with pytest.raises(ToolError) as revoked:
        await service.call(alice, "system.info", {"selection_id": handle})
    assert revoked.value.code == "device_revoked"
    assert (await service.call(alice, "devices.list", {}))["devices"] == []
    assert agents.calls == []


@pytest.mark.asyncio
async def test_expired_selection_handle_fails_before_agent_dispatch(tmp_path):
    db = Database(str(tmp_path / "selection-expiry.sqlite3"))
    device = _device(db, owner="alice")
    expired = db.create_selection("alice", device["id"], ttl_seconds=-60)
    agents = FakeAgents()
    service = ToolService(db, agents, 60)
    alice = Principal(
        "alice", "alice-client", "oauth2", (READ_SCOPE, STANDARD_SCOPE, FULL_SCOPE)
    )

    with pytest.raises(ToolError) as error:
        await service.call(
            alice,
            "shell.exec",
            {"selection_id": expired["selection_id"], "command": "id"},
        )
    assert error.value.code == "selection_not_found_or_expired"
    assert agents.calls == []
