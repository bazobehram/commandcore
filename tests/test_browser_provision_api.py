"""Synthetic OAuth->API->operator intent tests; no live OAuth or Docker."""

from __future__ import annotations

import json
import os

import pytest
from commandcore_server.browser_gateway import OwnedSession
from commandcore_server.browser_provision_api import (
    BrowserOAuthProvisioner,
    read_api_provision_key,
)
from commandcore_server.browser_provision_intent import (
    BrowserProvisionIntentDenied,
    verify_provision_intent,
)
from commandcore_server.browser_provision_ipc import BrowserProvisionTransportDenied
from commandcore_server.browser_worker_attestation import BrowserAttestationError
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_dynamic import RefreshingOwnerBrowserWorkerPool
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError, ToolService


@pytest.fixture(autouse=True)
def isolated_api_journal(tmp_path, monkeypatch):
    journal = tmp_path / "journals"
    journal.mkdir(mode=0o700)
    monkeypatch.setenv("COMMANDCORE_BROWSER_JOURNAL_DIR", str(journal))


ISSUER = "https://auth.review.invalid/"
KEY = b"dedicated-synthetic-api-provision-key-for-tests"
BIND = "independent-synthetic-browser-binding-key-1234"


class Proof:
    def __init__(self):
        self.available = True

    def verify(self, worker_id):
        if not self.available:
            raise BrowserAttestationError("synthetic proof absent")
        return {
            "steel_started_at": "synthetic-proven-instance",
            "boundary_name": "ccbw-boundary-" + worker_id,
        }


def principal(subject="alice", *, scope="commandcore:standard", kind="oauth2"):
    return Principal(
        subject=subject,
        issuer=ISSUER,
        client_id="review-client",
        auth_kind=kind,
        scopes=(scope,),
    )


def setup(tmp_path):
    tmp_path.chmod(0o700)
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"workers":[]}')
    manifest.chmod(0o600)
    proof = Proof()
    pool = RefreshingOwnerBrowserWorkerPool(
        str(manifest),
        BIND,
        ("example.com",),
        "https://commandcore.app",
        attestation=proof,
    )
    key = tmp_path / "intent.secret"
    key.write_bytes(KEY)
    key.chmod(0o600)
    provisioner = BrowserOAuthProvisioner(
        worker_pool=pool,
        provision_secret_path=str(key),
        socket_path=str(tmp_path / "operator.sock"),
        operator_uid=994,
        operator_gid=987,
    )
    return pool, proof, key, manifest, provisioner


def publish_binding(tmp_path, manifest, owner):
    worker_id = "w-000000000000000001"
    binding_path = tmp_path / "owner.sqlite3"
    ledger = BrowserWorkerBinding.provision(str(binding_path), worker_id, BIND)
    ledger.claim((owner.issuer, owner.subject, owner.client_id))
    ledger.close()
    row = {
        "worker_id": worker_id,
        "binding_path": str(binding_path),
        "steel_url": f"http://ccctl-{worker_id}:3000",
        "cdp_url": f"ws://ccctl-{worker_id}:3000",
        "egress_proxy_url": "http://browser-boundary:8080",
        "egress_policy_url": f"http://ccctl-{worker_id}:8080",
    }
    tmp = manifest.with_suffix(".new")
    tmp.write_text(json.dumps({"workers": [row]}))
    tmp.chmod(0o600)
    os.replace(tmp, manifest)


def test_secret_file_mode_symlink_and_directory_requirements(tmp_path):
    _, _, key, _, _ = setup(tmp_path)
    assert read_api_provision_key(str(key)) == KEY
    key.chmod(0o644)
    with pytest.raises(BrowserProvisionIntentDenied):
        read_api_provision_key(str(key))
    key.chmod(0o600)
    symlink = tmp_path / "secret-link"
    symlink.symlink_to(key)
    with pytest.raises(BrowserProvisionIntentDenied):
        read_api_provision_key(str(symlink))
    tmp_path.chmod(0o777)
    with pytest.raises(BrowserProvisionIntentDenied):
        read_api_provision_key(str(key))


@pytest.mark.asyncio
async def test_verified_standard_owner_allocates_with_real_signed_identity(
    tmp_path, monkeypatch
):
    pool, _, _, manifest, provisioner = setup(tmp_path)
    seen = []

    def operator_stub(token, socket_path, *, operator_uid, operator_gid):
        owner = verify_provision_intent(token, KEY, ISSUER)
        assert socket_path.endswith("operator.sock")
        assert (operator_uid, operator_gid) == (994, 987)
        seen.append((owner.issuer, owner.subject, owner.client_id))
        publish_binding(tmp_path, manifest, principal(owner.subject))
        return "accepted"

    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent", operator_stub
    )
    await provisioner.ensure_owner(principal())
    assert seen == [(ISSUER, "alice", "review-client")]
    assert pool.has_owner_binding((ISSUER, "alice", "review-client"))
    await provisioner.ensure_owner(principal())
    assert len(seen) == 1
    assert not pool.has_owner_binding((ISSUER, "bob", "review-client"))


@pytest.mark.asyncio
async def test_read_only_and_non_oauth_never_send_to_operator(tmp_path, monkeypatch):
    _, _, _, _, provisioner = setup(tmp_path)
    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lambda *_a, **_k: pytest.fail("unauthorized allocation reached operator"),
    )
    for user in (
        principal(scope="commandcore:read"),
        principal(kind="bootstrap-bearer"),
    ):
        with pytest.raises(BrowserProvisionIntentDenied):
            await provisioner.ensure_owner(user)


@pytest.mark.asyncio
async def test_existing_assignment_with_missing_attestation_never_reallocates(
    tmp_path, monkeypatch
):
    pool, proof, _, manifest, provisioner = setup(tmp_path)
    publish_binding(tmp_path, manifest, principal())
    proof.available = False
    assert pool.has_owner_binding((ISSUER, "alice", "review-client"))
    assert not pool.available(ISSUER, "alice", "review-client")
    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lambda *_a, **_k: pytest.fail("proof outage triggered duplicate allocation"),
    )
    await provisioner.ensure_owner(principal())


@pytest.mark.asyncio
async def test_uncertain_outcome_never_retries_unless_assignment_is_observed(
    tmp_path, monkeypatch
):
    _, _, _, _, provisioner = setup(tmp_path)
    calls = []

    def lost_connection(*_args, **_kwargs):
        calls.append(1)
        raise BrowserProvisionTransportDenied("synthetic timeout after send")

    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lost_connection,
    )
    with pytest.raises(BrowserProvisionTransportDenied):
        await provisioner.ensure_owner(principal())
    with pytest.raises(BrowserProvisionTransportDenied, match="pending"):
        await provisioner.ensure_owner(principal())
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_conversation_binding_does_not_need_preassigned_worker(tmp_path):
    pool, _, _, _, provisioner = setup(tmp_path)

    class Audit:
        def add_audit(self, **_kwargs):
            return 1

    service = ToolService(
        Audit(), None, 300, browser=pool, browser_provisioner=provisioner
    )
    args = service._browser_scope_args(
        principal(), "browser.open", {"url": "https://example.com"}, "chat-A"
    )
    assert args == {"url": "https://example.com"}
    assert (ISSUER, "alice", "review-client") in service._browser_conversation_leases
    with pytest.raises(ToolError) as conflict:
        service._browser_scope_args(principal(), "browser.open", {}, "chat-B")
    assert conflict.value.code == "browser_conversation_in_use"
    with pytest.raises(ToolError) as unbound:
        service._browser_scope_args(principal("bob"), "browser.frame", {}, "chat-A")
    assert unbound.value.code == "browser_conversation_not_active"


@pytest.mark.asyncio
async def test_toolservice_failed_allocation_scrubs_conversation_lease(
    tmp_path, monkeypatch
):
    pool, _, _, _, provisioner = setup(tmp_path)
    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lambda *_a, **_k: (_ for _ in ()).throw(
            BrowserProvisionTransportDenied("operator absent")
        ),
    )

    class Audit:
        def add_audit(self, **_kwargs):
            return 1

    service = ToolService(
        Audit(), None, 300, browser=pool, browser_provisioner=provisioner
    )
    with pytest.raises(ToolError) as blocked:
        await service.call(
            principal(),
            "browser.open",
            {"url": "https://example.com"},
            host_session="chat-A",
        )
    assert blocked.value.code == "browser_provision_pending"
    assert service._browser_conversation_leases == {}


@pytest.mark.asyncio
async def test_unavailable_operator_manifest_fails_before_creating_intent(
    tmp_path, monkeypatch
):
    _, _, _, manifest, provisioner = setup(tmp_path)
    manifest.chmod(0o644)
    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lambda *_args, **_kwargs: pytest.fail("invalid owner manifest dispatched"),
    )
    with pytest.raises(BrowserProvisionTransportDenied, match="manifest"):
        await provisioner.ensure_owner(principal())


@pytest.mark.asyncio
async def test_pending_owner_admission_is_bounded(tmp_path, monkeypatch):
    _, _, _, _, provisioner = setup(tmp_path)
    import time

    provisioner._pending = {
        (ISSUER, f"synthetic-owner-{i}", "client"): time.monotonic() + 600
        for i in range(256)
    }
    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lambda *_args, **_kwargs: pytest.fail("over-capacity dispatch"),
    )
    with pytest.raises(BrowserProvisionTransportDenied, match="capacity"):
        await provisioner.ensure_owner(principal())


def test_provision_api_is_disabled_unless_all_required_flags_present():
    from dataclasses import replace

    from commandcore_server.config import Settings

    settings = replace(
        Settings(),
        browser_enabled=True,
        browser_provision_api_enabled=True,
        browser_dynamic_workers_enabled=False,
    )
    with pytest.raises(RuntimeError, match="provisioning API requires"):
        settings.validate()


@pytest.mark.asyncio
async def test_toolservice_oauth_open_uses_allocated_owner_only(tmp_path, monkeypatch):
    journal = tmp_path / "journals"
    pool, _, _, manifest, provisioner = setup(tmp_path)
    seen = []

    def accepting_operator(token, _socket, **_kwargs):
        owner = verify_provision_intent(token, KEY, ISSUER)
        seen.append(owner.subject)
        publish_binding(tmp_path, manifest, principal(owner.subject))
        return "accepted"

    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        accepting_operator,
    )

    async def synthetic_gateway(*, subject, issuer, client_id, name, args):
        assert (issuer, subject, client_id) == (ISSUER, "alice", "review-client")
        assert name == "browser.open"
        pool._find_worker((issuer, subject, client_id)).sessions[
            (issuer, subject, client_id)
        ] = OwnedSession("a" * 36)
        return {"ok": True}

    monkeypatch.setattr(pool, "call", synthetic_gateway)

    class Audit:
        def add_audit(self, **_kwargs):
            return 1

    service = ToolService(
        Audit(), None, 300, browser=pool, browser_provisioner=provisioner
    )
    result = await service.call(
        principal(),
        "browser.open",
        {"url": "https://example.com"},
        host_session="chat-A",
    )
    assert result == {"ok": True}
    assert seen == ["alice"]
    assert len(list(journal.glob("*.conversation.enc"))) == 1
    # A newly constructed API service must recover only this verified owner/chat.
    recovered = ToolService(
        Audit(), None, 300, browser=pool, browser_provisioner=provisioner
    )
    assert (
        recovered._browser_scope_args(principal(), "browser.open", {}, "chat-A") == {}
    )
    with pytest.raises(ToolError) as wrong_chat:
        recovered._browser_scope_args(principal(), "browser.open", {}, "chat-B")
    assert wrong_chat.value.code == "browser_conversation_in_use"
    with pytest.raises(ToolError) as denied:
        await service.call(
            principal(scope="commandcore:read"),
            "browser.open",
            {"url": "https://example.com"},
            host_session="chat-A",
        )
    assert denied.value.code == "insufficient_scope"
    assert seen == ["alice"]


@pytest.mark.asyncio
async def test_missing_or_public_journal_never_provisions(tmp_path, monkeypatch):
    _, _, _, _, provisioner = setup(tmp_path)
    monkeypatch.setattr(
        "commandcore_server.browser_provision_api.send_provision_intent",
        lambda *_a, **_k: pytest.fail("unsafe journal triggered provisioning"),
    )
    journal = tmp_path / "journals"
    journal.chmod(0o755)
    with pytest.raises(BrowserProvisionIntentDenied, match="journal"):
        await provisioner.ensure_owner(principal())
    journal.chmod(0o700)
    journal.rmdir()
    with pytest.raises(BrowserProvisionIntentDenied, match="journal"):
        await provisioner.ensure_owner(principal())
