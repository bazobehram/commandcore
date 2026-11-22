"""Exercise listener-to-intake glue with real Unix sockets, never Docker."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest
from commandcore_server.browser_provision_intent import (
    BrowserProvisionIntentDenied,
    ProvisionNonceLedger,
    issue_provision_intent,
    verify_and_consume_provision_intent,
)
from commandcore_server.browser_provision_ipc import (
    BrowserProvisionTransportDenied,
    send_provision_intent,
)
from commandcore_server.models import Principal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_provision_listener as listener

ISSUER = "https://review.example/"
KEY = b"synthetic-operator-listener-provision-key-abc"
BINDING = "synthetic-different-long-worker-binding-key-1234567"


def _make(subject):
    return issue_provision_intent(
        Principal(
            subject=subject,
            issuer=ISSUER,
            client_id="review-app",
            auth_kind="oauth2",
            scopes=("commandcore:standard",),
        ),
        KEY,
    )


def test_full_local_listener_to_operator_adapter_with_fake_docker(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    ledger = ProvisionNonceLedger(str(tmp_path / "ledger.sqlite3"))
    seen = []

    def fake_handle_request(*, request_file, state_dir, issuer, **kwargs):
        assert issuer == ISSUER and state_dir == tmp_path
        assert request_file.stat().st_mode & 0o077 == 0
        assert kwargs["allow_hosts"] == "example.com"
        record = verify_and_consume_provision_intent(
            request_file.read_text(), KEY, ISSUER, ledger
        )
        seen.append(record.subject)
        return "w-mocked-not-created"

    monkeypatch.setattr(listener, "handle_request", fake_handle_request)
    sock = tmp_path / "provision.sock"
    failures = []

    def run():
        try:
            listener.run_operator_listener(
                socket_path=str(sock),
                state_dir=tmp_path,
                expected_client_uid=os.getuid(),
                issuer=ISSUER,
                allow_hosts="example.com",
                steel_image="mock:steel",
                boundary_image="mock:boundary",
                intent_secret=KEY,
                binding_secret=BINDING,
                max_connections=3,
            )
        except Exception as exc:  # noqa: BLE001 - preserve worker thread assertion
            failures.append(exc)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.01)
    assert sock.exists(), failures
    token = _make("alpha")
    assert (
        send_provision_intent(token, str(sock), operator_uid=os.getuid()) == "accepted"
    )
    with pytest.raises(BrowserProvisionTransportDenied):
        send_provision_intent(token, str(sock), operator_uid=os.getuid())
    assert (
        send_provision_intent(_make("beta"), str(sock), operator_uid=os.getuid())
        == "accepted"
    )
    t.join(timeout=7)
    ledger.close()
    assert not t.is_alive() and not failures
    assert seen == ["alpha", "beta"]
    assert not sock.exists()
    assert not list(tmp_path.glob(".intent-*.req"))
    assert not list(tmp_path.glob(".browser-owner-*.json"))


def test_private_credential_file_rejects_nonprivate_and_links(tmp_path):
    tmp_path.chmod(0o700)
    credential = tmp_path / "intent.secret"
    credential.write_bytes(KEY)
    credential.chmod(0o600)
    assert listener.private_secret(credential) == KEY
    credential.chmod(0o644)
    with pytest.raises(BrowserProvisionIntentDenied):
        listener.private_secret(credential)
    credential.chmod(0o600)
    linked = tmp_path / "intent-link.secret"
    linked.symlink_to(credential)
    with pytest.raises(BrowserProvisionIntentDenied):
        listener.private_secret(linked)


def test_operator_listener_refuses_identical_signing_and_owner_keys(tmp_path):
    tmp_path.chmod(0o700)
    with pytest.raises(BrowserProvisionIntentDenied):
        listener.run_operator_listener(
            socket_path=str(tmp_path / "no.sock"),
            state_dir=tmp_path,
            expected_client_uid=os.getuid(),
            issuer=ISSUER,
            allow_hosts="example.com",
            steel_image="mock:steel",
            boundary_image="mock:boundary",
            intent_secret=KEY,
            binding_secret=KEY.decode(),
            max_connections=1,
        )
    assert not (tmp_path / "no.sock").exists()
