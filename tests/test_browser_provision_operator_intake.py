"""No Docker or production worker: mock only the existing lifecycle provision call."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from commandcore_server.browser_provision_intent import (
    BrowserProvisionIntentDenied,
    issue_provision_intent,
)
from commandcore_server.browser_worker_orchestrator import WorkerQuarantined
from commandcore_server.models import Principal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_provision_from_intent as intake

ISSUER = "https://issuer.example/"
KEY = b"synthetic-intent-signing-key-for-staging-1234"
BINDING = "synthetic-separate-worker-binding-secret-1234567"


def write_request(path, token):
    path.write_text(token + "\n")
    path.chmod(0o600)


def user(subject):
    return Principal(
        subject=subject,
        client_id="review-client",
        auth_kind="oauth2",
        scopes=("commandcore:standard",),
        issuer=ISSUER,
    )


def run(request_file, root, **kwargs):
    return intake.handle_request(
        request_file=request_file,
        state_dir=root,
        issuer=kwargs.get("issuer", ISSUER),
        allow_hosts="example.com",
        steel_image="never:used",
        boundary_image="never:used",
        intent_secret=kwargs.get("key", KEY),
        binding_secret=kwargs.get("binding", BINDING),
        now=1001,
    )


def test_verified_two_accounts_only_provision_once_and_owner_file_is_removed(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    seen = []

    def fake_provision(root, owner_path, *_args):
        assert root == tmp_path
        assert owner_path.stat().st_mode & 0o077 == 0
        seen.append(json.loads(owner_path.read_text()))
        return "w-test-worker-" + str(len(seen))

    monkeypatch.setattr(intake, "provision", fake_provision)
    request = tmp_path / "request.txt"
    write_request(request, issue_provision_intent(user("alice"), KEY, now=1000))
    assert run(request, tmp_path) == "w-test-worker-1"
    assert not list(tmp_path.glob(".browser-owner-*.json"))
    with pytest.raises(BrowserProvisionIntentDenied, match="replayed"):
        run(request, tmp_path)
    write_request(request, issue_provision_intent(user("bob"), KEY, now=1000))
    assert run(request, tmp_path) == "w-test-worker-2"
    assert [x["subject"] for x in seen] == ["alice", "bob"]
    assert all(
        x["issuer"] == ISSUER and x["client_id"] == "review-client" for x in seen
    )
    assert len(list(tmp_path.glob(".browser-owner-*.json"))) == 0
    assert len(seen) == 2


def test_wrong_key_issuer_and_same_operator_secret_reject_before_docker(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(
        intake, "provision", lambda *_: pytest.fail("must not provision")
    )
    request = tmp_path / "request.txt"
    write_request(request, issue_provision_intent(user("alice"), KEY, now=1000))
    for options in (
        {"key": b"different-dedicated-intent-signing-key-1234"},
        {"issuer": "https://wrong.example/"},
        {"binding": KEY.decode()},
    ):
        with pytest.raises(BrowserProvisionIntentDenied):
            run(request, tmp_path, **options)


def test_request_file_symlink_world_readable_and_oversize_rejected(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(
        intake, "provision", lambda *_: pytest.fail("must not provision")
    )
    request = tmp_path / "request.txt"
    write_request(request, issue_provision_intent(user("alice"), KEY, now=1000))
    link = tmp_path / "link.txt"
    link.symlink_to(request)
    with pytest.raises(BrowserProvisionIntentDenied):
        run(link, tmp_path)
    os.chmod(request, 0o644)
    with pytest.raises(BrowserProvisionIntentDenied):
        run(request, tmp_path)
    request.write_text("a" * 5000)
    request.chmod(0o600)
    with pytest.raises(BrowserProvisionIntentDenied):
        run(request, tmp_path)


def test_failed_provision_cleans_ephemeral_owner_file_and_consumes_nonce(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    seen = []

    def fail(_root, owner_path, *_args):
        seen.append(owner_path.name)
        raise WorkerQuarantined("deliberate no-docker failure")

    monkeypatch.setattr(intake, "provision", fail)
    request = tmp_path / "request.txt"
    write_request(request, issue_provision_intent(user("alice"), KEY, now=1000))
    with pytest.raises(WorkerQuarantined):
        run(request, tmp_path)
    assert seen and not list(tmp_path.glob(".browser-owner-*.json"))
    with pytest.raises(BrowserProvisionIntentDenied, match="replayed"):
        run(request, tmp_path)
