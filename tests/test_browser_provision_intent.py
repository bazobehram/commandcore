"""Offline fail-closed tests; synthetic identities, no Docker/real OAuth tokens."""

from __future__ import annotations

import base64
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from commandcore_server.browser_provision_intent import (
    BrowserProvisionIntentDenied,
    ProvisionNonceLedger,
    issue_provision_intent,
    verify_and_consume_provision_intent,
    verify_provision_intent,
)
from commandcore_server.models import Principal

ISSUER = "https://issuer.example/"
KEY = b"synthetic-unique-provision-intent-key-for-tests"


def user(
    subject="alice",
    *,
    scopes=("commandcore:standard",),
    kind="oauth2",
    client="app-one",
):
    return Principal(
        subject=subject, client_id=client, auth_kind=kind, scopes=scopes, issuer=ISSUER
    )


def make(subject="alice"):
    return issue_provision_intent(user(subject), KEY, now=1000)


def test_accepted_oauth_owner_and_client_and_unique_nonces():
    a = verify_provision_intent(make("alice"), KEY, ISSUER, now=1030)
    b = verify_provision_intent(make("bob"), KEY, ISSUER, now=1030)
    assert (a.issuer, a.subject, a.client_id) == (ISSUER, "alice", "app-one")
    assert a.nonce != b.nonce
    assert b.subject == "bob"
    assert "commandcore:standard" not in make()  # no scope or bearer material forwarded


@pytest.mark.parametrize(
    "principal",
    [
        user(scopes=("commandcore:read",)),
        user(scopes=()),
        user(kind="bootstrap-bearer"),
        user(kind="oauth2-panel"),
        user(client="oauth-client"),
        user(client="unknown"),
        user(subject=""),
        Principal(
            subject="alice",
            client_id="app-one",
            auth_kind="oauth2",
            scopes=("commandcore:standard",),
            issuer="http://issuer.example/",
        ),
    ],
)
def test_non_authorized_identity_cannot_issue(principal):
    with pytest.raises(BrowserProvisionIntentDenied):
        issue_provision_intent(principal, KEY, now=1000)


def test_full_scope_allowed_for_verified_oauth():
    token = issue_provision_intent(user(scopes=("commandcore:full",)), KEY, now=1000)
    assert verify_provision_intent(token, KEY, ISSUER, now=1000).subject == "alice"


def test_wrong_key_audience_tampered_and_expired_denied():
    token = make()
    payload, tag = token.split(".")
    invalid = [
        (token, b"different-dedicated-operator-provision-key-32bytes", ISSUER, 1000),
        (token, KEY, "https://other-issuer.example/", 1000),
        (payload + "A." + tag, KEY, ISSUER, 1000),
        (payload + "." + "A" * len(tag), KEY, ISSUER, 1000),
        (token, KEY, ISSUER, 1060),
        (token, KEY, ISSUER, 993),
        (token + ".extra", KEY, ISSUER, 1000),
        ("", KEY, ISSUER, 1000),
        ("x" * 5000, KEY, ISSUER, 1000),
    ]
    for text, key, issuer, now in invalid:
        with pytest.raises(BrowserProvisionIntentDenied):
            verify_provision_intent(text, key, issuer, now=now)


def test_payload_is_not_an_oauth_bearer_token():
    payload = make().split(".")[0]
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert set(decoded) == {"v", "aud", "iss", "sub", "cid", "jti", "iat", "exp"}
    assert "access_token" not in decoded and "password" not in decoded


def test_nonce_ledger_is_durable_and_rejects_replay(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "nonce.sqlite3"
    first = verify_provision_intent(make("alice"), KEY, ISSUER, now=1005)
    second = verify_provision_intent(make("bob"), KEY, ISSUER, now=1005)
    ledger = ProvisionNonceLedger(str(path))
    ledger.consume(first, now=1005)
    new_process_ledger = ProvisionNonceLedger(str(path))
    with pytest.raises(BrowserProvisionIntentDenied, match="replayed"):
        new_process_ledger.consume(first, now=1006)
    new_process_ledger.consume(second, now=1007)
    assert (path.stat().st_mode & 0o077) == 0


def test_nonce_ledger_parallel_consumers_only_one_success(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "nonce.sqlite3"
    intent = verify_provision_intent(make(), KEY, ISSUER, now=1001)
    ProvisionNonceLedger(str(path))

    def consume(_):
        try:
            ProvisionNonceLedger(str(path)).consume(intent, now=1001)
            return True
        except BrowserProvisionIntentDenied:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, range(2)))
    assert sorted(results) == [False, True]


def test_nonce_ledger_rejects_symlink_world_readable_and_replacement(tmp_path):
    tmp_path.chmod(0o700)
    real = tmp_path / "real.sqlite3"
    ledger = ProvisionNonceLedger(str(real))
    link = tmp_path / "link.sqlite3"
    link.symlink_to(real)
    with pytest.raises(BrowserProvisionIntentDenied):
        ProvisionNonceLedger(str(link))
    old = tmp_path / "old.sqlite3"
    os.replace(real, old)
    with pytest.raises((BrowserProvisionIntentDenied, OSError)):
        ledger.consume(verify_provision_intent(make(), KEY, ISSUER, now=1001), now=1001)
    os.replace(old, real)
    os.chmod(real, 0o644)
    with pytest.raises(BrowserProvisionIntentDenied):
        ProvisionNonceLedger(str(real))


def test_operator_entrypoint_requires_nonce_consumption(tmp_path):
    tmp_path.chmod(0o700)
    ledger = ProvisionNonceLedger(str(tmp_path / "ledger.sqlite3"))
    token = make()
    verified = verify_and_consume_provision_intent(token, KEY, ISSUER, ledger, now=1003)
    assert verified.subject == "alice"
    with pytest.raises(BrowserProvisionIntentDenied, match="replayed"):
        verify_and_consume_provision_intent(token, KEY, ISSUER, ledger, now=1004)
