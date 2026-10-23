"""Network and worker proof gates run offline with adversarial inputs."""

import asyncio
import hashlib
import hmac
import json
from unittest.mock import AsyncMock

import pytest

from commandcore_server.browser_egress import EgressDenied, _resolve_global
from commandcore_server.browser_gateway import BrowserError, check_url
from commandcore_server.browser_worker_attestation import (
    BINDING_FIELDS,
    BrowserAttestationError,
    WorkerAttestationVerifier,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com:444",
        "https://user:password@example.com",
        "https://127.0.0.1",
        "https://[::1]",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost",
        "https://metadata.internal",
        "file:///etc/passwd",
        "https://example.com.evil.invalid",
        "https://2130706433",
        "https://0x7f000001",
    ],
)
def test_public_web_mode_still_denies_internal_navigation(url):
    with pytest.raises(BrowserError):
        check_url(url, ("*",))


def test_allowlist_is_exact_or_explicit_subdomain():
    assert check_url("https://docs.example.com/", ("*.example.com",))
    for url in [
        "https://example.com",
        "https://evilexample.com",
        "https://example.com.evil.com",
    ]:
        with pytest.raises(BrowserError):
            check_url(url, ("*.example.com",))


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["10.0.0.1"],
        ["::1"],
        ["fe80::1"],
        ["8.8.8.8", "192.168.1.1"],
        [],
        ["2002:0808:0808::1"],
    ],
)
def test_dns_rejects_entire_mixed_or_private_answer(monkeypatch, addresses):
    async def run():
        lookup = AsyncMock(
            return_value=[(None, None, None, None, (ip, 443)) for ip in addresses]
        )
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", lookup)
        with pytest.raises(EgressDenied):
            await _resolve_global("example.com", 443)

    asyncio.run(run())


def test_dns_returns_validated_numeric_address_without_second_lookup(monkeypatch):
    async def run():
        lookup = AsyncMock(return_value=[(None, None, None, None, ("8.8.8.8", 443))])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", lookup)
        assert await _resolve_global("example.com", 443) == ("8.8.8.8", 443)
        assert lookup.await_count == 1

    asyncio.run(run())


def test_worker_proof_rejects_stale_tampered_and_foreign_worker(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "proof.json"
    secret = "fixture-proof-key-" + "x" * 32
    row = {key: "fixture" for key in BINDING_FIELDS}
    row.update(worker_id="worker-one", steel_started_at="2026-01-01T00:00:00Z")
    body = {"version": 1, "issued_at": 100, "workers": [row]}
    mac = hmac.new(
        secret.encode(),
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    path.write_text(json.dumps({**body, "hmac_sha256": mac}))
    path.chmod(0o600)
    verifier = WorkerAttestationVerifier(str(path), secret)
    assert verifier.verify("worker-one", now=100)["worker_id"] == "worker-one"
    for worker, now in [("worker-two", 100), ("worker-one", 113), ("worker-one", 97)]:
        with pytest.raises(BrowserAttestationError):
            verifier.verify(worker, now=now)
    row["steel_container_id"] = "substituted-container"
    path.write_text(json.dumps({**body, "hmac_sha256": mac}))
    with pytest.raises(BrowserAttestationError, match="signature"):
        verifier.verify("worker-one", now=100)
