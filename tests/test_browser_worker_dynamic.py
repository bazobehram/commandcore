"""Synthetic two-owner dynamic worker reconciliation; no Docker or live Auth0."""

from __future__ import annotations

import json
import os

import pytest
from commandcore_server.browser_gateway import BrowserError, BrowserGateway
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_dynamic import RefreshingOwnerBrowserWorkerPool


@pytest.fixture(autouse=True)
def isolated_browser_session_journal(tmp_path, monkeypatch):
    # CI runners do not have the production /data mount. Never write there in tests.
    monkeypatch.setenv("COMMANDCORE_BROWSER_JOURNAL_DIR", str(tmp_path / "journals"))


SECRET = "synthetic-test-unique-browser-owner-binding-key"
ISSUER = "https://review.example/"


class SyntheticProof:
    def verify(self, worker_id):
        return {
            "steel_started_at": "synthetic-same-incarnation",
            "boundary_name": "isolated-boundary-" + worker_id,
        }


def owner(index):
    return ISSUER, "owner-" + str(index), "review-client"


def assign(root, index):
    worker = f"w-{index:018x}"
    binding_path = root / f"{worker}.sqlite3"
    binding = BrowserWorkerBinding.provision(str(binding_path), worker, SECRET)
    binding.claim(owner(index))
    binding.close()
    return {
        "worker_id": worker,
        "binding_path": str(binding_path),
        "steel_url": f"http://ccctl-{worker}:3000",
        "cdp_url": f"ws://ccctl-{worker}:3000",
        "egress_proxy_url": "http://browser-boundary:8080",
        "egress_policy_url": f"http://ccctl-{worker}:8080",
    }


def write_manifest(path, rows):
    tmp = path.with_suffix(".new")
    tmp.write_text(json.dumps({"workers": rows}, separators=(",", ":")))
    tmp.chmod(0o600)
    os.replace(tmp, path)


def dynamic(root, manifest):
    return RefreshingOwnerBrowserWorkerPool(
        str(manifest),
        SECRET,
        ("example.com",),
        "https://commandcore.app",
        attestation=SyntheticProof(),
    )


def test_two_owner_hot_add_remove_preserves_only_same_ledger_sessions(tmp_path):
    tmp_path.chmod(0o700)
    source = tmp_path / "workers.json"
    write_manifest(source, [])
    pool = dynamic(tmp_path, source)
    assert not pool.available(*owner(1))
    first = assign(tmp_path, 1)
    write_manifest(source, [first])
    assert pool.available(*owner(1))
    assert not pool.available(*owner(2))
    worker = pool._find_worker(owner(1))
    # A verified session on an identical physical route survives additions.
    worker.sessions[owner(1)] = object()
    second = assign(tmp_path, 2)
    write_manifest(source, [first, second])
    assert pool.available(*owner(2))
    assert pool._find_worker(owner(1)) is worker
    assert owner(1) in worker.sessions
    write_manifest(source, [second])
    assert not pool.available(*owner(1))
    assert pool.available(*owner(2))
    assert worker.sessions == {}
    write_manifest(source, [])
    assert not pool.available(*owner(2))
    assert pool.workers == ()


def test_invalid_world_readable_manifest_fails_closed_scrubs_sessions(tmp_path):
    tmp_path.chmod(0o700)
    source = tmp_path / "workers.json"
    first = assign(tmp_path, 1)
    write_manifest(source, [first])
    pool = dynamic(tmp_path, source)
    worker = pool._find_worker(owner(1))
    worker.sessions[owner(1)] = object()
    source.chmod(0o644)
    with pytest.raises(BrowserError, match="unavailable or invalid"):
        pool._find_worker(owner(1))
    assert pool.workers == () and not worker.sessions
    source.chmod(0o600)
    assert pool.available(*owner(1))
    assert pool._find_worker(owner(1)) is not worker
    assert not pool._find_worker(owner(1)).sessions


def test_symlink_manifest_swap_fails_closed(tmp_path):
    tmp_path.chmod(0o700)
    source = tmp_path / "workers.json"
    first = assign(tmp_path, 1)
    write_manifest(source, [first])
    pool = dynamic(tmp_path, source)
    moved = tmp_path / "old.json"
    os.replace(source, moved)
    source.symlink_to(moved)
    with pytest.raises(BrowserError):
        pool._find_worker(owner(1))
    assert pool.workers == ()


@pytest.mark.asyncio
async def test_worker_removed_during_async_action_never_returns_result(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    source = tmp_path / "workers.json"
    first = assign(tmp_path, 1)
    write_manifest(source, [first])
    pool = dynamic(tmp_path, source)

    async def simulated_network_action(self, **kwargs):
        write_manifest(source, [])
        return {"screenshot": "synthetic-frame-must-not-escape"}

    monkeypatch.setattr(BrowserGateway, "call", simulated_network_action)
    with pytest.raises(BrowserError, match="changed during action"):
        await pool.call(
            subject=owner(1)[1],
            issuer=ISSUER,
            client_id=owner(1)[2],
            name="browser.frame",
            args={},
        )
    assert pool.workers == ()
