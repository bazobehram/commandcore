"""Read-only public routing fixture: no live operator state or OAuth."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from commandcore_server.browser_gateway import BrowserError
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_dynamic import RefreshingOwnerBrowserWorkerPool
from commandcore_server.browser_worker_orchestrator import WorkerQuarantined

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_worker_publish as publisher

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux DAC")
KEY = "synthetic-publication-owner-key-for-testing"
ISSUER = "https://review.example/"


class Proof:
    def verify(self, worker_id):
        return {
            "steel_started_at": "synthetic-incarnation",
            "boundary_name": "ccbw-boundary-" + worker_id,
        }


def owner(n):
    return ISSUER, f"owner-{n}", "fixture-client"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    uid = os.getuid() or 10001
    gid = os.getgid() or 987
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    root = tmp_path / "public"
    root.mkdir(mode=0o750)
    os.chown(root, uid, gid)
    root.chmod(0o750)
    monkeypatch.setattr(os, "getgroups", lambda: [gid])
    monkeypatch.setenv("COMMANDCORE_BROWSER_JOURNAL_DIR", str(tmp_path / "journals"))
    rows = []
    for n in (1, 2):
        worker = f"w-{n:018x}"
        folder = state / worker
        folder.mkdir(mode=0o700)
        source = folder / "owner.sqlite3"
        binding = BrowserWorkerBinding.provision(str(source), worker, KEY)
        binding.claim(owner(n))
        binding.close()
        os.chown(source, uid, gid)
        rows.append(
            {
                "worker_id": worker,
                "state": "active",
                "relay": {"fixture": True},
                "route": {"binding_path": str(source)},
            }
        )

    def store():
        path = state / "registry.json"
        path.write_text(json.dumps({"workers": rows}))
        path.chmod(0o600)

    def publish():
        store()
        return publisher.publish_once(state, root, uid=uid, gid=gid)

    def pool():
        return RefreshingOwnerBrowserWorkerPool(
            str(root / "browser-workers.json"),
            KEY,
            ("example.com",),
            "https://commandcore.app",
            attestation=Proof(),
            publication_identity=(uid, gid),
        )

    return root, rows, publish, pool


def test_two_owners_read_only_and_route_withdrawal(setup):
    root, rows, publish, pool = setup
    assert publish() == 2
    active = pool()
    assert active.available(*owner(1)) and active.available(*owner(2))
    assert not active.available(*owner(3))
    first = active._find_worker(owner(1))
    path = first.worker_binding.path
    identity = path.stat().st_ino
    with pytest.raises(Exception, match="another OAuth user"):
        first.worker_binding.claim(owner(2))
    assert publish() == 2 and path.stat().st_ino == identity
    rows[0]["state"] = "stopping"
    assert publish() == 1
    assert not active.available(*owner(1))
    assert active.available(*owner(2))
    assert {x.name for x in root.iterdir()} == {
        "browser-workers.json",
        "w-000000000000000001.sqlite3",
        "w-000000000000000002.sqlite3",
    }


def test_invalid_binding_permissions_withdraw_routes(setup):
    root, _, publish, pool = setup
    publish()
    active = pool()
    first = active._find_worker(owner(1))
    first.sessions[owner(1)] = object()
    first.worker_binding.path.chmod(0o660)
    with pytest.raises(WorkerQuarantined):
        publish()
    assert json.loads((root / "browser-workers.json").read_text()) == {"workers": []}
    assert not active.available(*owner(1))
    assert first.sessions == {}


def test_manifest_cannot_point_at_another_worker_binding(setup):
    root, _, publish, pool = setup
    publish()
    active = pool()
    manifest = root / "browser-workers.json"
    data = json.loads(manifest.read_text())
    data["workers"][0]["binding_path"] = data["workers"][1]["binding_path"]
    manifest.write_text(json.dumps(data))
    with pytest.raises(BrowserError, match="manifest unavailable"):
        active.refresh()
    assert active.workers == ()
