"""Operator provisioning must not reassign OAuth owners, even after retirement."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from commandcore_server.browser_worker_binding import BrowserWorkerBinding
from commandcore_server.browser_worker_orchestrator import WorkerQuarantined


def _load_operator():
    path = Path(__file__).resolve().parents[1] / "scripts/browser_worker_lifecycle.py"
    spec = importlib.util.spec_from_file_location(
        "commandcore_operator_lifecycle_test", path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("prior_state", ["active", "stopped", "retired"])
def test_existing_oauth_owner_cannot_be_provisioned_again(
    tmp_path, monkeypatch, prior_state
):
    module = _load_operator()
    tmp_path.chmod(0o700)
    key = "synthetic-test-only-binding-key-long-enough"
    owner = {
        "issuer": "https://review.invalid/",
        "subject": "owner-one",
        "client_id": "review-client",
    }
    owner_file = tmp_path / "owner.json"
    owner_file.write_text(json.dumps(owner))
    owner_file.chmod(0o600)
    binding_file = tmp_path / "binding.sqlite3"
    ledger = BrowserWorkerBinding.provision(
        str(binding_file), "w-111111111111111111", key
    )
    ledger.claim((owner["issuer"], owner["subject"], owner["client_id"]))
    ledger.close()
    entries = [
        {
            "worker_id": "w-111111111111111111",
            "state": prior_state,
            "route": {"binding_path": str(binding_file)},
        }
    ]

    @contextmanager
    def isolated_state(_root):
        yield entries

    monkeypatch.setattr(module, "exclusive_state", isolated_state)
    monkeypatch.setattr(module, "inspect_image", lambda _: "sha256:" + "a" * 64)
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}")
    monkeypatch.setattr(module, "SECCOMP_PROFILE", seccomp)
    monkeypatch.setattr(
        module,
        "SECCOMP_SOURCE_SHA256",
        hashlib.sha256(seccomp.read_bytes()).hexdigest(),
    )

    with pytest.raises(
        WorkerQuarantined, match="already has a browser worker assignment"
    ):
        module.provision(
            tmp_path, owner_file, "example.com", "mock:steel", "mock:boundary", key
        )
    assert entries[0]["state"] == prior_state

    binding_file.unlink()
    with pytest.raises(WorkerQuarantined, match="ledger cannot be verified"):
        module.provision(
            tmp_path, owner_file, "example.com", "mock:steel", "mock:boundary", key
        )
