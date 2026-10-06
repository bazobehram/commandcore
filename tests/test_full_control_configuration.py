import json
import os
import subprocess
from argparse import Namespace

import pytest
from commandcore_agent import full_control
from commandcore_agent.privileged_helper import _write_initial_files


def test_helper_initialization_preserves_trust_and_key(installed):
    args = Namespace(
        agent_user="nobody",
        max_profile="STANDARD",
        policy_file=str(installed),
        secret_file=str(full_control.SECRET),
        update_public_key_b64="",
        update_manifest_origin=[],
    )
    assert _write_initial_files(args) == 0
    original = full_control.SECRET.read_bytes()
    assert len(original) == 48 and full_control.SECRET.stat().st_mode & 0o777 == 0o640
    assert _write_initial_files(args) == 0
    assert full_control.SECRET.read_bytes() == original
    assert (
        json.loads(installed.read_text())["update_public_key_b64"] == "retained-trust"
    )


pytestmark = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="real Linux root ownership gate",
)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    helper = tmp_path / "helper/venv/bin/commandcore-helper"
    helper.parent.mkdir(parents=True)
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "configured_max_permission_profile": "STANDARD",
                "update_public_key_b64": "retained-trust",
                "update_manifest_origins": ["https://updates.example.org"],
            }
        )
    )
    monkeypatch.setattr(full_control, "HELPER", helper)
    monkeypatch.setattr(full_control, "POLICY", policy)
    monkeypatch.setattr(full_control, "SECRET", tmp_path / "helper.key")
    monkeypatch.setattr(full_control, "UNIT", tmp_path / "commandcore-helper.service")
    return policy


def test_activation_failure_leaves_standard_and_preserves_update_trust(
    installed, monkeypatch
):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(full_control.subprocess, "run", fail)
    assert full_control.configure(True, "nobody", True) == 1
    policy = json.loads(installed.read_text())
    assert policy["configured_max_permission_profile"] == "STANDARD"
    assert policy["update_public_key_b64"] == "retained-trust"
    assert policy["update_manifest_origins"] == ["https://updates.example.org"]


def test_enable_refuses_an_unrelated_unit(installed, monkeypatch):
    full_control.UNIT.write_text("[Service]\nExecStart=/bin/sleep infinity\n")
    assert full_control.configure(True, "nobody", True) == 1
    assert not full_control.SECRET.exists()
    assert (
        json.loads(installed.read_text())["configured_max_permission_profile"]
        == "STANDARD"
    )


def test_disable_lowers_policy_before_service_call(installed, monkeypatch):
    installed.write_text(
        json.dumps(
            {
                "configured_max_permission_profile": "FULL_CONTROL",
                "update_public_key_b64": "retained-trust",
            }
        )
    )

    def check(*args, **kwargs):
        assert (
            json.loads(installed.read_text())["configured_max_permission_profile"]
            == "STANDARD"
        )

    monkeypatch.setattr(full_control.subprocess, "run", check)
    assert full_control.configure(False, "nobody") == 0
    assert (
        json.loads(installed.read_text())["update_public_key_b64"] == "retained-trust"
    )
