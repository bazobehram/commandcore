from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = (
    Path(__file__).resolve().parents[1] / "scripts/verify_shell_timeout_deployment.py"
)
SPEC = importlib.util.spec_from_file_location("timeout_deployment_guard", SOURCE)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


def fake_docker(monkeypatch, *, overrides=None, health="healthy", result_code=0):
    data = {
        "tool_count": 48,
        "required_tools": sorted(module.REQUIRED_TOOLS),
        "default_ms": 8000,
        "max_ms": 10000,
        "send_seconds": 3.0,
        "cancel_seconds": 2.0,
    }
    data.update(overrides or {})
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "inspect":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps([{"State": {"Health": {"Status": health}}}]),
            )
        return SimpleNamespace(returncode=result_code, stdout=json.dumps(data))

    monkeypatch.setattr(module.subprocess, "run", run)
    return calls


def test_matching_live_policy_passes(monkeypatch):
    calls = fake_docker(monkeypatch)
    assert module.verify("commandcore-public-commandcore-1", 48)["status"] == "PASS"
    assert [call[1] for call in calls] == ["inspect", "exec"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("default_ms", 30000),
        ("max_ms", 3600000),
        ("send_seconds", 15.0),
        ("cancel_seconds", 5.0),
    ],
)
def test_timeout_drift_fails_closed(monkeypatch, field, value):
    fake_docker(monkeypatch, overrides={field: value})
    with pytest.raises(ValueError, match="timeout_policy_drift"):
        module.verify("private-controller")


def test_missing_managed_process_tool_rejected(monkeypatch):
    fake_docker(monkeypatch, overrides={"required_tools": ["shell.exec"]})
    with pytest.raises(ValueError, match="managed_process_tools_missing"):
        module.verify("private-controller")


def test_tool_count_mismatch_rejected(monkeypatch):
    fake_docker(monkeypatch)
    with pytest.raises(ValueError, match="tool_count_drift"):
        module.verify("private-controller", 50)


def test_unhealthy_container_rejected_without_exec(monkeypatch):
    calls = fake_docker(monkeypatch, health="starting")
    with pytest.raises(ValueError, match="container_not_healthy"):
        module.verify("private-controller")
    assert len(calls) == 1


@pytest.mark.parametrize("name", ["", "-bad", "../bad", "bad;whoami", "bad name"])
def test_invalid_container_name_rejected_before_docker(monkeypatch, name):
    calls = fake_docker(monkeypatch)
    with pytest.raises(ValueError, match="invalid_container_name"):
        module.verify(name)
    assert not calls


def test_docker_error_fails_without_output(monkeypatch):
    fake_docker(monkeypatch, result_code=1)
    with pytest.raises(ValueError, match="docker_probe_failed"):
        module.verify("private-controller")


def test_missing_docker_binary_exits_without_traceback(monkeypatch, capsys):
    def missing(*args, **kwargs):
        raise FileNotFoundError("docker is not installed")

    monkeypatch.setattr(module.subprocess, "run", missing)
    monkeypatch.setattr(
        module.sys,
        "argv",
        ["verify_shell_timeout_deployment.py", "--container", "example"],
    )
    assert module.main() == 1
    assert "probe_unavailable" in capsys.readouterr().err
