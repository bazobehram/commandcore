import pytest

from commandcore_agent.executor import Executor


async def _noop_output(stream, data):
    return None


@pytest.mark.asyncio
async def test_package_install_rejects_option_injection(monkeypatch, tmp_path):
    # Exercise helper-side argv validation; local trust has separate root tests.
    executor = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    result = await executor.execute(
        "x", "FULL_CONTROL", "package.install", {"packages": ["--help"]}, _noop_output
    )
    assert result["status"] == "error"
    assert "invalid package name" in result["error"]


@pytest.mark.asyncio
async def test_power_tools_require_explicit_confirm(monkeypatch, tmp_path):
    # Exercise helper-side argv validation; local trust has separate root tests.
    executor = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    denied = await executor.execute(
        "x", "FULL_CONTROL", "system.reboot", {"dry_run": True}, _noop_output
    )
    assert denied["status"] == "error"
    ok = await executor.execute(
        "y",
        "FULL_CONTROL",
        "system.reboot",
        {"confirm": True, "dry_run": True},
        _noop_output,
    )
    assert ok["status"] == "ok"
    assert ok["result"]["dry_run"] is True


@pytest.mark.asyncio
async def test_service_action_is_allowlisted(monkeypatch, tmp_path):
    # Exercise helper-side argv validation; local trust has separate root tests.
    executor = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    result = await executor.execute(
        "x",
        "FULL_CONTROL",
        "services.manage",
        {"service": "ssh", "action": "anything"},
        _noop_output,
    )
    assert result["status"] == "error"
    assert "unsupported service action" in result["error"]


@pytest.mark.asyncio
async def test_service_name_rejects_option_injection(monkeypatch, tmp_path):
    # Exercise helper-side argv validation; local trust has separate root tests.
    executor = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    result = await executor.execute(
        "x",
        "FULL_CONTROL",
        "services.manage",
        {"service": "--root=/tmp/evil", "action": "status"},
        _noop_output,
    )
    assert result["status"] == "error"
    assert "option prefix" in result["error"]
