"""Browser master switch must disable all API-side Browser components."""

import os
import subprocess
import sys
from dataclasses import replace

import pytest
from commandcore_server.config import Settings


def test_master_off_keeps_subordinate_configuration_dormant():
    settings = replace(
        Settings(),
        browser_enabled=False,
        api_token="fixture-api-only-" * 3,
        panel_session_secret="fixture-panel-only-" * 3,
        oauth_enabled=False,
        browser_dynamic_workers_enabled=True,
        browser_uds_relay_enabled=True,
        browser_provision_api_enabled=True,
        browser_worker_manifest="/nonexistent-fixture-manifest",
        browser_uds_relay_root="/nonexistent-fixture-sockets",
        browser_provision_socket="/nonexistent-fixture-provision.sock",
        browser_allow_hosts=(),
    )
    settings.validate()
    with pytest.raises(RuntimeError, match="Unix relay requires"):
        replace(settings, browser_enabled=True).validate()


def test_master_switch_does_not_disable_non_browser_security_validation():
    settings = replace(
        Settings(),
        browser_enabled=False,
        browser_uds_relay_enabled=True,
        api_token="short",
    )
    with pytest.raises(RuntimeError, match="COMMANDCORE_API_TOKEN"):
        settings.validate()


def test_master_off_server_starts_without_browser_or_provisioner(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMMANDCORE_")}
    env.update(
        COMMANDCORE_DB=str(tmp_path / "fixture.sqlite3"),
        COMMANDCORE_UI_TASK_DB=str(tmp_path / "ui-tasks.sqlite3"),
        COMMANDCORE_API_TOKEN="fixture-api-only-" * 3,
        COMMANDCORE_PANEL_SESSION_SECRET="fixture-panel-only-" * 3,
        COMMANDCORE_OAUTH_ENABLED="false",
        COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED="false",
        COMMANDCORE_BROWSER_ENABLED="false",
        COMMANDCORE_BROWSER_DYNAMIC_WORKERS_ENABLED="true",
        COMMANDCORE_BROWSER_UDS_RELAY_ENABLED="true",
        COMMANDCORE_BROWSER_PROVISION_API_ENABLED="true",
        COMMANDCORE_BROWSER_WORKER_MANIFEST="/nonexistent-fixture-manifest",
        COMMANDCORE_BROWSER_UDS_RELAY_ROOT="/nonexistent-fixture-sockets",
        COMMANDCORE_BROWSER_PROVISION_SOCKET="/nonexistent-fixture-provision.sock",
    )
    code = """
from commandcore_server import main
assert main.browser is None and main.provisioner is None
assert not any(x["name"] in main.BROWSER_TOOL_NAMES for x in main.visible_tools)
assert not any(x["name"] in main.BROWSER_TOOL_NAMES for x in main.visible_core_tools)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
