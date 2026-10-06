from pathlib import Path


def test_helper_runtime_directory_is_traversable_but_socket_is_group_restricted():
    root = Path(__file__).resolve().parents[1]
    service = (root / "deploy/systemd/commandcore-helper.service").read_text()
    installer = (root / "agent/install-linux.sh").read_text()
    assert "RuntimeDirectoryMode=0755" in service
    assert "RuntimeDirectoryMode=0755" in installer
    # The helper itself narrows the endpoint after creation.
    helper = (root / "agent/commandcore_agent/privileged_helper.py").read_text()
    assert "os.chmod(self.socket_path, 0o660)" in helper


def test_network_agent_systemd_service_remains_unprivileged():
    root = Path(__file__).resolve().parents[1]
    service = (root / "deploy/systemd/commandcore-agent.service").read_text()
    installer = (root / "agent/install-linux.sh").read_text()
    assert "User=commandcore" in service
    assert "NoNewPrivileges=true" in service
    assert "User=$SERVICE_USER" in installer
    assert "NoNewPrivileges=true" in installer
    assert "User=root\nGroup=root" not in service


def test_v070_install_has_versioned_agent_pointer_and_stable_updater_runtime():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "agent/install-linux.sh").read_text()
    service = (root / "deploy/systemd/commandcore-agent.service").read_text()
    assert "releases/$PY_RELEASE_ID" in installer
    assert 'ln -sfn "releases/$PY_RELEASE_ID" "$PREFIX/current"' in installer
    assert "/usr/local/bin/commandcore-updater" in installer
    assert "$HELPER_DIR/venv/bin/commandcore-agent" in installer
    assert (
        "COMMANDCORE_AGENT_HEALTH_FILE=/run/commandcore-agent/health.json" in installer
    )
    assert "RuntimeDirectory=commandcore-agent" in installer
    assert "ExecStart=/usr/local/bin/commandcore-agent run" in service


def test_v070_installer_supports_root_owned_update_trust():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "agent/install-linux.sh").read_text()
    helper = (root / "agent/commandcore_agent/privileged_helper.py").read_text()
    assert "--update-public-key-b64" in installer
    assert "--update-manifest-origin" in installer
    assert "--update-public-key-b64" in helper
    assert "--update-manifest-origin" in helper
    assert "/etc/commandcore/agent-policy.json" in helper
