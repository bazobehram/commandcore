import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_rust_crate_declares_native_candidate_and_required_dependencies():
    cargo = tomllib.loads(read("agent/rust/Cargo.toml"))
    assert cargo["package"]["name"] == "commandcore-agent-rust"
    version = cargo["package"]["version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version)
    locked = tomllib.loads(read("agent/rust/Cargo.lock"))
    native = [p for p in locked["package"] if p["name"] == "commandcore-agent-rust"]
    assert len(native) == 1 and native[0]["version"] == version
    deps = cargo["dependencies"]
    for dep in (
        "tokio",
        "tokio-tungstenite",
        "reqwest",
        "ed25519-dalek",
        "hmac",
        "serde_json",
    ):
        assert dep in deps


def test_rust_cli_exposes_identity_network_and_parity_commands():
    main = read("agent/rust/src/main.rs")
    for command in ("Enroll", "Run", "RotateKey", "Capabilities"):
        assert command in main
    assert "connect_authenticated" in main
    assert "danger_accept_invalid_certs(insecure)" in main
    assert "Refusing to overwrite existing Agent identity" in main


def test_rust_network_path_implements_protocol_v1_reconnect_heartbeat_jobs_and_cancel():
    client = read("agent/rust/src/client.rs")
    for token in (
        '"type":"hello"',
        '"type":"heartbeat"',
        '"job.request"',
        '"job.cancel"',
        '"job.result"',
        '"job.output"',
        "reconnecting in",
        "PROTOCOL_VERSION",
    ):
        assert token in client or token in read("agent/rust/src/output.rs")


def test_rust_agent_enforces_local_ceiling_and_uses_existing_helper_for_full_control():
    executor = read("agent/rust/src/executor.rs")
    policy = read("agent/rust/src/policy.rs")
    helper = read("agent/rust/src/helper.rs")
    assert "local_permission_ceiling" in executor
    assert "privileged_helper_unavailable_or_not_authorized" in executor
    assert "profile == PermissionProfile::FullControl" in executor
    assert "COMMANDCORE_HELPER_SOCKET" in helper
    assert "COMMANDCORE_HELPER_SECRET" in helper
    assert "Hmac" in helper and "Sha256" in helper
    assert '"agent.update.activate"' in policy
    assert '"agent.update.rollback"' in policy


def test_rust_standard_read_only_surface_covers_phase1_acceptance_tools():
    src = read("agent/rust/src/executor.rs")
    for tool in (
        "fs.list",
        "fs.stat",
        "fs.read",
        "fs.write",
        "fs.patch",
        "fs.search",
        "fs.copy",
        "fs.move",
        "fs.delete",
        "shell.exec",
        "process.start",
        "process.list",
        "process.status",
        "process.output",
        "process.stop",
        "system.info",
        "system.metrics",
        "transfer.upload",
        "transfer.download",
        "git.status",
        "git.diff",
        "git.log",
        "git.run",
        "agent.update.status",
    ):
        assert f'"{tool}"' in src


def test_rust_state_is_atomic_private_and_rotation_recoverable_by_design():
    state = read("agent/rust/src/state.rs")
    client = read("agent/rust/src/client.rs")
    main = read("agent/rust/src/main.rs")
    assert "create_new(true)" in state
    assert "0o600" in state
    assert "fs::rename" in state
    assert "pending_private_key_b64" in state
    assert "prefer_pending" in client
    assert "key_rotation_not_pending" in main


def test_ci_requires_compile_and_standard_full_control_black_box_parity():
    ci = read(".github/workflows/ci.yml")
    assert "rust-agent-parity:" in ci
    assert "cargo test --locked --manifest-path agent/rust/Cargo.toml" in ci
    assert "cargo build --locked --release --manifest-path agent/rust/Cargo.toml" in ci
    assert (
        "cargo clippy --locked --manifest-path agent/rust/Cargo.toml --all-targets --all-features -- -D warnings"
        in ci
    )
    assert "continue-on-error: true" not in ci
    assert "scripts/rust_agent_smoke.py" in ci
    assert "scripts/rust_full_control_smoke.py" in ci


def test_linux_installer_keeps_python_known_good_unless_native_is_explicitly_selected():
    install = read("agent/install-linux.sh")
    assert 'NATIVE_BINARY=""' in install
    assert 'ACTIVATE_NATIVE="false"' in install
    assert "--native-binary" in install
    assert "--activate-native" in install
    assert 'ln -sfn "releases/$PY_RELEASE_ID" "$PREFIX/current"' in install
    assert 'ln -sfn "releases/$NATIVE_RELEASE_ID" "$PREFIX/current"' in install
    assert 'if [[ -x "$PREFIX/current/commandcore-agent" ]]' in install
    assert 'exec "$PREFIX/current/venv/bin/commandcore-agent"' in install
