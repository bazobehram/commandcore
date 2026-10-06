from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_alignment_for_native_candidate():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    import re

    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version)
    root_project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    agent_project = tomllib.loads(
        (ROOT / "agent/pyproject.toml").read_text(encoding="utf-8")
    )
    cargo = tomllib.loads((ROOT / "agent/rust/Cargo.toml").read_text(encoding="utf-8"))
    assert root_project["project"]["version"] == version
    assert agent_project["project"]["version"] == version
    native_version = cargo["package"]["version"]
    lock = tomllib.loads((ROOT / "agent/rust/Cargo.lock").read_text(encoding="utf-8"))
    assert (
        next(
            p["version"]
            for p in lock["package"]
            if p["name"] == "commandcore-agent-rust"
        )
        == native_version
    )
    assert 'pub const VERSION: &str = env!("CARGO_PKG_VERSION")' in (
        ROOT / "agent/rust/src/client.rs"
    ).read_text(encoding="utf-8")
    assert 'const VERSION: &str = env!("CARGO_PKG_VERSION")' in (
        ROOT / "agent/rust/src/executor.rs"
    ).read_text(encoding="utf-8")


def test_rust_network_agent_source_contract_is_present():
    required = {
        "client.rs",
        "executor.rs",
        "helper.rs",
        "lib.rs",
        "main.rs",
        "output.rs",
        "policy.rs",
        "protocol.rs",
        "state.rs",
    }
    src = ROOT / "agent/rust/src"
    assert required.issubset({p.name for p in src.glob("*.rs")})
    client = (src / "client.rs").read_text(encoding="utf-8")
    main = (src / "main.rs").read_text(encoding="utf-8")
    executor = (src / "executor.rs").read_text(encoding="utf-8")
    helper = (src / "helper.rs").read_text(encoding="utf-8")
    for marker in (
        "crate::network::connect",
        '"type":"hello"',
        '"job.request"',
        '"job.cancel"',
        '"heartbeat"',
    ):
        assert marker in client
    for marker in (
        "Enroll",
        "Run",
        "Status",
        "RotateKey",
        "Capabilities",
        "validate_endpoints",
    ):
        assert marker in main
    for tool in (
        "fs.read",
        "fs.write",
        "shell.exec",
        "process.start",
        "process.list",
        "system.info",
        "git.status",
        "git.run",
    ):
        assert f'"{tool}"' in executor
    assert '"permission_profile":"FULL_CONTROL"' in helper
    assert "COMMANDCORE_HELPER_SOCKET" in helper


def test_rust_candidate_ci_has_hard_compile_and_black_box_gates():
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "rust-agent-parity:" in ci
    assert "cargo test --locked --manifest-path agent/rust/Cargo.toml" in ci
    assert "cargo build --locked --release --manifest-path agent/rust/Cargo.toml" in ci
    assert "python scripts/rust_agent_smoke.py" in ci
    assert "scripts/rust_full_control_smoke.py" in ci
    assert "continue-on-error: true" not in ci
    assert "--all-targets --all-features -- -D warnings" in ci


def test_rust_candidate_does_not_ship_unverified_binary():
    assert "target/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert not (ROOT / "dist/commandcore-agent").exists()
    assert (ROOT / "agent/rust/Cargo.lock").is_file()


def test_rust_enrollment_requires_explicit_secure_remote_endpoints():
    main = (ROOT / "agent/rust/src/main.rs").read_text(encoding="utf-8")
    assert 'default_value="http://127.0.0.1' not in main
    assert "/agent/ws" not in main
    assert "remote control URL must use HTTPS" in main
    assert "remote Agent URL must use WSS" in main
    assert "--insecure is allowed only for loopback development" in main
