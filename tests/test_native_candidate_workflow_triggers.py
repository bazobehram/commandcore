"""Ensure a release identity change cannot leave native review artifacts stale."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "unsigned-linux-native-candidate.yml",
    "unsigned-linux-arm64-candidate.yml",
)
REBUILD_INPUTS = (
    "VERSION",
    "agent/rust/Cargo.toml",
    "agent/rust/Cargo.lock",
    "scripts/package_unsigned_native_candidate.py",
    "tests/test_package_unsigned_native_candidate.py",
)


@pytest.mark.parametrize("name", WORKFLOWS)
def test_native_candidate_rebuilds_when_release_identity_changes(name):
    source = (ROOT / ".github" / "workflows" / name).read_text()
    for path in REBUILD_INPUTS:
        assert f"      - '{path}'" in source
    assert "branches: [main]" in source
    assert "if: github.ref == 'refs/heads/main'" in source
    assert "workflow_dispatch:" in source
    assert "permissions:\n  contents: read" in source
