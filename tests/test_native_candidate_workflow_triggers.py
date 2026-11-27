"""Ensure a release identity change cannot leave native review artifacts stale."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "unsigned-linux-native-candidate.yml",
    "unsigned-linux-arm64-candidate.yml",
)
REBUILD_INPUTS = (
    "VERSION",
    "agent/rust/Cargo.toml",
    "agent/rust/Cargo.lock",
    "agent/rust/src/**",
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


@pytest.mark.parametrize("name,arch", zip(WORKFLOWS, ("x86_64", "arm64"), strict=True))
def test_native_build_provenance_is_verified_before_upload(name, arch):
    workflow = yaml.load(
        (ROOT / ".github" / "workflows" / name).read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"push", "workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["unsigned-linux-candidate"]
    assert job["permissions"] == {
        "contents": "read",
        "attestations": "write",
        "id-token": "write",
    }
    assert job["runs-on"] in {"ubuntu-22.04", "ubuntu-22.04-arm"}
    steps = job["steps"]
    attest = next(
        i
        for i, s in enumerate(steps)
        if s.get("name") == "Attest exact native binary and build metadata"
    )
    verify = next(
        i
        for i, s in enumerate(steps)
        if s.get("name") == "Verify native build provenance"
    )
    upload = next(
        i
        for i, s in enumerate(steps)
        if s.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert attest < verify < upload
    assert (
        steps[attest]["uses"]
        == "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    )
    root = "dist/unsigned-native-agent-candidate/"
    assert steps[attest]["with"]["subject-path"].splitlines() == [
        root + "commandcore-agent-linux-" + arch,
        root + "UNSIGNED_BUILD_METADATA.json",
    ]
    command = steps[verify]["run"]
    assert 'gh attestation verify "$file"' in command
    assert f'--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/{name}"' in command
    assert '--source-ref refs/heads/main --source-digest "$GITHUB_SHA"' in command
    assert "--deny-self-hosted-runners" in command
