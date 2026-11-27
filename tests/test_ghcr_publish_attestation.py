"""GHCR release workflow must sign and verify immutable image provenance."""

from pathlib import Path

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ghcr-publish.yml"


def test_ghcr_publish_generates_and_verifies_signed_digest_provenance():
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    assert workflow["on"] == {"push": {"branches": ["main"], "tags": ["v*"]}}

    job = workflow["jobs"]["publish"]
    assert job["environment"] == "ghcr-publish"
    assert job["runs-on"] == "ubuntu-latest"
    assert "github.repository == 'bazobehram/commandcore'" in job["if"]
    permissions = job["permissions"]
    assert permissions == {
        "contents": "read",
        "packages": "write",
        "attestations": "write",
        "id-token": "write",
    }

    steps = job["steps"]
    build_index = next(i for i, step in enumerate(steps) if step.get("id") == "build")
    attest_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Generate signed GitHub provenance attestation"
    )
    verify_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Verify signed provenance for exact image digest"
    )
    parity_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Verify immutable server code and packaged MCP UI bytes"
    )
    assert build_index < parity_index < attest_index < verify_index
    assert any(
        step.get("name") == "Validate reviewed source ref"
        and '[[ "$GITHUB_REF" == "refs/heads/main" ]]' in step["run"]
        for step in steps
    )
    assert (
        next(step for step in steps if step.get("id") == "meta")["with"]["flavor"]
        == "latest=false"
    )

    attestation = steps[attest_index]
    assert attestation["uses"] == (
        "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    )
    assert attestation["with"] == {
        "subject-name": "ghcr.io/${{ github.repository }}",
        "subject-digest": "${{ steps.build.outputs.digest }}",
        "push-to-registry": "true",
        "create-storage-record": "false",
    }

    verification = steps[verify_index]
    assert verification["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert verification["env"]["RELEASE_IMAGE"] == (
        "ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}"
    )
    command = verification["run"]
    assert 'gh attestation verify "oci://${RELEASE_IMAGE}"' in command
    assert '--repo "$GITHUB_REPOSITORY"' in command
    assert (
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/ghcr-publish.yml"'
        in command
    )
    assert '--source-ref "$GITHUB_REF"' in command
    assert '--source-digest "$GITHUB_SHA"' in command
    assert "--deny-self-hosted-runners" in command
