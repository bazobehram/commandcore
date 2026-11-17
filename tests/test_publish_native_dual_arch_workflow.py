"""Public native Agent release publication must verify both signed Linux arches."""

from pathlib import Path

import yaml


WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github/workflows/publish-native-agent.yml"
)


def test_public_agent_publish_requires_signed_x86_and_arm64():
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    assert "workflow_dispatch" in workflow["on"]
    job = workflow["jobs"]["publish"]
    assert job["environment"] == "agent-release"
    step = next(
        item
        for item in job["steps"]
        if item.get("name") == "Verify signed release before publication"
    )
    command = step["run"]
    assert "for architecture in x86_64 arm64; do" in command
    assert '--architecture "$architecture"' in command
    assert command.count("verify_native_agent_release.py") == 1
    assert "artifacts'][0]" not in command
    assert (
        step["env"]["RELEASE_PUBLIC_KEY"] == "${{ vars.AGENT_RELEASE_PUBLIC_KEY_B64 }}"
    )
    assert step["env"]["RELEASE_VERSION"] == "${{ inputs.version }}"
    assert step["env"]["REPOSITORY"] == "${{ github.repository }}"
