"""Same-version FULL_CONTROL reinstall never re-runs the root helper."""

import json
import subprocess
from pathlib import Path


INSTALLER = Path(__file__).resolve().parents[1] / "install/linux.sh"


def _run_status_probe(
    tmp_path: Path, *, helper: bool, version: str
) -> subprocess.CompletedProcess[str]:
    source = INSTALLER.read_text()
    start = source.index(
        '  if [ "$service" = yes ] && systemctl is-active --quiet commandcore-helper.service'
    )
    end = source.index("    # An existing but unhealthy/different helper", start)
    # Execute the production predicate unchanged. Stub only the service/Agent
    # providers, never sudo or the network; this isolates the idempotence gate.
    branch = source[start:end].split("  else\n", 1)[0]
    script = branch + '\n  else\n    echo "Helper needs preparation"\n  fi\n'
    stub = tmp_path / "bin"
    stub.mkdir()
    sysctl = stub / "systemctl"
    sysctl.write_text("#!/bin/sh\nexit " + ("0" if helper else "3") + "\n")
    sysctl.chmod(0o755)
    exe = tmp_path / "agent" / "current" / "commandcore-agent"
    exe.parent.mkdir(parents=True)
    facts = {
        "privileged_helper": helper,
        "privileged_helper_version": version,
        "local_max_permission_profile": "FULL_CONTROL",
        "configured_max_permission_profile": "FULL_CONTROL",
        "policy_error": None,
    }
    exe.write_text("#!/bin/sh\nprintf '%s\\n' '" + json.dumps(facts) + "'\n")
    exe.chmod(0o755)
    return subprocess.run(
        ["sh", "-c", "set -eu\n" + script],
        env={
            "PATH": str(stub) + ":/usr/bin:/bin",
            "service": "yes",
            "install_root": str(tmp_path / "agent"),
            "COMMANDCORE_HELPER_RELEASE_VERSION": "0.9.0-rc7",
        },
        capture_output=True,
        text=True,
        check=True,
    )


def test_healthy_matching_helper_is_not_reinstalled(tmp_path):
    result = _run_status_probe(tmp_path, helper=True, version="0.9.0-rc7")
    assert "already installed and healthy" in result.stdout
    assert "needs preparation" not in result.stdout.lower()


def test_missing_helper_requires_preparation(tmp_path):
    result = _run_status_probe(tmp_path, helper=False, version="0.9.0-rc7")
    assert "Helper needs preparation" in result.stdout


def test_mismatched_helper_version_is_not_mistaken_for_healthy(tmp_path):
    result = _run_status_probe(tmp_path, helper=True, version="0.9.0-rc6")
    assert "Helper needs preparation" in result.stdout
