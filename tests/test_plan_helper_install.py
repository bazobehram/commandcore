import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "plan_helper_install",
    Path(__file__).resolve().parents[1] / "scripts/plan_helper_install.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_noncanonical_target_rejected_without_mutation(tmp_path):
    with pytest.raises(ValueError, match="noncanonical"):
        module.plan(
            tmp_path / "missing",
            tmp_path / "missing",
            "invalid",
            version="0.9.0-rc7",
            arch="x86_64",
            home=tmp_path,
            username="ortamzeka",
            install_root=tmp_path / "user-controlled",
        )


def test_missing_agent_is_refused(tmp_path):
    with pytest.raises(ValueError):
        module.plan(
            tmp_path / "missing",
            tmp_path / "missing",
            "invalid",
            version="0.9.0-rc7",
            arch="x86_64",
            home=tmp_path,
            username="ortamzeka",
            install_root=Path("/opt/commandcore-agent/helper"),
        )


def test_missing_signed_release_is_refused(tmp_path):
    home = tmp_path / "ortamzeka"
    (home / ".local/bin").mkdir(parents=True)
    (home / ".local/share/commandcore-agent/releases").mkdir(parents=True)
    (home / ".local/bin/commandcore-agent").write_text("existing")
    with pytest.raises((ValueError, FileNotFoundError)):
        module.plan(
            tmp_path / "missing",
            tmp_path / "missing",
            "invalid",
            version="0.9.0-rc7",
            arch="x86_64",
            home=home,
            username="ortamzeka",
            install_root=Path("/opt/commandcore-agent/helper"),
        )
    assert (home / ".local/bin/commandcore-agent").read_text() == "existing"
