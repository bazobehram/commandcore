import importlib.util
from pathlib import Path

import pytest

p = Path(__file__).resolve().parents[1] / "scripts/helper_runtime_transaction.py"
spec = importlib.util.spec_from_file_location("helper_transaction", p)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_new_release_read_only(tmp_path):
    root = tmp_path / "helper"
    root.mkdir()
    if root.stat().st_uid != 0:
        pytest.skip("root-owned staging test requires root; separate CI root test")
    result = module.stage_layout(root, "0.9.0-rc8")
    assert result["previous"] is None
    assert result["network_agent_mutation"] is False
    assert not (root / "releases").exists()


def test_traversal_rejected(tmp_path):
    root = tmp_path / "helper"
    root.mkdir()
    if root.stat().st_uid != 0:
        pytest.skip("requires root")
    with pytest.raises(ValueError):
        module.stage_layout(root, "../agent")


def test_release_collision_rejected(tmp_path):
    root = tmp_path / "helper"
    (root / "releases" / "same").mkdir(parents=True)
    if root.stat().st_uid != 0:
        pytest.skip("requires root")
    with pytest.raises(FileExistsError):
        module.stage_layout(root, "same")


def test_previous_escape_rejected():
    with pytest.raises(ValueError):
        module.rollback_target({"previous": "../../agent"})


def test_untrusted_directory_refused(tmp_path):
    root = tmp_path / "helper"
    root.mkdir()
    root.chmod(0o777)
    with pytest.raises(PermissionError):
        module.stage_layout(root, "rc8")


@pytest.mark.parametrize(
    "target",
    [
        "releases/",
        "releases/.",
        "releases/..",
        "releases/../agent",
        "releases/bad\\name",
        "releases/a/b",
        "releases/" + "x" * 81,
    ],
)
def test_rollback_target_rejects_invalid_names(target):
    with pytest.raises(ValueError):
        module.rollback_target({"previous": target})


def test_valid_rollback_target_preserved():
    assert (
        module.rollback_target({"previous": "releases/0.9.0-rc7"})
        == "releases/0.9.0-rc7"
    )


@pytest.mark.parametrize(
    "target", ["releases/..", "releases/.", "releases/", "releases/bad/name"]
)
def test_current_pointer_rejects_invalid_rollback_target(tmp_path, target):
    root = tmp_path / "helper"
    root.mkdir()
    (root / "current").symlink_to(target)
    if root.stat().st_uid != 0:
        pytest.skip("requires root")
    with pytest.raises(ValueError, match="current helper pointer"):
        module.stage_layout(root, "new-release")
