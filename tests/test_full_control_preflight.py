from pathlib import Path
import os
import runpy

inspect = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "full_control_preflight.py")
)["inspect"]


def test_absent_helper_fails_closed(tmp_path):
    result = inspect(tmp_path / "policy", tmp_path / "helper", tmp_path / "unit")
    assert result["ready_for_local_approval"] is False
    assert set(result["helper_files"].values()) == {"missing"}


def test_untrusted_helper_fails_closed(tmp_path):
    policy, helper, unit = (tmp_path / n for n in ("policy", "helper", "unit"))
    for path in (policy, helper, unit):
        path.write_text("placeholder")
    helper.chmod(0o777)
    result = inspect(policy, helper, unit)
    assert result["helper_files"]["helper"] == "untrusted"
    assert result["ready_for_local_approval"] is False


def test_symlink_fails_closed(tmp_path):
    target = tmp_path / "target"
    target.write_text("placeholder")
    link = tmp_path / "helper"
    link.symlink_to(target)
    result = inspect(tmp_path / "policy", link, tmp_path / "unit")
    assert result["helper_files"]["helper"] == "untrusted"
