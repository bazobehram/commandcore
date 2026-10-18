import importlib.util
from pathlib import Path


def gate():
    path = Path(__file__).resolve().parents[1] / "scripts/deployment_topology_gate.py"
    spec = importlib.util.spec_from_file_location("deployment_topology_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_matching_order_passes(tmp_path):
    one = tmp_path / "base.yml"
    two = tmp_path / "overlay.yml"
    one.write_text("services: {}")
    two.write_text("services: {}")
    paths = [str(one), str(two)]
    assert gate().validate(paths, paths) == []


def test_different_overlay_blocks():
    assert gate().validate(["/a", "/b"], ["/a", "/c"])


def test_reordered_overlay_blocks():
    assert gate().validate(["/a", "/b"], ["/b", "/a"])


def test_missing_live_topology_blocks():
    assert gate().validate(["/a"], [])


def test_missing_config_file_blocks():
    assert any(
        "missing or inaccessible" in issue
        for issue in gate().validate(
            ["/nonexistent-commandcore-test-compose.yml"],
            ["/nonexistent-commandcore-test-compose.yml"],
        )
    )


def test_duplicate_overlay_blocks():
    assert gate().validate(["/a", "/a"], ["/a", "/a"])
