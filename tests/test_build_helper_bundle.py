import importlib.util
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "helper_bundle",
    Path(__file__).resolve().parents[1] / "scripts/build_helper_bundle.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def wheel_fixture(tmp_path, *, helper=True):
    path = tmp_path / "commandcore_agent-0.9.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "commandcore_agent-0.9.0.dist-info/entry_points.txt",
            "[console_scripts]\n"
            + (
                "commandcore-helper=commandcore_agent.privileged_helper:main\n"
                if helper
                else ""
            ),
        )
    return path


def test_bundle_is_unsigned_and_contains_exact_wheel(tmp_path):
    wheel = wheel_fixture(tmp_path)
    output = tmp_path / "helper.tar.gz"
    metadata = module.build(wheel, output, version="0.9.0-rc7")
    assert metadata["unsigned"] is True
    with tarfile.open(output, "r:gz") as archive:
        assert archive.getnames() == ["metadata.json", wheel.name]
        assert archive.extractfile(wheel.name).read() == wheel.read_bytes()
        assert json.load(archive.extractfile("metadata.json")) == metadata
    with pytest.raises(FileExistsError):
        module.build(wheel, output, version="0.9.0-rc7")


def test_missing_helper_entrypoint_rejected(tmp_path):
    wheel = wheel_fixture(tmp_path, helper=False)
    with pytest.raises(ValueError, match="entry point"):
        module.build(wheel, tmp_path / "out.tar.gz", version="0.9.0")


def test_symlink_and_traversal_rejected(tmp_path):
    wheel = wheel_fixture(tmp_path)
    alias = tmp_path / "commandcore_agent-link.whl"
    alias.symlink_to(wheel)
    with pytest.raises(ValueError):
        module.build(alias, tmp_path / "out.tar.gz", version="0.9.0")
    wheel.unlink()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../bad", "unsafe")
        archive.writestr(
            "commandcore_agent-0.9.0.dist-info/entry_points.txt",
            "commandcore-helper=x:y",
        )
    with pytest.raises(ValueError, match="unsafe"):
        module.build(wheel, tmp_path / "out.tar.gz", version="0.9.0")


def test_repeated_builds_identical(tmp_path):
    wheel = wheel_fixture(tmp_path)
    first, second = tmp_path / "one.tar.gz", tmp_path / "two.tar.gz"
    module.build(wheel, first, version="0.9.0-rc7")
    module.build(wheel, second, version="0.9.0-rc7")
    assert first.read_bytes() == second.read_bytes()
