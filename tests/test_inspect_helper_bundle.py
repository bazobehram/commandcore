import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "helper_inspect",
    Path(__file__).resolve().parents[1] / "scripts/inspect_helper_bundle.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture_bundle(tmp_path, *, evil=False):
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr(
            "../bad" if evil else "commandcore_agent-0.9.dist-info/entry_points.txt",
            "commandcore-helper=commandcore_agent.privileged_helper:main",
        )
    payload = wheel.getvalue()
    import hashlib

    meta = dict(
        schema_version=1,
        product="commandcore-privileged-helper-candidate",
        unsigned=True,
        wheel_name="commandcore_agent-0.9-py3-none-any.whl",
        wheel_size=len(payload),
        wheel_sha256=hashlib.sha256(payload).hexdigest(),
        version="0.9",
    )
    path = tmp_path / "helper.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in (
            ("metadata.json", json.dumps(meta).encode()),
            (meta["wheel_name"], payload),
        ):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    return path


def test_well_formed_bundle(tmp_path):
    assert module.inspect_bundle(fixture_bundle(tmp_path))["version"] == "0.9"


def test_wheel_traversal_rejected(tmp_path):
    with pytest.raises(ValueError, match="unsafe"):
        module.inspect_bundle(fixture_bundle(tmp_path, evil=True))


def test_extra_tar_entry_rejected(tmp_path):
    path = fixture_bundle(tmp_path)
    with tarfile.open(path, "r:gz") as archive:
        parts = [(m.name, archive.extractfile(m).read()) for m in archive]
    path.unlink()
    with tarfile.open(path, "w:gz") as tar:
        for name, data in parts + [("unexpected", b"")]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    with pytest.raises((ValueError, tarfile.ReadError)):
        module.inspect_bundle(path)


def test_modified_bytes_rejected(tmp_path):
    path = fixture_bundle(tmp_path)
    with tarfile.open(path, "r:gz") as archive:
        parts = [(m.name, archive.extractfile(m).read()) for m in archive]
    path.unlink()
    with tarfile.open(path, "w:gz") as archive:
        for name, data in parts:
            if name.endswith(".whl"):
                data += b"modified"
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    with pytest.raises(ValueError, match="size"):
        module.inspect_bundle(path)
