import hashlib
import json
import zipfile

import pytest

from scripts.package_workspace_release import package

COMMIT = "a" * 40


def fixture(tmp_path):
    root = tmp_path / "browser"
    root.mkdir()
    (root / "index.html").write_text('<script src="main-ABC.js"></script>')
    (root / "main-ABC.js").write_text("console.log(1)")
    (root / "brand").mkdir()
    (root / "brand" / "icon.png").write_bytes(b"fixture")
    return root


def test_repeatable_archive_and_manifest(tmp_path):
    root = fixture(tmp_path)
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    digest = package(root, a, COMMIT)
    assert package(root, b, COMMIT) == digest
    assert a.read_bytes() == b.read_bytes()
    with zipfile.ZipFile(a) as archive:
        manifest = json.loads(archive.read("WORKSPACE_RELEASE.json"))
        assert manifest["source_commit"] == COMMIT
        assert set(archive.namelist()) == {"WORKSPACE_RELEASE.json"} | {
            "browser/" + name for name in manifest["files"]
        }
        for name, digest in manifest["files"].items():
            assert hashlib.sha256(archive.read("browser/" + name)).hexdigest() == digest


@pytest.mark.parametrize("bad", ["symlink", "source_map", "hidden", "missing"])
def test_reject_unsafe_or_incomplete_build(tmp_path, bad):
    root = fixture(tmp_path)
    if bad == "symlink":
        (root / "foreign.js").symlink_to(tmp_path / "missing")
    elif bad == "source_map":
        (root / "main-ABC.js.map").write_text("{}")
    elif bad == "hidden":
        (root / ".hidden").write_text("fixture")
    else:
        (root / "main-ABC.js").unlink()
    with pytest.raises(ValueError):
        package(root, tmp_path / "out.zip", COMMIT)
    assert not (tmp_path / "out.zip").exists()


def test_invalid_commit_and_output_inside_root(tmp_path):
    root = fixture(tmp_path)
    with pytest.raises(ValueError):
        package(root, tmp_path / "out.zip", "main")
    with pytest.raises(ValueError):
        package(root, root / "out.zip", COMMIT)
