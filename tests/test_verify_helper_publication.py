"""Release verification must fail closed before publishing privileged assets."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

source = Path(__file__).resolve().parents[1] / "scripts/verify_helper_publication.py"
spec = importlib.util.spec_from_file_location("helper_publication", source)
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


def layout(tmp_path):
    root = tmp_path / "signed-helper"
    root.mkdir()
    (root / "manifest.signed.json").write_text(
        json.dumps(
            {
                "version": "0.9.0-rc8",
                "python_minor": "3.13",
                "artifacts": [
                    {
                        "filename": "commandcore-helper-linux-x86_64.tar.gz",
                        "platform": "linux",
                        "architecture": "x86_64",
                        "kind": "privileged-helper",
                    }
                ],
            }
        )
    )
    (root / "commandcore-helper-linux-x86_64.tar.gz").write_bytes(
        b"signed candidate fixture"
    )
    wheels = root / "wheels"
    wheels.mkdir()
    (wheels / "commandcore_agent-0.9.0rc8-py3-none-any.whl").write_bytes(
        b"wheel fixture"
    )
    (wheels / "pip-25.3-py3-none-any.whl").write_bytes(b"signed pip fixture")
    return root


def dummy_verifiers(monkeypatch):
    def load(script):
        if script == "verify_signed_helper_wheelhouse":
            return SimpleNamespace(
                verify=lambda *args: {
                    "version": "0.9.0-rc8",
                    "helper_sha256": "a" * 64,
                    "wheel_count": 2,
                }
            )
        if script == "check_helper_offline_dependencies":
            return SimpleNamespace(
                check=lambda *args, **kwargs: {"wheel_count": 2, "complete": True}
            )
        pytest.fail(f"Unexpected verifier: {script}")

    monkeypatch.setattr(publication, "_load", load)


def test_signed_release_includes_every_wheel(monkeypatch, tmp_path):
    root = layout(tmp_path)
    dummy_verifiers(monkeypatch)
    result = publication.verify(root, "trusted", "0.9.0-rc8", "x86_64")
    assert result["verified"]
    assert result["signed_by_external_authority"]
    assert result["root_operation"] is False
    assert len(result["assets"]) == 4
    assert result["assets"][-1].endswith(".whl")


def test_publish_refuses_missing_or_extra_assets(monkeypatch, tmp_path):
    root = layout(tmp_path)
    dummy_verifiers(monkeypatch)
    (root / "unexpected-private-key").write_bytes(b"should never publish")
    with pytest.raises(ValueError, match="unexpected signed helper assets"):
        publication.verify(root, "trusted", "0.9.0-rc8", "x86_64")
    (root / "unexpected-private-key").unlink()
    (root / "wheels" / "pip-25.3-py3-none-any.whl").unlink()
    with pytest.raises(ValueError, match="signed pip bootstrap"):
        publication.verify(root, "trusted", "0.9.0-rc8", "x86_64")


def test_publish_refuses_symlinks(monkeypatch, tmp_path):
    root = layout(tmp_path)
    dummy_verifiers(monkeypatch)
    wheel = next((root / "wheels").iterdir())
    wheel.unlink()
    wheel.symlink_to(root / "manifest.signed.json")
    with pytest.raises(ValueError, match="wheelhouse member"):
        publication.verify(root, "trusted", "0.9.0-rc8", "x86_64")


def test_publish_refuses_arch_version_or_manifest_mismatch(monkeypatch, tmp_path):
    root = layout(tmp_path)
    dummy_verifiers(monkeypatch)
    with pytest.raises(ValueError, match="version mismatch"):
        publication.verify(root, "trusted", "0.9.0-rc9", "x86_64")
    with pytest.raises(ValueError, match="signed helper assets"):
        publication.verify(root, "trusted", "0.9.0-rc8", "arm64")
    doc = json.loads((root / "manifest.signed.json").read_text())
    doc["artifacts"][0]["architecture"] = "arm64"
    (root / "manifest.signed.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="target mismatch"):
        publication.verify(root, "trusted", "0.9.0-rc8", "x86_64")


def test_arm64_helper_release_is_architecture_scoped(monkeypatch, tmp_path):
    root = layout(tmp_path)
    dummy_verifiers(monkeypatch)
    old = root / "commandcore-helper-linux-x86_64.tar.gz"
    old.rename(root / "commandcore-helper-linux-arm64.tar.gz")
    doc = json.loads((root / "manifest.signed.json").read_text())
    doc["artifacts"][0]["filename"] = "commandcore-helper-linux-arm64.tar.gz"
    doc["artifacts"][0]["architecture"] = "arm64"
    (root / "manifest.signed.json").write_text(json.dumps(doc))
    result = publication.verify(root, "trusted", "0.9.0-rc8", "arm64")
    assert result["architecture"] == "arm64"
    assert any("linux-arm64" in path for path in result["assets"])


def test_signed_python_runtime_target_is_enforced(monkeypatch, tmp_path):
    root = layout(tmp_path)
    dummy_verifiers(monkeypatch)
    with pytest.raises(ValueError, match="Python version mismatch"):
        publication.verify(root, "trusted", "0.9.0-rc8", "x86_64", "3.12")
    with pytest.raises(ValueError, match="invalid helper Python"):
        publication.verify(root, "trusted", "0.9.0-rc8", "x86_64", "3.14")
