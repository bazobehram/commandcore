import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / "scripts/helper_install_preflight.py"
spec = importlib.util.spec_from_file_location("helper_install_preflight", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_missing_signed_bundle_fails_closed(tmp_path):
    with pytest.raises((ValueError, FileNotFoundError)):
        module.verify_inputs(
            tmp_path / "missing.json",
            tmp_path / "missing.tar.gz",
            "invalid",
            architecture="x86_64",
            expected_version="0.9.0-rc7",
        )


def test_expected_version_required(tmp_path):
    with pytest.raises(ValueError, match="version"):
        module.verify_inputs(
            tmp_path / "missing.json",
            tmp_path / "missing.tar.gz",
            "invalid",
            architecture="x86_64",
            expected_version="",
        )


def test_bad_signature_fails_closed(tmp_path):
    manifest = tmp_path / "manifest.json"
    artifact = tmp_path / "helper.tar.gz"
    manifest.write_text('{"signature":"broken"}')
    artifact.write_bytes(b"not a helper")
    with pytest.raises(Exception):
        module.verify_inputs(
            manifest,
            artifact,
            "invalid",
            architecture="x86_64",
            expected_version="0.9.0-rc7",
        )
