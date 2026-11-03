"""Offline acceptance bundle regression tests; no VM or production access."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from zipfile import ZipFile

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "package_windows_vm_acceptance",
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "package_windows_vm_acceptance.py",
)
assert _SPEC is not None and _SPEC.loader is not None
bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bundle)

SHA = "a" * 40


def test_bundle_is_reproducible_and_verifies(tmp_path):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    bundle.build(first, SHA)
    bundle.build(second, SHA)
    assert first.read_bytes() == second.read_bytes()
    bundle.verify(first)
    with ZipFile(first) as archive:
        assert set(archive.namelist()) == set(bundle.FILES) | {
            bundle.SOURCE_NAME,
            bundle.HASHES_NAME,
        }
        assert archive.read(bundle.SOURCE_NAME) == (SHA + "\n").encode()


def test_modified_script_is_rejected(tmp_path):
    original = tmp_path / "original.zip"
    altered = tmp_path / "altered.zip"
    bundle.build(original, SHA)
    with ZipFile(original) as source, ZipFile(altered, "w") as dest:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "scripts/windows_interactive_logon_action.ps1":
                data += b"\n# altered\n"
            dest.writestr(info, data)
    with pytest.raises(ValueError, match="hash mismatch"):
        bundle.verify(altered)


def test_extra_file_is_rejected(tmp_path):
    original = tmp_path / "original.zip"
    altered = tmp_path / "extra.zip"
    bundle.build(original, SHA)
    with ZipFile(original) as source, ZipFile(altered, "w") as dest:
        for info in source.infolist():
            dest.writestr(info, source.read(info))
        info, payload = bundle._zip_entry("agent.json", b"secret")
        dest.writestr(info, payload)
    with pytest.raises(ValueError, match="contains extras"):
        bundle.verify(altered)


def test_invalid_commit_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="commit SHA"):
        bundle.build(tmp_path / "bad.zip", "main")


def test_duplicate_name_is_rejected(tmp_path):
    original = tmp_path / "original.zip"
    altered = tmp_path / "duplicate.zip"
    bundle.build(original, SHA)
    with ZipFile(original) as source, ZipFile(altered, "w") as dest:
        for info in source.infolist():
            dest.writestr(info, source.read(info))
        info, payload = bundle._zip_entry(bundle.SOURCE_NAME, (SHA + "\n").encode())
        # zipfile permits duplicates; the verifier must not.
        dest.writestr(info, payload)
    with pytest.raises(ValueError, match="duplicates"):
        bundle.verify(altered)
