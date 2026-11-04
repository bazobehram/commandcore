"""Offline release review handoff tests; test builds are never signed or published."""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import package_unsigned_native_candidate as candidate  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "prepare_linux_release_review", ROOT / "scripts/prepare_linux_release_review.py"
)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SOURCE = "a" * 40
VERSION = "0.9.0-rc9"
ORIGIN = "https://commandcore.example.com"


def fixtures(tmp_path, monkeypatch):
    monkeypatch.setattr(candidate, "glibc_max_required", lambda _: (2, 34))
    lock = tmp_path / "Cargo.lock"
    lock.write_text("locked dependency fixture")
    result = {}
    for arch, machine in (("x86_64", 62), ("arm64", 183)):
        elf = bytearray(256)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", elf, 16, 3)
        struct.pack_into("<H", elf, 18, machine)
        binary = tmp_path / f"build-{arch}"
        binary.write_bytes(elf)
        folder = tmp_path / f"candidate-{arch}"
        candidate.prepare(
            binary,
            folder,
            SOURCE,
            "0.9.0-rc7",
            lock,
            "rustc fixture",
            "cargo fixture",
            arch,
        )
        result[arch] = folder
    return result


def test_dual_architecture_unsigned_review_manifest(tmp_path, monkeypatch):
    folders = fixtures(tmp_path, monkeypatch)
    output = tmp_path / "review.json"
    manifest = module.prepare(folders, SOURCE, VERSION, ORIGIN, output)
    assert manifest["version"] == VERSION
    assert len(manifest["artifacts"]) == 2
    assert {a["architecture"] for a in manifest["artifacts"]} == {"x86_64", "arm64"}
    assert all(
        a["url"].startswith(f"{ORIGIN}/releases/agent/{VERSION}/")
        for a in manifest["artifacts"]
    )
    assert "signature" not in manifest
    assert "signing_key_id" not in manifest
    assert json.loads(output.read_text()) == manifest


def test_reject_wrong_source_without_output(tmp_path, monkeypatch):
    folders = fixtures(tmp_path, monkeypatch)
    output = tmp_path / "review.json"
    with pytest.raises(ValueError):
        module.prepare(folders, "b" * 40, VERSION, ORIGIN, output)
    assert not output.exists()


def test_reject_tampered_candidate_without_output(tmp_path, monkeypatch):
    folders = fixtures(tmp_path, monkeypatch)
    (folders["arm64"] / "SHA256SUMS.txt").write_text("tampered")
    output = tmp_path / "review.json"
    with pytest.raises(ValueError):
        module.prepare(folders, SOURCE, VERSION, ORIGIN, output)
    assert not output.exists()


@pytest.mark.parametrize(
    "origin",
    [
        "http://commandcore.example.com",
        "https://other.example.com/release",
        "https://u:p@commandcore.example.com",
        "https://commandcore.example.com:8443",
    ],
)
def test_invalid_origin_rejected(tmp_path, monkeypatch, origin):
    folders = fixtures(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="invalid_release_origin"):
        module.prepare(folders, SOURCE, VERSION, origin, tmp_path / "review.json")


def test_refuse_overwrite_and_partial_architecture(tmp_path, monkeypatch):
    folders = fixtures(tmp_path, monkeypatch)
    output = tmp_path / "review.json"
    output.write_text("existing")
    with pytest.raises(ValueError, match="output_already_exists"):
        module.prepare(folders, SOURCE, VERSION, ORIGIN, output)
    with pytest.raises(ValueError, match="both_linux_architectures_required"):
        module.prepare(
            {"x86_64": folders["x86_64"]},
            SOURCE,
            VERSION,
            ORIGIN,
            tmp_path / "new.json",
        )
