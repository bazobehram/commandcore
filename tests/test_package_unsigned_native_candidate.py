"""Offline test matrix for the unsigned source-pinned Linux review candidate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "package_unsigned_native_candidate",
    ROOT / "scripts/package_unsigned_native_candidate.py",
)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
SHA = "a" * 40
VERSION = "0.9.0-rc7"


def elf_fixture() -> bytes:
    raw = bytearray(256)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", raw, 16, 3)
    struct.pack_into("<H", raw, 18, 62)
    return bytes(raw)


def setup_candidate(tmp_path, monkeypatch):
    binary = tmp_path / "native-agent"
    binary.write_bytes(elf_fixture())
    lock = tmp_path / "Cargo.lock"
    lock.write_text("locked dependency fixture\n")
    monkeypatch.setattr(MODULE, "glibc_max_required", lambda _: (2, 35))
    output = tmp_path / "candidate"
    MODULE.prepare(binary, output, SHA, VERSION, lock, "rustc test", "cargo test")
    return output


def test_source_pinned_unsigned_candidate_round_trip(tmp_path, monkeypatch):
    output = setup_candidate(tmp_path, monkeypatch)
    MODULE.verify(output, SHA)
    metadata = json.loads((output / MODULE.MANIFEST_NAME).read_text())
    assert metadata["source_commit"] == SHA
    assert metadata["signatures"] == "NONE"
    assert metadata["release_status"] == "UNSIGNED_NOT_APPROVED"
    assert metadata["sha256"] == hashlib.sha256(elf_fixture()).hexdigest()
    assert metadata["max_required_glibc"] == "2.35"


@pytest.mark.parametrize("part", ["binary", "source", "hashes", "metadata"])
def test_modified_candidate_fails_closed(tmp_path, monkeypatch, part):
    output = setup_candidate(tmp_path, monkeypatch)
    if part == "binary":
        path = output / MODULE.BINARY_NAME
        raw = path.read_bytes()
        path.write_bytes(raw[:64] + b"altered" + raw[71:])
    elif part == "source":
        (output / MODULE.SOURCE_NAME).write_text("b" * 40 + "\n")
    elif part == "hashes":
        (output / MODULE.HASH_NAME).write_text("INVALID")
    else:
        metadata_path = output / MODULE.MANIFEST_NAME
        data = json.loads(metadata_path.read_text())
        data["release_status"] = "APPROVED"
        metadata_path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        MODULE.verify(output, SHA)


def test_candidate_refuses_unexpected_extra_file(tmp_path, monkeypatch):
    output = setup_candidate(tmp_path, monkeypatch)
    (output / "release-private-seed").write_bytes(b"unsafe")
    with pytest.raises(ValueError, match="unexpected_candidate_file"):
        MODULE.verify(output, SHA)


def test_candidate_refuses_existing_output(tmp_path, monkeypatch):
    setup_candidate(tmp_path, monkeypatch)
    binary = tmp_path / "native-agent"
    with pytest.raises(ValueError, match="refuse_existing_output"):
        MODULE.prepare(
            binary,
            tmp_path / "candidate",
            SHA,
            VERSION,
            tmp_path / "Cargo.lock",
            "rustc fixture",
            "cargo fixture",
        )


def test_candidate_rejects_arm64_and_executable_type(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "glibc_max_required", lambda _: (2, 35))
    binary = tmp_path / "native"
    arm = bytearray(elf_fixture())
    struct.pack_into("<H", arm, 18, 183)
    binary.write_bytes(arm)
    with pytest.raises(ValueError, match="not_linux_expected_architecture_pie_elf"):
        MODULE.prepare(
            binary, tmp_path / "out", SHA, VERSION, tmp_path / "Cargo.lock", "", ""
        )


def test_glibc_runtime_above_supported_minimum_rejected(monkeypatch, tmp_path):
    binary = tmp_path / "native"
    binary.write_bytes(elf_fixture())
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "GLIBC_2.17 GLIBC_2.39", ""
        ),
    )
    with pytest.raises(ValueError, match="glibc_requirement_exceeds_2_36"):
        MODULE.glibc_max_required(binary)


def test_glibc_runtime_below_supported_minimum_passes(monkeypatch, tmp_path):
    binary = tmp_path / "native"
    binary.write_bytes(elf_fixture())
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "GLIBC_2.17 GLIBC_2.35", ""
        ),
    )
    assert MODULE.glibc_max_required(binary) == (2, 35)


def test_source_sha_must_match_reviewed_commit(tmp_path, monkeypatch):
    output = setup_candidate(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="invalid_candidate_metadata"):
        MODULE.verify(output, "b" * 40)


def test_candidate_rechecks_real_glibc_requirement(tmp_path, monkeypatch):
    output = setup_candidate(tmp_path, monkeypatch)
    # A perfectly consistent metadata and checksum bundle can still lie
    # about which glibc versions the binary actually needs.
    monkeypatch.setattr(MODULE, "glibc_max_required", lambda _: (2, 36))
    with pytest.raises(ValueError, match="candidate_glibc_evidence_mismatch"):
        MODULE.verify(output, SHA)


def test_candidate_rejects_binary_requiring_newer_glibc(tmp_path, monkeypatch):
    output = setup_candidate(tmp_path, monkeypatch)
    monkeypatch.setattr(MODULE, "glibc_max_required", lambda _: (2, 39))
    with pytest.raises(ValueError, match="candidate_glibc_evidence_mismatch"):
        MODULE.verify(output, SHA)


@pytest.mark.parametrize("architecture,machine", [("x86_64", 62), ("arm64", 183)])
def test_architecture_pinned_unsigned_candidate(
    tmp_path, monkeypatch, architecture, machine
):
    binary = tmp_path / "agent"
    raw = bytearray(elf_fixture())
    struct.pack_into("<H", raw, 18, machine)
    binary.write_bytes(raw)
    lock = tmp_path / "Cargo.lock"
    lock.write_text("locked fixture")
    monkeypatch.setattr(MODULE, "glibc_max_required", lambda _: (2, 35))
    output = tmp_path / "candidate"
    MODULE.prepare(binary, output, SHA, VERSION, lock, "rustc", "cargo", architecture)
    MODULE.verify(output, SHA, architecture)
    assert (output / MODULE.BINARY_NAMES[architecture]).exists()
    with pytest.raises(ValueError):
        MODULE.verify(output, SHA, "arm64" if architecture == "x86_64" else "x86_64")


def test_arm64_candidate_rejects_wrong_elf_machine(tmp_path, monkeypatch):
    binary = tmp_path / "agent"
    binary.write_bytes(elf_fixture())
    lock = tmp_path / "Cargo.lock"
    lock.write_text("locked fixture")
    monkeypatch.setattr(MODULE, "glibc_max_required", lambda _: (2, 35))
    with pytest.raises(ValueError, match="not_linux_expected_architecture_pie_elf"):
        MODULE.prepare(
            binary, tmp_path / "candidate", SHA, VERSION, lock, "", "", "arm64"
        )


def test_candidate_rejects_unknown_architecture(tmp_path):
    with pytest.raises(ValueError, match="unsupported_candidate_architecture"):
        MODULE.verify(tmp_path, SHA, "mips")


def test_candidate_file_reader_rejects_symlink(tmp_path):
    target = tmp_path / "actual"
    target.write_bytes(b"valid")
    linked = tmp_path / "candidate"
    linked.symlink_to(target)
    with pytest.raises(ValueError, match="candidate_symlink"):
        MODULE.file_bytes(linked, 32)


def test_candidate_file_reader_rejects_fifo(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="candidate_file_type_or_size"):
        MODULE.file_bytes(fifo, 32)


def test_candidate_file_reader_detects_growth_during_read(tmp_path, monkeypatch):
    original = MODULE.os.fdopen
    file = tmp_path / "candidate"
    file.write_bytes(b"expected")

    class GrowingStream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return b"expected-surprise"

    def opened(fd, mode):
        os.close(fd)
        return GrowingStream()

    monkeypatch.setattr(MODULE.os, "fdopen", opened)
    try:
        with pytest.raises(ValueError, match="candidate_file_changed_or_oversized"):
            MODULE.file_bytes(file, 64)
    finally:
        monkeypatch.setattr(MODULE.os, "fdopen", original)


def test_candidate_file_reader_checks_open_fd_not_path_stat(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"different")
    real_open = MODULE.os.open

    def swap_after_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if Path(path) == candidate:
            candidate.unlink()
            candidate.symlink_to(replacement)
        return fd

    monkeypatch.setattr(MODULE.os, "open", swap_after_open)
    assert MODULE.file_bytes(candidate, 100) == b"original"
