from __future__ import annotations

import hashlib
import importlib.util
import zipfile
from pathlib import Path


def verifier():
    path = Path(__file__).resolve().parents[1] / "scripts/verify_release_artifact.py"
    spec = importlib.util.spec_from_file_location("verify_release_artifact", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixtures(tmp_path):
    contract = b'{"tools":[]}'
    archive = tmp_path / "commandcore-release.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("commandcore-release/docs/mcp-tool-contract.json", contract)
    checksum = tmp_path / "commandcore-release.sha256"
    checksum.write_text(
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  commandcore-release.zip\n"
    )
    manifest = tmp_path / "release-manifest.txt"
    sha = "a" * 40
    manifest.write_text(
        f"git_sha={sha}\nmcp_contract_sha256={hashlib.sha256(contract).hexdigest()}\n"
    )
    return archive, checksum, manifest, sha


def test_valid_artifact(tmp_path):
    verifier().verify(*fixtures(tmp_path))


def test_wrong_commit_rejected(tmp_path):
    a, c, m, _ = fixtures(tmp_path)
    try:
        verifier().verify(a, c, m, "b" * 40)
    except ValueError as exc:
        assert "Git SHA mismatch" in str(exc)
    else:
        raise AssertionError("wrong SHA accepted")


def test_mutated_zip_rejected(tmp_path):
    a, c, m, sha = fixtures(tmp_path)
    a.write_bytes(a.read_bytes() + b"tamper")
    try:
        verifier().verify(a, c, m, sha)
    except ValueError as exc:
        assert "digest mismatch" in str(exc)
    else:
        raise AssertionError("mutated archive accepted")


def test_wrong_contract_rejected(tmp_path):
    a, c, m, sha = fixtures(tmp_path)
    m.write_text(f"git_sha={sha}\nmcp_contract_sha256={'0' * 64}\n")
    try:
        verifier().verify(a, c, m, sha)
    except ValueError as exc:
        assert "contract digest mismatch" in str(exc)
    else:
        raise AssertionError("wrong contract accepted")
