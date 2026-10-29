"""Offline signer tests use ephemeral disposable keys, never real signing material."""

import importlib.util
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load(script):
    path = Path(__file__).resolve().parents[1] / "scripts" / (script + ".py")
    spec = importlib.util.spec_from_file_location(script, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


signer = load("sign_helper_release_offline")
verifier = load("verify_signed_helper_wheelhouse")


def assets(tmp_path):
    wheels = tmp_path / "wheelhouse"
    wheels.mkdir()
    wheel = wheels / "commandcore_agent-0.9.0rc7-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "commandcore_agent-0.9.0rc7.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: commandcore-agent\nVersion: 0.9.0rc7\n",
        )
        archive.writestr(
            "commandcore_agent-0.9.0rc7.dist-info/entry_points.txt",
            "[console_scripts]\ncommandcore-helper=commandcore_agent.privileged_helper:main\n",
        )
    pip_wheel = wheels / "pip-25.3-py3-none-any.whl"
    with zipfile.ZipFile(pip_wheel, "w") as archive:
        archive.writestr(
            "pip-25.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: pip\nVersion: 25.3\n",
        )
    bundle = tmp_path / "commandcore-helper-linux-x86_64.tar.gz"
    load("build_helper_bundle").build(wheel, bundle, version="0.9.0-rc7")
    private = Ed25519PrivateKey.generate()
    key_file = tmp_path / "private.pem"
    key_file.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    return key_file, bundle, wheels


def test_offline_signer_produces_publisher_verifiable_assets(tmp_path):
    key, bundle, wheels = assets(tmp_path)
    root = tmp_path / "signed-release"
    result = signer.sign_to_directory(
        key, bundle, wheels, root, "0.9.0-rc7", "x86_64", "3.13", "a" * 40
    )
    assert result["signed"] and result["device_installation"] is False
    verified = verifier.verify(
        root / "manifest.signed.json",
        root / "commandcore-helper-linux-x86_64.tar.gz",
        root / "wheels",
        result["public_key_b64"],
        "x86_64",
    )
    assert verified["result"] == "SIGNED_OFFLINE_WHEELHOUSE_VERIFIED"
    assert verified["wheel_count"] == 2
    with pytest.raises(FileExistsError):
        signer.sign_to_directory(
            key, bundle, wheels, root, "0.9.0-rc7", "x86_64", "3.13", "a" * 40
        )


def test_offline_signer_rejects_unsafe_key(tmp_path):
    key, bundle, wheels = assets(tmp_path)
    key.chmod(0o644)
    with pytest.raises(PermissionError, match="mode 0600"):
        signer.sign_to_directory(
            key,
            bundle,
            wheels,
            tmp_path / "signed",
            "0.9.0-rc7",
            "x86_64",
            "3.13",
            "b" * 40,
        )
    assert not (tmp_path / "signed").exists()
    key.chmod(0o600)
    link = tmp_path / "key-link"
    link.symlink_to(key)
    with pytest.raises(PermissionError):
        signer.load_private_key(link)


def test_offline_signer_rejects_unverified_inputs(tmp_path):
    key, bundle, wheels = assets(tmp_path)
    with pytest.raises(ValueError, match="source SHA"):
        signer.prepare_manifest(
            bundle, wheels, "0.9.0-rc7", "x86_64", "3.13", "not-a-commit"
        )
    with pytest.raises(ValueError, match="architecture"):
        signer.prepare_manifest(bundle, wheels, "0.9.0-rc7", "arm64", "3.13", "b" * 40)
    link = wheels / "malicious.whl"
    link.symlink_to(next(wheels.iterdir()))
    with pytest.raises(ValueError):
        signer.prepare_manifest(bundle, wheels, "0.9.0-rc7", "x86_64", "3.13", "b" * 40)


def test_offline_signer_tty_prompt_uses_nonseekable_descriptor_io(monkeypatch):
    response = iter(b"SIGN HELPER RELEASE\n")
    written = []
    monkeypatch.setattr(signer.os, "open", lambda *args: 42)
    monkeypatch.setattr(
        signer.os, "write", lambda fd, data: written.append(data) or len(data)
    )
    monkeypatch.setattr(signer.os, "read", lambda fd, size: bytes([next(response)]))
    monkeypatch.setattr(signer.os, "close", lambda fd: None)
    signer.local_approval("0.9.0-rc7", "x86_64", "3.12")
    assert b"SIGN HELPER RELEASE" in b"".join(written)


def test_offline_signer_tty_rejection_fails_closed(monkeypatch):
    response = iter(b"NO\n")
    monkeypatch.setattr(signer.os, "open", lambda *args: 42)
    monkeypatch.setattr(signer.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(signer.os, "read", lambda fd, size: bytes([next(response)]))
    monkeypatch.setattr(signer.os, "close", lambda fd: None)
    with pytest.raises(PermissionError, match="authorization declined"):
        signer.local_approval("0.9.0-rc7", "x86_64", "3.12")
