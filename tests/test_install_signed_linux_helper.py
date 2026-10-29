"""The root helper setup must fail closed before running any privileged code."""

import importlib.util
from pathlib import Path

import pytest

module_path = (
    Path(__file__).resolve().parents[1] / "scripts/install_signed_linux_helper.py"
)
spec = importlib.util.spec_from_file_location(
    "install_signed_linux_helper", module_path
)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def test_invalid_release_rejected_before_signature_processing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        setup,
        "verify_signed_wheels",
        lambda *a, **kw: pytest.fail("untrusted release reached signature checker"),
    )
    for version in ("", "latest", "../1.0.0", "0.9.0;sh", "0.9.0-rc"):
        with pytest.raises(ValueError, match="invalid signed helper"):
            setup.validate_assets(
                tmp_path / "manifest",
                tmp_path / "bundle",
                tmp_path,
                "key",
                version,
                "x86_64",
            )


def test_nonroot_install_refused_without_touching_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="local Linux administrator"):
        setup.install(
            tmp_path / "manifest",
            tmp_path / "bundle",
            tmp_path,
            "key",
            "0.9.0-rc7",
            "x86_64",
            "netti",
        )


def test_helper_root_rejects_symlink_and_writable_dir(tmp_path, monkeypatch):
    # Linux privileged setup uses a root-only directory, never a
    # user-writable path or symlink.
    target = tmp_path / "helper"
    target.symlink_to(tmp_path)
    with pytest.raises(PermissionError, match="unsafe root"):
        setup._root_dir(target)


def test_signed_bundle_must_match_signed_wheelhouse(monkeypatch, tmp_path):
    wheel = tmp_path / "commandcore_agent-0.9.0rc7-py3-none-any.whl"
    wheel.write_bytes(b"legitimate signed wheel fixture")
    monkeypatch.setattr(
        setup,
        "verify_signed_wheels",
        lambda *a, **k: {
            "version": "0.9.0-rc7",
            "helper_sha256": "a" * 64,
        },
    )
    monkeypatch.setattr(
        setup,
        "inspect_bundle",
        lambda *a, **k: {
            "version": "0.9.0-rc7",
            "wheel_name": wheel.name,
            "wheel_sha256": "b" * 64,
        },
    )
    monkeypatch.setattr(
        setup,
        "verify_dependencies",
        lambda *a, **k: {
            "wheel_count": 1,
        },
    )
    with pytest.raises(ValueError, match="differs from signed wheelhouse"):
        setup.validate_assets(
            tmp_path / "manifest",
            tmp_path / "bundle",
            tmp_path,
            "key",
            "0.9.0-rc7",
            "x86_64",
        )


def test_signed_version_mismatch_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(
        setup,
        "verify_signed_wheels",
        lambda *a, **k: {
            "version": "0.9.0-rc8",
            "helper_sha256": "a" * 64,
        },
    )
    monkeypatch.setattr(
        setup,
        "inspect_bundle",
        lambda *a, **k: {
            "version": "0.9.0-rc7",
        },
    )
    monkeypatch.setattr(
        setup,
        "verify_dependencies",
        lambda *a, **k: {
            "wheel_count": 1,
        },
    )
    with pytest.raises(ValueError, match="release version"):
        setup.validate_assets(
            tmp_path / "manifest",
            tmp_path / "bundle",
            tmp_path,
            "key",
            "0.9.0-rc7",
            "x86_64",
        )


def test_offline_venv_uses_final_path_and_never_reenrolls(monkeypatch, tmp_path):
    from types import SimpleNamespace

    root = tmp_path / "opt" / "commandcore-agent" / "helper"
    root.parent.mkdir(parents=True)
    monkeypatch.setattr(setup, "ROOT", root)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=1001, pw_dir=str(tmp_path)),
    )
    monkeypatch.setattr(
        setup,
        "_load",
        lambda name: SimpleNamespace(
            inspect_agent=lambda home, user: {"existing_agent": True}
        ),
    )
    monkeypatch.setattr(setup, "_root_dir", lambda path: None)
    monkeypatch.setattr(setup, "_approval", lambda version, username: None)
    monkeypatch.setattr(
        setup,
        "validate_assets",
        lambda *a: {
            "version": "0.9.0-rc7",
            "architecture": "x86_64",
            "helper_digest": "a" * 64,
            "wheel_count": 1,
        },
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    bundle = tmp_path / "helper.tar.gz"
    bundle.write_bytes(b"archive")
    wheels = tmp_path / "wheelhouse"
    wheels.mkdir()
    (wheels / "commandcore_agent-0.9.0rc7-py3-none-any.whl").write_bytes(b"wheel")
    (wheels / "pip-25.3-py3-none-any.whl").write_bytes(b"signed pip fixture")
    commands = []

    def run(argv, **kwargs):
        commands.append(list(map(str, argv)))
        if argv[1:3] == ["-m", "venv"]:
            target = Path(argv[-1])
            (target / "bin").mkdir(parents=True)
            (target / "bin/python").write_text("python")
        if argv[1:4] == ["-m", "pip", "install"]:
            (root / "venv/bin/commandcore-helper").write_text("helper")
            (root / "venv/bin/commandcore-agent").write_text("agent")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    outcome = setup.install(
        manifest, bundle, wheels, "trusted", "0.9.0-rc7", "x86_64", "netti"
    )
    assert outcome["agent_reenrolled"] is False
    assert any(str(root / "venv") in cmd for cmd in commands)
    assert not (root / "venv").is_symlink()
    assert all("enroll" not in cmd for cmd in commands)


def test_offline_install_failure_removes_partial_helper_only(monkeypatch, tmp_path):
    import subprocess
    from types import SimpleNamespace

    root = tmp_path / "opt" / "commandcore-agent" / "helper"
    root.parent.mkdir(parents=True)
    monkeypatch.setattr(setup, "ROOT", root)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=1001, pw_dir=str(tmp_path)),
    )
    monkeypatch.setattr(
        setup,
        "_load",
        lambda name: SimpleNamespace(
            inspect_agent=lambda home, user: {"existing_agent": True}
        ),
    )
    monkeypatch.setattr(setup, "_root_dir", lambda path: None)
    monkeypatch.setattr(setup, "_approval", lambda version, username: None)
    monkeypatch.setattr(setup, "validate_assets", lambda *a: {"version": "0.9.0-rc7"})
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    bundle = tmp_path / "bundle.tar.gz"
    bundle.write_bytes(b"archive")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / "commandcore_agent-0.9.0rc7-py3-none-any.whl").write_bytes(b"wheel")
    (wheels / "pip-25.3-py3-none-any.whl").write_bytes(b"signed pip fixture")

    def failed(argv, **kwargs):
        if argv[1:3] == ["-m", "venv"]:
            (root / "venv/bin").mkdir(parents=True)
            return SimpleNamespace(returncode=0)
        raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(setup.subprocess, "run", failed)
    with pytest.raises(subprocess.CalledProcessError):
        setup.install(
            manifest, bundle, wheels, "trusted", "0.9.0-rc7", "x86_64", "netti"
        )
    assert not (root / "venv").exists()


def test_source_symlink_rejected_by_descriptor_copy(tmp_path):
    payload = tmp_path / "payload"
    payload.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(payload.name)
    with pytest.raises(OSError):
        setup._copy_verified(link, tmp_path / "copy")


def test_descriptor_copy_rejects_oversized_asset(tmp_path):
    payload = tmp_path / "payload"
    payload.write_bytes(b"abcdef")
    with pytest.raises(ValueError, match="size"):
        setup._copy_verified(payload, tmp_path / "copy", 5)


def test_missing_user_agent_blocks_root_helper_setup(monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda _: SimpleNamespace(pw_uid=1001, pw_dir=str(tmp_path)),
    )

    def invalid_agent(name):
        if name == "helper_identity_guard":
            return SimpleNamespace(
                inspect_agent=lambda *_: (_ for _ in ()).throw(
                    ValueError("existing user Agent not found")
                )
            )
        pytest.fail("unexpected helper module")

    monkeypatch.setattr(setup, "_load", invalid_agent)
    with pytest.raises(ValueError, match="existing user Agent not found"):
        setup.install(
            tmp_path / "manifest.json",
            tmp_path / "bundle.tar.gz",
            tmp_path / "wheels",
            "key",
            "0.9.0-rc7",
            "x86_64",
            "netti",
        )


def test_requires_signed_pip_wheel(tmp_path):
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    (wheelhouse / "commandcore_agent-0.9.0rc7-py3-none-any.whl").write_bytes(
        b"candidate"
    )
    with pytest.raises(
        ValueError, match="signed wheelhouse must contain exactly one pip"
    ):
        setup._signed_pip_wheel(wheelhouse)
    (wheelhouse / "pip-25.3-py3-none-any.whl").write_bytes(b"pip")
    assert setup._signed_pip_wheel(wheelhouse).name.startswith("pip-")
    (wheelhouse / "pip-24.0-py3-none-any.whl").write_bytes(b"pip")
    with pytest.raises(ValueError, match="exactly one pip"):
        setup._signed_pip_wheel(wheelhouse)


def test_helper_admin_approval_works_with_unseekable_tty(monkeypatch):
    response = iter(b"ENABLE FULL_CONTROL\n")
    written = []
    monkeypatch.setattr(setup.os, "open", lambda *a: 70)
    monkeypatch.setattr(
        setup.os, "write", lambda fd, msg: written.append(msg) or len(msg)
    )
    monkeypatch.setattr(setup.os, "read", lambda fd, count: bytes([next(response)]))
    monkeypatch.setattr(setup.os, "close", lambda fd: None)
    setup._approval("0.9.0-rc7", "netti")
    assert b"ENABLE FULL_CONTROL" in b"".join(written)


def test_helper_admin_approval_does_not_accept_other_text(monkeypatch):
    response = iter(b"NO\n")
    monkeypatch.setattr(setup.os, "open", lambda *a: 70)
    monkeypatch.setattr(setup.os, "write", lambda fd, msg: len(msg))
    monkeypatch.setattr(setup.os, "read", lambda fd, count: bytes([next(response)]))
    monkeypatch.setattr(setup.os, "close", lambda fd: None)
    with pytest.raises(PermissionError, match="approval declined"):
        setup._approval("0.9.0-rc7", "netti")
