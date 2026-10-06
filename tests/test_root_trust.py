import os

import pytest

from commandcore_agent.root_trust import read_root_file

pytestmark = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0, reason="real root ownership gate"
)


def test_root_configuration_rejects_writable_policy_and_symlink(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_bytes(b"{}")
    policy.chmod(0o644)
    assert read_root_file(policy) == b"{}"
    policy.chmod(0o664)
    with pytest.raises(PermissionError):
        read_root_file(policy)
    policy.chmod(0o644)
    link = tmp_path / "linked.json"
    link.symlink_to(policy)
    with pytest.raises(OSError):
        read_root_file(link)


def test_secret_rejects_public_access_and_nonroot_owner(tmp_path):
    secret = tmp_path / "helper.key"
    secret.write_bytes(b"x" * 48)
    secret.chmod(0o640)
    assert read_root_file(secret, secret=True) == b"x" * 48
    secret.chmod(0o644)
    with pytest.raises(PermissionError):
        read_root_file(secret, secret=True)
    secret.chmod(0o640)
    os.chown(secret, 65534, 65534)
    with pytest.raises(PermissionError):
        read_root_file(secret, secret=True)


def test_parent_directory_cannot_be_agent_writable(tmp_path):
    directory = tmp_path / "unsafe"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    policy = directory / "policy.json"
    policy.write_bytes(b"{}")
    with pytest.raises(PermissionError):
        read_root_file(policy)
