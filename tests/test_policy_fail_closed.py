import json
import os

import pytest
from commandcore_agent.local_policy import load_local_policy


@pytest.fixture(autouse=True)
def no_environment_ceiling(monkeypatch):
    monkeypatch.delenv("COMMANDCORE_AGENT_MAX_PERMISSION_PROFILE", raising=False)


def check(path, profile, error=False):
    policy = load_local_policy(str(path))
    assert policy["configured_max_permission_profile"] == profile
    assert bool(policy.get("policy_error")) is error


def test_absent_policy_is_standard(tmp_path):
    check(tmp_path / "missing", "STANDARD")


@pytest.mark.parametrize("profile", ["READ_ONLY", "STANDARD"])
def test_valid_policy(tmp_path, profile):
    path = tmp_path / "policy"
    path.write_text(json.dumps({"configured_max_permission_profile": profile}))
    path.chmod(0o600)
    check(path, profile)


@pytest.mark.parametrize(
    "contents",
    [
        "{",
        "[]",
        "{}",
        '{"configured_max_permission_profile":"invalid"}',
        '{"configured_max_permission_profile":null}',
    ],
)
def test_present_invalid_policy_never_becomes_standard(tmp_path, contents):
    path = tmp_path / "policy"
    path.write_text(contents)
    check(path, "READ_ONLY", True)


def test_unreadable_policy(tmp_path, monkeypatch):
    path = tmp_path / "policy"
    path.write_text('{"configured_max_permission_profile":"READ_ONLY"}')

    def denied(*args, **kwargs):
        raise PermissionError("fixture")

    monkeypatch.setattr(os, "open", denied)
    check(path, "READ_ONLY", True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership")
def test_unsafe_permissions_and_symlink(tmp_path):
    path = tmp_path / "policy"
    path.write_text('{"configured_max_permission_profile":"STANDARD"}')
    path.chmod(0o666)
    check(path, "READ_ONLY", True)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    check(link, "READ_ONLY", True)
    path.unlink()
    check(link, "READ_ONLY", True)


def test_full_requires_root_trust(tmp_path):
    path = tmp_path / "policy"
    path.write_text('{"configured_max_permission_profile":"FULL_CONTROL"}')
    path.chmod(0o600)
    if os.name == "posix" and os.geteuid() == 0:
        check(path, "FULL_CONTROL")
        path.chmod(0o622)
        check(path, "READ_ONLY", True)
        path.chmod(0o600)
        os.chown(path, 65534, 65534)
    check(path, "READ_ONLY", True)
