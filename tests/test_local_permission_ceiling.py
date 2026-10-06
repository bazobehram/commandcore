import pytest

from commandcore_server.db import Database


def _device(db, caps):
    created = db.register_device(
        owner_id="owner",
        display_name="d",
        hostname="h",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.3.0",
        agent_protocol_version="1",
        public_key_b64="AA==",
        capabilities=caps,
        auto_approve=True,
    )
    return created["device_id"]


def test_server_cannot_exceed_device_local_max(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    did = _device(
        db, {"privileged_helper": False, "local_max_permission_profile": "READ_ONLY"}
    )
    with pytest.raises(
        RuntimeError, match="permission_exceeds_device_local_max:READ_ONLY"
    ):
        db.set_permission("owner", did, "STANDARD")


def test_full_control_requires_helper_and_local_full(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    did = _device(
        db, {"privileged_helper": True, "local_max_permission_profile": "STANDARD"}
    )
    with pytest.raises(
        RuntimeError, match="permission_exceeds_device_local_max:STANDARD"
    ):
        db.set_permission("owner", did, "FULL_CONTROL")
    db.mark_online(
        did,
        ip="127.0.0.1",
        agent_version="0.3.0",
        capabilities={
            "privileged_helper": True,
            "local_max_permission_profile": "FULL_CONTROL",
        },
        agent_protocol_version="1",
    )
    assert db.set_permission("owner", did, "FULL_CONTROL")
    assert db.get_device(did)["permission_profile"] == "FULL_CONTROL"


def test_runtime_helper_loss_downgrades_without_automatic_reupgrade(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    did = _device(
        db, {"privileged_helper": True, "local_max_permission_profile": "FULL_CONTROL"}
    )
    db.mark_online(
        did,
        ip="127.0.0.1",
        agent_version="0.3.0",
        capabilities={
            "privileged_helper": True,
            "local_max_permission_profile": "FULL_CONTROL",
        },
        agent_protocol_version="1",
    )
    db.set_permission("owner", did, "FULL_CONTROL")
    old, new = db.update_runtime_capabilities(
        did,
        {
            "privileged_helper": False,
            "configured_max_permission_profile": "FULL_CONTROL",
            "local_max_permission_profile": "STANDARD",
        },
    )
    assert (old, new) == ("FULL_CONTROL", "STANDARD")
    assert db.get_device(did)["permission_profile"] == "STANDARD"
    old, new = db.update_runtime_capabilities(
        did,
        {
            "privileged_helper": True,
            "configured_max_permission_profile": "FULL_CONTROL",
            "local_max_permission_profile": "FULL_CONTROL",
        },
    )
    assert (old, new) == (None, None)
    assert db.get_device(did)["permission_profile"] == "STANDARD"


@pytest.mark.asyncio
async def test_agent_enforces_local_read_only_even_if_server_requests_standard(
    tmp_path, monkeypatch
):
    import json
    from commandcore_agent.executor import Executor

    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "configured_max_permission_profile": "READ_ONLY",
                "allowed_helper_uids": [],
            }
        )
    )
    monkeypatch.setenv("COMMANDCORE_AGENT_POLICY", str(policy))
    seen = []

    async def output(stream, data):
        seen.append((stream, data))

    result = await Executor().execute(
        "x", "STANDARD", "shell.exec", {"command": "printf should-not-run"}, output
    )
    assert result["status"] == "error"
    assert result["error"] == "local_permission_ceiling:READ_ONLY"
    assert seen == []
