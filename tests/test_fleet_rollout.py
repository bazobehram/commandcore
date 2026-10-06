import asyncio
from pathlib import Path

from commandcore_server.db import Database
from commandcore_server.fleet import FleetRolloutService
from commandcore_server.models import JobResult


def _register(db: Database, owner: str, name: str):
    item = db.register_device(
        owner_id=owner,
        display_name=name,
        hostname=name,
        platform="linux",
        architecture="x86_64",
        agent_version="0.6.0",
        agent_protocol_version="1",
        public_key_b64="abc",
        capabilities={
            "privileged_helper": True,
            "local_max_permission_profile": "FULL_CONTROL",
            "agent_update": True,
            "agent_update_trust_configured": True,
        },
        auto_approve=True,
    )
    did = item["device_id"]
    assert db.set_permission(owner, did, "FULL_CONTROL")
    return did


def test_fleet_rollout_rings_and_skip(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    ids = [_register(db, owner, f"d{i}") for i in range(5)]
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=ids,
        canary_count=1,
        ring_size=2,
    )
    rings = [d["ring"] for d in r["devices"]]
    assert rings == [0, 1, 1, 2, 2]
    assert r["status"] == "planned"
    assert db.set_fleet_device_state(owner, r["id"], ids[0], "skipped", event="test")


class FakeAgents:
    def __init__(self, db, target):
        self.db = db
        self.target = target
        self.calls = []

    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        self.calls.append((device["id"], tool, arguments))
        if tool == "agent.update.stage":
            return JobResult(
                "e1",
                "ok",
                {
                    "metadata_path": f"/var/lib/commandcore/updates/{self.target}/stage.json"
                },
                0,
            )
        if tool == "agent.update.activate":
            # activation intentionally looks like a transport loss; next hello is authoritative
            return JobResult(
                "e2", "agent_disconnected", None, None, error="agent disconnected"
            )
        raise AssertionError(tool)


def test_fleet_canary_stage_activate_commit_and_advance(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    d1 = _register(db, owner, "canary")
    d2 = _register(db, owner, "ring1")
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=[d1, d2],
        canary_count=1,
        ring_size=10,
    )
    # Mark live while preserving FULL_CONTROL capabilities.
    caps = {
        "privileged_helper": True,
        "local_max_permission_profile": "FULL_CONTROL",
        "update_rollout_status": None,
        "agent_update": True,
        "agent_update_trust_configured": True,
    }
    db.mark_online(
        d1,
        ip="127.0.0.1",
        agent_version="0.6.0",
        capabilities=caps,
        agent_protocol_version="1",
    )
    db.mark_online(
        d2,
        ip="127.0.0.1",
        agent_version="0.6.0",
        capabilities=caps,
        agent_protocol_version="1",
    )
    svc = FleetRolloutService(db, FakeAgents(db, "0.7.0"))
    a = asyncio.run(svc.advance(owner, r["id"]))
    assert a["action"] == "staged"
    a = asyncio.run(svc.advance(owner, r["id"]))
    assert a["action"] == "activating"
    # Simulate reconnect after local updater committed.
    caps2 = {
        **caps,
        "update_rollout_status": "committed",
        "update_candidate_version": "0.7.0",
        "agent_update": True,
        "agent_update_trust_configured": True,
    }
    db.mark_online(
        d1,
        ip="127.0.0.1",
        agent_version="0.7.0",
        capabilities=caps2,
        agent_protocol_version="1",
    )
    rr = svc.reconcile(owner, r["id"])
    assert rr["current_ring"] == 1 and rr["status"] == "running"
    assert (
        next(x for x in rr["devices"] if x["device_id"] == d1)["state"] == "committed"
    )


def test_fleet_failure_pauses_ring(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    d1 = _register(db, owner, "canary")
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=[d1],
    )
    db.set_fleet_rollout_status(owner, r["id"], "running")
    db.set_fleet_device_state(
        owner, r["id"], d1, "failed", last_error="boom", event="device.failed"
    )
    rr = FleetRolloutService(db, FakeAgents(db, "0.7.0")).reconcile(owner, r["id"])
    assert rr["status"] == "paused"
    assert rr["last_error"] == "ring_0_failure"


def test_fleet_requires_device_local_update_trust(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    item = db.register_device(
        owner_id=owner,
        display_name="no-trust",
        hostname="no-trust",
        platform="linux",
        architecture="x86_64",
        agent_version="0.7.0",
        agent_protocol_version="1",
        public_key_b64="abc",
        capabilities={
            "privileged_helper": True,
            "local_max_permission_profile": "FULL_CONTROL",
            "agent_update": True,
        },
        auto_approve=True,
    )
    did = item["device_id"]
    db.set_permission(owner, did, "FULL_CONTROL")
    import pytest

    with pytest.raises(ValueError, match="fleet_device_update_trust_not_configured"):
        db.create_fleet_rollout(
            owner_id=owner,
            created_by=owner,
            target_version="0.8.0",
            manifest_url="https://updates.example/manifest.json",
            device_ids=[did],
        )


class OfflineRaceAgents:
    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        raise RuntimeError("device_offline")


def test_fleet_stage_offline_race_returns_pending(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    did = _register(db, owner, "race-stage")
    caps = {
        "privileged_helper": True,
        "local_max_permission_profile": "FULL_CONTROL",
        "agent_update": True,
        "agent_update_trust_configured": True,
    }
    db.mark_online(
        did,
        ip="127.0.0.1",
        agent_version="0.6.0",
        capabilities=caps,
        agent_protocol_version="1",
    )
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=[did],
    )
    out = asyncio.run(
        FleetRolloutService(db, OfflineRaceAgents()).advance(owner, r["id"])
    )
    assert out["action"] == "waiting"
    item = db.get_fleet_rollout(owner, r["id"])["devices"][0]
    assert item["state"] == "pending"
    assert item["last_error"] == "device_offline"


def test_fleet_stale_staging_recovers_to_pending(tmp_path: Path, monkeypatch):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    did = _register(db, owner, "stale-stage")
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=[did],
    )
    db.set_fleet_rollout_status(owner, r["id"], "running")
    db.set_fleet_device_state(owner, r["id"], did, "staging", event="device.staging")
    old = 1000.0
    with db.lock:
        db.conn.execute(
            "UPDATE fleet_rollout_devices SET updated_at=? WHERE rollout_id=? AND device_id=?",
            (old, r["id"], did),
        )
        db.conn.commit()
    monkeypatch.setattr("commandcore_server.fleet.time.time", lambda: old + 601)
    rr = FleetRolloutService(db, FakeAgents(db, "0.7.0")).reconcile(owner, r["id"])
    item = next(x for x in rr["devices"] if x["device_id"] == did)
    assert item["state"] == "pending"
    assert item["last_error"] == "staging_recovered_after_timeout"


class StageDisconnectAgents:
    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        assert tool == "agent.update.stage"
        return JobResult(
            "e-stage", "agent_disconnected", None, None, error="transport lost"
        )


def test_fleet_stage_transport_loss_is_retryable(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    did = _register(db, owner, "stage-loss")
    caps = {
        "privileged_helper": True,
        "local_max_permission_profile": "FULL_CONTROL",
        "agent_update": True,
        "agent_update_trust_configured": True,
    }
    db.mark_online(
        did,
        ip="127.0.0.1",
        agent_version="0.6.0",
        capabilities=caps,
        agent_protocol_version="1",
    )
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=[did],
    )
    out = asyncio.run(
        FleetRolloutService(db, StageDisconnectAgents()).advance(owner, r["id"])
    )
    assert out["action"] == "waiting"
    item = db.get_fleet_rollout(owner, r["id"])["devices"][0]
    assert item["state"] == "pending"
    assert item["last_error"] == "transport lost"


def test_fleet_activate_offline_race_preserves_staged_artifact(tmp_path: Path):
    db = Database(str(tmp_path / "db.sqlite"))
    owner = "u"
    did = _register(db, owner, "race-activate")
    caps = {
        "privileged_helper": True,
        "local_max_permission_profile": "FULL_CONTROL",
        "agent_update": True,
        "agent_update_trust_configured": True,
    }
    db.mark_online(
        did,
        ip="127.0.0.1",
        agent_version="0.6.0",
        capabilities=caps,
        agent_protocol_version="1",
    )
    r = db.create_fleet_rollout(
        owner_id=owner,
        created_by=owner,
        target_version="0.7.0",
        manifest_url="https://updates.example/manifest.json",
        device_ids=[did],
    )
    db.set_fleet_rollout_status(owner, r["id"], "running")
    db.set_fleet_device_state(
        owner,
        r["id"],
        did,
        "staged",
        stage_metadata_path="/var/lib/commandcore/updates/0.7.0/stage.json",
    )
    out = asyncio.run(
        FleetRolloutService(db, OfflineRaceAgents()).advance(owner, r["id"])
    )
    assert out["action"] == "waiting"
    item = db.get_fleet_rollout(owner, r["id"])["devices"][0]
    assert item["state"] == "staged"
    assert item["stage_metadata_path"].endswith("stage.json")
