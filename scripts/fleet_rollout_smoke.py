#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from commandcore_server.db import Database
from commandcore_server.fleet import FleetRolloutService
from commandcore_server.models import JobResult


class FakeAgents:
    def __init__(self, db: Database, target: str):
        self.db = db
        self.target = target
        self.calls = []

    async def dispatch(self, *, owner_id, device, tool, arguments, timeout_ms):
        self.calls.append(
            {"device_id": device["id"], "tool": tool, "arguments": arguments}
        )
        if tool == "agent.update.stage":
            return JobResult(
                "stage",
                "ok",
                {
                    "metadata_path": f"/var/lib/commandcore/updates/{self.target}/stage.json"
                },
                0,
            )
        if tool == "agent.update.activate":
            return JobResult(
                "activate",
                "agent_disconnected",
                None,
                None,
                error="expected restart disconnect",
            )
        raise AssertionError(tool)


def register(db: Database, owner: str, name: str) -> str:
    item = db.register_device(
        owner_id=owner,
        display_name=name,
        hostname=name,
        platform="linux",
        architecture="x86_64",
        agent_version="0.7.0",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={
            "privileged_helper": True,
            "local_max_permission_profile": "FULL_CONTROL",
            "agent_update": True,
            "agent_update_trust_configured": True,
        },
        auto_approve=True,
    )
    device_id = item["device_id"]
    db.set_permission(owner, device_id, "FULL_CONTROL")
    db.mark_online(
        device_id,
        ip="127.0.0.1",
        agent_version="0.7.0",
        capabilities={
            "privileged_helper": True,
            "local_max_permission_profile": "FULL_CONTROL",
            "update_rollout_status": None,
            "agent_update": True,
            "agent_update_trust_configured": True,
        },
        agent_protocol_version="1",
    )
    return device_id


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="commandcore-fleet-") as td:
        db = Database(str(Path(td) / "commandcore.sqlite3"))
        owner = "fleet-smoke-owner"
        canary = register(db, owner, "canary")
        second = register(db, owner, "second")
        third = register(db, owner, "third")
        rollout = db.create_fleet_rollout(
            owner_id=owner,
            created_by=owner,
            target_version="0.8.0",
            manifest_url="https://updates.example/commandcore/manifest.json",
            device_ids=[canary, second, third],
            canary_count=1,
            ring_size=2,
            stop_on_failure=True,
        )
        agents = FakeAgents(db, "0.8.0")
        fleet = FleetRolloutService(db, agents)

        assert asyncio.run(fleet.advance(owner, rollout["id"]))["action"] == "staged"
        assert (
            asyncio.run(fleet.advance(owner, rollout["id"]))["action"] == "activating"
        )
        # Commit signal comes from the newly authenticated Agent heartbeat.
        db.mark_online(
            canary,
            ip="127.0.0.1",
            agent_version="0.8.0",
            capabilities={
                "privileged_helper": True,
                "local_max_permission_profile": "FULL_CONTROL",
                "update_rollout_status": "committed",
                "update_candidate_version": "0.8.0",
                "agent_update": True,
                "agent_update_trust_configured": True,
            },
            agent_protocol_version="1",
        )
        after = fleet.reconcile(owner, rollout["id"])
        assert after["current_ring"] == 1 and after["status"] == "running"

        # A failure in ring 1 pauses further rollout rather than touching third-party devices.
        db.set_fleet_device_state(
            owner,
            rollout["id"],
            second,
            "failed",
            last_error="simulated_failure",
            event="device.failed",
        )
        paused = fleet.reconcile(owner, rollout["id"])
        assert paused["status"] == "paused" and paused["last_error"] == "ring_1_failure"
        resumed = fleet.resume(owner, rollout["id"])
        assert resumed["status"] == "running"
        db.set_fleet_device_state(
            owner,
            rollout["id"],
            second,
            "skipped",
            last_error="operator_skipped",
            event="device.skipped",
        )
        db.set_fleet_device_state(
            owner,
            rollout["id"],
            third,
            "skipped",
            last_error="operator_skipped",
            event="device.skipped",
        )
        done = fleet.reconcile(owner, rollout["id"])
        assert done["status"] == "completed"

        print(
            json.dumps(
                {
                    "status": "PASS",
                    "canary_stage": True,
                    "activation_restart_disconnect_expected": True,
                    "authenticated_reconnect_commit": True,
                    "ring_advance": True,
                    "stop_on_failure": True,
                    "operator_resume": True,
                    "operator_skip": True,
                    "rollout_completed": True,
                    "remote_calls": len(agents.calls),
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
