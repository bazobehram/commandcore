from __future__ import annotations

from typing import Any
import time

from .agent_gateway import AgentManager
from .db import Database, local_max_profile

TERMINAL_ROLLOUTS = {"completed", "failed", "canceled"}
FAILURE_STATES = {"failed", "rolled_back"}
STAGING_STALE_SECONDS = 600


class FleetRolloutService:
    """Persistent, operator-driven fleet rollout coordinator.

    `advance()` performs at most one remote lifecycle action. This keeps HTTP/API
    calls bounded and makes every transition durable/auditable instead of hiding
    a long-running background loop in the web process. Repeated advance calls can
    be made from the panel, an automation, or a future controller worker.
    """

    def __init__(self, db: Database, agents: AgentManager):
        self.db = db
        self.agents = agents

    def reconcile(self, owner_id: str, rollout_id: str) -> dict[str, Any]:
        rollout = self.db.get_fleet_rollout(owner_id, rollout_id)
        if not rollout:
            raise KeyError("fleet_rollout_not_found")
        target = str(rollout["target_version"])

        # Reconcile durable device state from the authoritative current device
        # version + Agent-advertised local rollout state.
        for item in rollout["devices"]:
            device = self.db.get_device(str(item["device_id"]))
            if not device:
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    str(item["device_id"]),
                    "failed",
                    last_error="device_missing",
                    event="device.failed",
                    detail={"error": "device_missing"},
                )
                continue
            state = str(item["state"])
            if (
                state == "staging"
                and time.time() - float(item.get("updated_at") or 0)
                >= STAGING_STALE_SECONDS
            ):
                # Staging is idempotent and signed. If the server died after
                # persisting `staging` but before recording the response, retry
                # from pending instead of deadlocking the ring forever.
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device["id"],
                    "pending",
                    last_error="staging_recovered_after_timeout",
                    event="device.staging_recovered",
                    detail={"timeout_seconds": STAGING_STALE_SECONDS},
                )
                state = "pending"
            caps = device.get("capabilities") or {}
            local_rollout = str(caps.get("update_rollout_status") or "")
            observed = str(device.get("agent_version") or "")

            if device.get("revoked_at") and state not in {
                "committed",
                "skipped",
                "failed",
                "rolled_back",
            }:
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device["id"],
                    "failed",
                    observed_version=observed,
                    last_error="device_revoked",
                    event="device.failed",
                    detail={"error": "device_revoked"},
                )
                continue

            if (
                observed == target
                and local_rollout == "committed"
                and state != "committed"
            ):
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device["id"],
                    "committed",
                    observed_version=observed,
                    last_error=None,
                    event="device.committed",
                    detail={"version": target},
                )
            elif state == "activating" and local_rollout in {
                "rolled_back",
                "rollback_failed",
            }:
                failed_state = (
                    "rolled_back" if local_rollout == "rolled_back" else "failed"
                )
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device["id"],
                    failed_state,
                    observed_version=observed,
                    last_error=local_rollout,
                    event="device.failed",
                    detail={
                        "local_rollout": local_rollout,
                        "observed_version": observed,
                    },
                )

        rollout = self.db.get_fleet_rollout(owner_id, rollout_id)
        assert rollout is not None
        if rollout["status"] in TERMINAL_ROLLOUTS:
            return rollout

        current_ring = int(rollout["current_ring"])
        current = [d for d in rollout["devices"] if int(d["ring"]) == current_ring]
        failures = [d for d in current if str(d["state"]) in FAILURE_STATES]
        if failures and bool(rollout["stop_on_failure"]):
            if rollout["status"] != "paused":
                self.db.set_fleet_rollout_status(
                    owner_id,
                    rollout_id,
                    "paused",
                    last_error=f"ring_{current_ring}_failure",
                )
                self.db.add_fleet_event(
                    owner_id,
                    rollout_id,
                    "rollout.paused",
                    detail={
                        "ring": current_ring,
                        "failed_devices": [d["device_id"] for d in failures],
                    },
                )
            return self.db.get_fleet_rollout(owner_id, rollout_id) or rollout

        satisfied = {"committed", "skipped"}
        if not bool(rollout["stop_on_failure"]):
            satisfied |= FAILURE_STATES
        if current and all(str(d["state"]) in satisfied for d in current):
            max_ring = int(rollout["max_ring"])
            if current_ring >= max_ring:
                self.db.set_fleet_rollout_status(
                    owner_id, rollout_id, "completed", last_error=None
                )
                self.db.add_fleet_event(
                    owner_id,
                    rollout_id,
                    "rollout.completed",
                    detail={"target_version": target},
                )
            else:
                self.db.set_fleet_rollout_status(
                    owner_id,
                    rollout_id,
                    "running",
                    last_error=None,
                    current_ring=current_ring + 1,
                )
                self.db.add_fleet_event(
                    owner_id,
                    rollout_id,
                    "ring.advanced",
                    detail={"from": current_ring, "to": current_ring + 1},
                )
        return self.db.get_fleet_rollout(owner_id, rollout_id) or rollout

    async def advance(self, owner_id: str, rollout_id: str) -> dict[str, Any]:
        rollout = self.reconcile(owner_id, rollout_id)
        if rollout["status"] in TERMINAL_ROLLOUTS or rollout["status"] == "paused":
            return {"action": "none", "rollout": rollout}
        if rollout["status"] == "planned":
            self.db.set_fleet_rollout_status(
                owner_id, rollout_id, "running", last_error=None
            )
            self.db.add_fleet_event(owner_id, rollout_id, "rollout.started", detail={})
            rollout = self.db.get_fleet_rollout(owner_id, rollout_id) or rollout

        ring = int(rollout["current_ring"])
        candidates = [d for d in rollout["devices"] if int(d["ring"]) == ring]
        for item in candidates:
            state = str(item["state"])
            if state in {"committed", "failed", "rolled_back", "skipped", "activating"}:
                continue
            device_id = str(item["device_id"])
            device = self.db.get_device(device_id)
            if not device:
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device_id,
                    "failed",
                    last_error="device_missing",
                    event="device.failed",
                )
                return {
                    "action": "failed",
                    "device_id": device_id,
                    "rollout": self.reconcile(owner_id, rollout_id),
                }
            caps = device.get("capabilities") or {}
            if (
                str(device.get("permission_profile")) != "FULL_CONTROL"
                or local_max_profile(caps) != "FULL_CONTROL"
            ):
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device_id,
                    "failed",
                    observed_version=str(device.get("agent_version") or ""),
                    last_error="full_control_no_longer_available",
                    event="device.failed",
                    detail={"error": "full_control_no_longer_available"},
                )
                return {
                    "action": "failed",
                    "device_id": device_id,
                    "rollout": self.reconcile(owner_id, rollout_id),
                }
            if device.get("status") != "online":
                # Offline is not a rollout failure. Leave it pending/staged and let
                # the operator decide whether to wait, skip, or cancel the rollout.
                continue

            dispatch_device = dict(device)
            dispatch_device["permission_profile"] = "FULL_CONTROL"
            if state == "pending":
                self.db.set_fleet_device_state(
                    owner_id, rollout_id, device_id, "staging", event="device.staging"
                )
                try:
                    result = await self.agents.dispatch(
                        owner_id=owner_id,
                        device=dispatch_device,
                        tool="agent.update.stage",
                        arguments={"manifest_url": rollout["manifest_url"]},
                        timeout_ms=360000,
                    )
                except RuntimeError as exc:
                    if str(exc) == "device_offline":
                        # Race: the device went offline after the DB status check.
                        # This is not an update failure; return to pending and wait.
                        self.db.set_fleet_device_state(
                            owner_id,
                            rollout_id,
                            device_id,
                            "pending",
                            last_error="device_offline",
                            event="device.waiting",
                            detail={"reason": "device_offline"},
                        )
                        return {
                            "action": "waiting",
                            "device_id": device_id,
                            "rollout": self.reconcile(owner_id, rollout_id),
                        }
                    self.db.set_fleet_device_state(
                        owner_id,
                        rollout_id,
                        device_id,
                        "failed",
                        last_error=str(exc),
                        observed_version=str(device.get("agent_version") or ""),
                        event="device.failed",
                        detail={"error": str(exc)},
                    )
                    return {
                        "action": "stage_failed",
                        "device_id": device_id,
                        "rollout": self.reconcile(owner_id, rollout_id),
                    }
                if (
                    result.status == "ok"
                    and isinstance(result.result, dict)
                    and result.result.get("metadata_path")
                ):
                    path = str(result.result["metadata_path"])
                    self.db.set_fleet_device_state(
                        owner_id,
                        rollout_id,
                        device_id,
                        "staged",
                        stage_metadata_path=path,
                        observed_version=str(device.get("agent_version") or ""),
                        event="device.staged",
                        detail={"stage_metadata_path": path},
                    )
                    return {
                        "action": "staged",
                        "device_id": device_id,
                        "rollout": self.reconcile(owner_id, rollout_id),
                    }
                if result.status in {"agent_disconnected", "timeout"}:
                    # Staging is signed + idempotent; transport uncertainty is a
                    # wait/retry condition, not evidence that the release is bad.
                    error = (
                        result.error or result.stderr or f"stage_status:{result.status}"
                    )
                    self.db.set_fleet_device_state(
                        owner_id,
                        rollout_id,
                        device_id,
                        "pending",
                        last_error=error,
                        observed_version=str(device.get("agent_version") or ""),
                        event="device.waiting",
                        detail={"reason": result.status},
                    )
                    return {
                        "action": "waiting",
                        "device_id": device_id,
                        "rollout": self.reconcile(owner_id, rollout_id),
                    }
                error = result.error or result.stderr or f"stage_status:{result.status}"
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device_id,
                    "failed",
                    last_error=error,
                    observed_version=str(device.get("agent_version") or ""),
                    event="device.failed",
                    detail={"error": error},
                )
                return {
                    "action": "stage_failed",
                    "device_id": device_id,
                    "rollout": self.reconcile(owner_id, rollout_id),
                }

            if state == "staged":
                stage_path = str(item.get("stage_metadata_path") or "")
                if not stage_path:
                    self.db.set_fleet_device_state(
                        owner_id,
                        rollout_id,
                        device_id,
                        "failed",
                        last_error="missing_stage_metadata_path",
                        event="device.failed",
                        detail={"error": "missing_stage_metadata_path"},
                    )
                    return {
                        "action": "activate_failed",
                        "device_id": device_id,
                        "rollout": self.reconcile(owner_id, rollout_id),
                    }
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device_id,
                    "activating",
                    event="device.activating",
                )
                try:
                    result = await self.agents.dispatch(
                        owner_id=owner_id,
                        device=dispatch_device,
                        tool="agent.update.activate",
                        arguments={
                            "stage_metadata_path": stage_path,
                            "health_timeout_seconds": 60,
                        },
                        timeout_ms=120000,
                    )
                except RuntimeError as exc:
                    if str(exc) == "device_offline":
                        # If dispatch never started, preserve the staged artifact so
                        # the operator can retry activation after reconnect.
                        self.db.set_fleet_device_state(
                            owner_id,
                            rollout_id,
                            device_id,
                            "staged",
                            last_error="device_offline",
                            event="device.waiting",
                            detail={"reason": "device_offline"},
                        )
                        return {
                            "action": "waiting",
                            "device_id": device_id,
                            "rollout": self.reconcile(owner_id, rollout_id),
                        }
                    self.db.set_fleet_device_state(
                        owner_id,
                        rollout_id,
                        device_id,
                        "failed",
                        last_error=str(exc),
                        event="device.failed",
                        detail={"error": str(exc)},
                    )
                    return {
                        "action": "activate_failed",
                        "device_id": device_id,
                        "rollout": self.reconcile(owner_id, rollout_id),
                    }
                # Restarting the Agent normally tears down the transport before the
                # helper can deliver its final response. That is expected; the next
                # authenticated hello/heartbeat is the commit signal.
                if result.status in {"ok", "agent_disconnected", "timeout"}:
                    return {
                        "action": "activating",
                        "device_id": device_id,
                        "rollout": self.reconcile(owner_id, rollout_id),
                    }
                error = (
                    result.error or result.stderr or f"activate_status:{result.status}"
                )
                self.db.set_fleet_device_state(
                    owner_id,
                    rollout_id,
                    device_id,
                    "failed",
                    last_error=error,
                    event="device.failed",
                    detail={"error": error},
                )
                return {
                    "action": "activate_failed",
                    "device_id": device_id,
                    "rollout": self.reconcile(owner_id, rollout_id),
                }

        # Nothing actionable in the ring (typically waiting for an offline device
        # or an activating device to reconnect).
        return {"action": "waiting", "rollout": self.reconcile(owner_id, rollout_id)}

    def resume(self, owner_id: str, rollout_id: str) -> dict[str, Any]:
        rollout = self.db.get_fleet_rollout(owner_id, rollout_id)
        if not rollout:
            raise KeyError("fleet_rollout_not_found")
        if rollout["status"] != "paused":
            raise ValueError("fleet_rollout_not_paused")
        self.db.set_fleet_rollout_status(
            owner_id, rollout_id, "running", last_error=None
        )
        self.db.add_fleet_event(owner_id, rollout_id, "rollout.resumed", detail={})
        return self.db.get_fleet_rollout(owner_id, rollout_id) or rollout
