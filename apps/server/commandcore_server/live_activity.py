"""Owner-scoped in-flight and historical activity without content or secrets."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .models import Principal


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


class LiveActivity:
    def __init__(self) -> None:
        self.active: dict[str, dict[str, Any]] = {}

    def begin(self, principal: Principal, tool: str) -> str:
        key = str(uuid.uuid4())
        self.active[key] = {
            "key": key,
            "owner": principal.subject,
            "issuer": principal.issuer,
            "tool": tool,
            "device_id": None,
            "started_epoch": time.time(),
        }
        return key

    def set_device(self, key: str | None, device_id: str) -> None:
        if key in self.active:
            self.active[key]["device_id"] = device_id

    def finish(self, key: str | None) -> None:
        if key:
            self.active.pop(key, None)

    def snapshot(
        self,
        principal: Principal,
        audits: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        limit: int,
    ) -> dict[str, Any]:
        authorized = {
            d["id"]: d["display_name"] for d in devices if not d.get("revoked_at")
        }
        now = time.time()
        rows = []
        for e in self.active.values():
            if e["owner"] != principal.subject or e["issuer"] != principal.issuer:
                continue
            if e["device_id"] and e["device_id"] not in authorized:
                continue
            rows.append(
                {
                    "id": e["key"],
                    "tool": e["tool"],
                    "status": "running",
                    "device": authorized.get(e["device_id"], "Control plane"),
                    "started_at": _iso(e["started_epoch"]),
                    "duration_ms": max(0, int((now - e["started_epoch"]) * 1000)),
                }
            )
        for e in audits:
            if str(e.get("tool", "")).startswith("activity."):
                continue
            device_id = e.get("device_id")
            if device_id and device_id not in authorized:
                continue
            status = str(e.get("status") or "error")
            if status not in {
                "ok",
                "completed",
                "started",
                "error",
                "timeout",
                "agent_disconnected",
                "canceled",
            }:
                status = "error"
            dur = e.get("duration_ms")
            rows.append(
                {
                    "id": "audit-" + str(e["id"]),
                    "tool": str(e.get("tool") or "operation"),
                    "status": status,
                    "device": authorized.get(device_id, "Control plane"),
                    "started_at": str(e.get("timestamp") or ""),
                    "duration_ms": dur if type(dur) is int and dur >= 0 else None,
                }
            )
        rows.sort(key=lambda x: x["started_at"], reverse=True)
        return {
            "events": rows[: max(1, min(limit, 50))],
            "refreshed_at": _iso(now),
            "privacy": "Only tool, device, time and status. No arguments or output.",
        }
