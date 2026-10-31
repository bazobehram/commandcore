"""Bounded, single-target Chrome DevTools Protocol transport.

This module sends commands over an existing private WebSocket only. Browser
session ownership, network egress, and request authorization remain in the
gateway/worker boundaries; callers must never infer them from a CDP target ID.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from .browser_errors import BrowserError


class CDP:
    def __init__(self, websocket: Any):
        self.ws = websocket
        self.counter = 0

    async def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session: str | None = None,
    ) -> dict[str, Any]:
        self.counter += 1
        call_id = self.counter
        msg: dict[str, Any] = {"id": call_id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        await self.ws.send(json.dumps(msg))
        # A single command must have a total deadline. A busy page can emit
        # a stream of unrelated events; per-receive timeouts alone never bound
        # the duration. Never retry state-changing actions on expiry.
        try:
            async with asyncio.timeout(20):
                while True:
                    # Ignore unrelated CDP notifications until this command's
                    # response arrives. The enclosing deadline bounds the wait.
                    result = json.loads(await self.ws.recv())
                    if result.get("id") == call_id:
                        if result.get("error"):
                            raise BrowserError(f"CDP operation failed: {method}")
                        return result.get("result") or {}
        except TimeoutError as exc:
            raise BrowserError("CDP response timeout") from exc
        raise BrowserError("CDP response timeout")

    async def attach_page(self, target_id: str | None) -> tuple[str, str]:
        # Never attach to "the first page": Steel may have other tabs.
        # The target is created explicitly and pinned for this owner.
        if target_id is None:
            created = await self.send("Target.createTarget", {"url": "about:blank"})
            target_id = created["targetId"]
        info = await self.send("Target.getTargets")
        if not any(
            t.get("targetId") == target_id and t.get("type") == "page"
            for t in info.get("targetInfos", [])
        ):
            raise BrowserError("owned browser tab disappeared")
        result = await self.send(
            "Target.attachToTarget", {"targetId": target_id, "flatten": True}
        )
        session = result["sessionId"]
        await self.send("Page.enable", session=session)
        await self.send("Runtime.enable", session=session)
        return session, target_id
