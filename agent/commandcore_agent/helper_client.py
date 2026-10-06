from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import shutil
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable

from .local_policy import load_local_policy, normalize_profile

OutputFn = Callable[[str, str], Awaitable[None]]

DEFAULT_SOCKET = "/run/commandcore/helper.sock"
DEFAULT_SECRET = "/etc/commandcore/helper.key"


def _canonical(payload: dict[str, Any]) -> bytes:
    body = {k: v for k, v in payload.items() if k != "mac"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load_secret(path: str) -> bytes:
    data = Path(path).read_bytes().strip()
    if len(data) < 32:
        raise RuntimeError("helper secret must contain at least 32 bytes")
    return data


class HelperClient:
    def __init__(
        self,
        socket_path: str | None = None,
        secret_path: str | None = None,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path or os.getenv(
            "COMMANDCORE_HELPER_SOCKET", DEFAULT_SOCKET
        )
        self.secret_path = secret_path or os.getenv(
            "COMMANDCORE_HELPER_SECRET", DEFAULT_SECRET
        )
        self.timeout = timeout

    def _sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        secret = _load_secret(self.secret_path)
        out = dict(payload)
        out.setdefault("request_id", str(uuid.uuid4()))
        out.setdefault("timestamp", time.time())
        out.setdefault("nonce", secrets.token_urlsafe(24))
        out["mac"] = hmac.new(secret, _canonical(out), hashlib.sha256).hexdigest()
        return out

    async def _request(
        self, payload: dict[str, Any], output: OutputFn | None = None
    ) -> dict[str, Any]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(self.socket_path, limit=32 * 1024 * 1024),
            timeout=self.timeout,
        )
        try:
            signed = self._sign(payload)
            encoded = (
                json.dumps(signed, separators=(",", ":"), ensure_ascii=False).encode(
                    "utf-8"
                )
                + b"\n"
            )
            writer.write(encoded)
            await writer.drain()
            response_timeout = (
                3605.0 if payload.get("action") == "execute" else self.timeout
            )
            while True:
                raw = await asyncio.wait_for(
                    reader.readline(), timeout=response_timeout
                )
                if not raw:
                    raise RuntimeError(
                        "privileged helper closed the connection without a final result"
                    )
                if len(raw) > 32 * 1024 * 1024:
                    raise RuntimeError(
                        "privileged helper response exceeded maximum frame size"
                    )
                msg = json.loads(raw)
                if msg.get("type") == "output":
                    if output:
                        await output(
                            str(msg.get("stream", "stdout")), str(msg.get("data", ""))
                        )
                    continue
                if msg.get("type") == "result":
                    outcome = msg.get("outcome")
                    return (
                        outcome
                        if isinstance(outcome, dict)
                        else {"status": "error", "error": "invalid_helper_result"}
                    )
                if msg.get("type") == "probe":
                    return msg
                if msg.get("type") == "error":
                    return {
                        "status": "error",
                        "error": str(msg.get("error", "helper_error")),
                    }
        finally:
            writer.close()
            await writer.wait_closed()

    async def probe(self) -> dict[str, Any]:
        try:
            result = await self._request({"action": "probe"})
        except (OSError, asyncio.TimeoutError, RuntimeError, json.JSONDecodeError):
            return {"available": False, "max_permission_profile": "STANDARD"}
        if result.get("type") == "probe":
            return {
                "available": bool(result.get("available", True)),
                "max_permission_profile": normalize_profile(
                    str(result.get("max_permission_profile", "STANDARD"))
                ),
                "helper_version": str(result.get("helper_version", "unknown")),
            }
        return {"available": False, "max_permission_profile": "STANDARD"}

    async def execute(
        self, execution_id: str, tool: str, arguments: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        return await self._request(
            {
                "action": "execute",
                "execution_id": execution_id,
                "permission_profile": "FULL_CONTROL",
                "tool": tool,
                "arguments": arguments,
            },
            output=output,
        )

    async def cancel(self, execution_id: str) -> dict[str, Any]:
        return await self._request({"action": "cancel", "execution_id": execution_id})


async def build_runtime_capabilities(base: dict[str, Any]) -> dict[str, Any]:
    capabilities = dict(base)
    policy = load_local_policy()
    configured = normalize_profile(
        str(policy.get("configured_max_permission_profile", "STANDARD"))
    )
    helper = HelperClient()
    probe = (
        await helper.probe()
        if configured == "FULL_CONTROL"
        else {"available": False, "max_permission_profile": configured}
    )
    helper_ok = (
        configured == "FULL_CONTROL"
        and bool(probe.get("available"))
        and probe.get("max_permission_profile") == "FULL_CONTROL"
    )
    if configured == "READ_ONLY":
        effective = "READ_ONLY"
    elif configured == "FULL_CONTROL" and helper_ok:
        effective = "FULL_CONTROL"
    else:
        effective = "STANDARD"
    rollout_path = Path(
        os.getenv(
            "COMMANDCORE_AGENT_ROLLOUT_STATE", "/opt/commandcore-agent/rollout.json"
        )
    )
    rollout_status = None
    rollout_candidate = None
    try:
        rollout = json.loads(rollout_path.read_text(encoding="utf-8"))
        if isinstance(rollout, dict):
            rollout_status = (
                str(rollout.get("status")) if rollout.get("status") else None
            )
            rollout_candidate = (
                str(rollout.get("candidate_version"))
                if rollout.get("candidate_version")
                else None
            )
    except Exception:
        pass
    capabilities.update(
        {
            "privileged_helper": helper_ok,
            "configured_max_permission_profile": configured,
            "policy_error": policy.get("policy_error"),
            "local_max_permission_profile": effective,
            "privileged_helper_version": probe.get("helper_version")
            if helper_ok
            else None,
            "git": shutil.which("git") is not None,
            "docker": helper_ok and shutil.which("docker") is not None,
            "services": helper_ok,
            "packages": helper_ok,
            "system_power": helper_ok,
            "update_rollout_status": rollout_status,
            "update_candidate_version": rollout_candidate,
            "agent_update_trust_configured": bool(
                str(
                    policy.get("update_public_key_b64")
                    or os.getenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "")
                ).strip()
            )
            and bool(
                policy.get("update_manifest_origins")
                or os.getenv("COMMANDCORE_UPDATE_MANIFEST_ORIGIN", "").strip()
            ),
        }
    )
    return capabilities
