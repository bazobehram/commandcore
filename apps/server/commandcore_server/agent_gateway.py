from __future__ import annotations

import asyncio
import json
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from .db import Database
from .metrics import Metrics
from .models import JobResult
from .security import token_hash, verify_device_signature

AGENT_PROTOCOL_VERSION = "1"


@dataclass
class PendingJob:
    execution_id: str
    device_id: str
    future: asyncio.Future[JobResult]
    stdout_parts: list[str] = field(default_factory=list)
    stderr_parts: list[str] = field(default_factory=list)
    output_bytes: int = 0
    observed_output_bytes: int = 0


@dataclass
class AgentConnection:
    device_id: str
    websocket: WebSocket
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class AgentManager:
    def __init__(self, db: Database, metrics: Metrics, max_output_bytes: int):
        self.db = db
        self.metrics = metrics
        self.max_output_bytes = max_output_bytes
        self.connections: dict[str, AgentConnection] = {}
        self.jobs: dict[str, PendingJob] = {}
        self._lock = asyncio.Lock()

    async def count(self) -> int:
        async with self._lock:
            return len(self.connections)

    async def online_device_ids(self) -> list[str]:
        async with self._lock:
            return sorted(self.connections.keys())

    def active_job_count(self) -> int:
        return sum(1 for job in self.jobs.values() if not job.future.done())

    async def _lifecycle(self, device_id: str, event: str) -> None:
        from .activity import ActivityEvent, notify

        device = self.db.get_device(device_id)
        if not device:
            return
        timestamp = time.time()
        activity = ActivityEvent(
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            device_id,
            str(device["display_name"]),
            "agent." + event,
            {},
            str(device["permission_profile"]),
            timestamp,
            completed_at=timestamp,
            duration_ms=0,
            status="completed",
            kind="lifecycle",
            source={"auth_kind": "device-agent"},
            result_summary="Authenticated Agent " + event,
        )
        self.db.save_activity(activity.wire())
        await notify(activity.wire())

    def _apply_runtime_capabilities(
        self, device_id: str, capabilities: dict[str, Any]
    ) -> None:
        old_profile, new_profile = self.db.update_runtime_capabilities(
            device_id, capabilities
        )
        if old_profile and new_profile:
            self.db.add_audit(
                user_id="system",
                client_id="agent-gateway",
                device_id=device_id,
                tool="policy.local_ceiling",
                args_summary=json.dumps(
                    {"from": old_profile, "to": new_profile}, separators=(",", ":")
                ),
                execution_id=None,
                status="ok",
                duration_ms=0,
                exit_code=None,
                risk_class="high",
            )

    async def disconnect_device(self, device_id: str) -> None:
        async with self._lock:
            conn = self.connections.pop(device_id, None)
        if conn:
            try:
                await conn.websocket.close(code=4001)
            except Exception:
                pass
        async with self._lock:
            if device_id not in self.connections:
                self.db.mark_offline(device_id)

    async def handle_websocket(self, websocket: WebSocket) -> None:
        auth = websocket.headers.get("authorization", "")
        if not auth.startswith("Device ") or ":" not in auth[7:]:
            await websocket.close(code=4401)
            return
        device_id, raw_token = auth[7:].split(":", 1)
        row = self.db.get_device_auth_row(device_id)
        if not row or row.get("revoked_at") or not row.get("approved_at"):
            await websocket.close(code=4403)
            return
        if not hmac.compare_digest(
            token_hash(raw_token), str(row["device_token_hash"])
        ):
            await websocket.close(code=4401)
            return

        await websocket.accept()
        nonce = secrets.token_urlsafe(32)
        await websocket.send_json(
            {
                "type": "challenge",
                "nonce": nonce,
                "protocol_version": AGENT_PROTOCOL_VERSION,
            }
        )
        try:
            hello = await asyncio.wait_for(websocket.receive_json(), timeout=10)
        except Exception:
            await websocket.close(code=4408)
            return
        if hello.get("type") != "hello" or hello.get("device_id") != device_id:
            await websocket.close(code=4400)
            return
        if str(hello.get("protocol_version")) != AGENT_PROTOCOL_VERSION:
            await websocket.close(code=4406)
            return
        message = f"commandcore-agent-auth-v1\n{device_id}\n{nonce}".encode()
        if not verify_device_signature(
            row["public_key_b64"], str(hello.get("signature", "")), message
        ):
            await websocket.close(code=4401)
            return

        conn = AgentConnection(device_id=device_id, websocket=websocket)
        async with self._lock:
            old = self.connections.get(device_id)
            self.connections[device_id] = conn
        if old:
            try:
                await old.websocket.close(code=4002)
            except Exception:
                pass

        client = websocket.client
        hello_capabilities = hello.get("capabilities") or {}
        previous_device = self.db.get_device(device_id) or {}

        def runtime(capabilities):
            if not isinstance(capabilities, dict):
                return None
            return {
                "boot_id": capabilities.get("agent_boot_id"),
                "process_start": capabilities.get("agent_process_start"),
                "pid": capabilities.get("agent_process_id"),
            }

        previous_runtime = runtime(previous_device.get("capabilities"))
        current_runtime = runtime(hello_capabilities)
        recovery_event = None
        if isinstance(previous_runtime, dict) and isinstance(current_runtime, dict):
            valid = all(
                isinstance(runtime.get("boot_id"), str)
                and isinstance(runtime.get("process_start"), str)
                for runtime in (previous_runtime, current_runtime)
            )
            if valid and previous_runtime["boot_id"] != current_runtime["boot_id"]:
                recovery_event = "host_rebooted"
            elif valid and (
                previous_runtime["process_start"] != current_runtime["process_start"]
                or previous_runtime["pid"] != current_runtime["pid"]
            ):
                recovery_event = "restarted"
        self.db.mark_online(
            device_id,
            ip=client.host if client else None,
            agent_version=str(hello.get("agent_version", "unknown")),
            capabilities=hello_capabilities,
            agent_protocol_version=AGENT_PROTOCOL_VERSION,
        )
        self._apply_runtime_capabilities(device_id, hello_capabilities)
        self.metrics.inc("commandcore_agent_connections_total")
        rotation_nonce = secrets.token_urlsafe(32)
        await websocket.send_json(
            {
                "type": "hello.ack",
                "device_id": device_id,
                "key_generation": int(row.get("key_generation") or 1),
                "key_rotation_nonce": rotation_nonce,
            }
        )
        await self._lifecycle(device_id, "connected")
        if recovery_event:
            await self._lifecycle(device_id, recovery_event)

        try:
            while True:
                msg = await websocket.receive_json()
                # A replaced socket may finish receiving after the new hello.
                # Only the current authenticated connection can update state.
                async with self._lock:
                    if self.connections.get(device_id) is not conn:
                        break
                mtype = msg.get("type")
                if mtype == "heartbeat":
                    self.db.heartbeat(device_id)
                    if isinstance(msg.get("capabilities"), dict):
                        self._apply_runtime_capabilities(device_id, msg["capabilities"])
                    async with conn.send_lock:
                        await asyncio.wait_for(
                            websocket.send_json({"type": "heartbeat.ack"}), timeout=15
                        )
                    continue
                if mtype == "job.output":
                    await self._handle_output(device_id, msg)
                    continue
                if mtype == "job.result":
                    await self._handle_result(device_id, msg)
                    continue
                if mtype == "device.key.rotate.prepare":
                    await self._handle_key_rotation_prepare(
                        conn, device_id, rotation_nonce, msg
                    )
                    continue
                if mtype == "device.key.rotate.confirm":
                    await self._handle_key_rotation_confirm(conn, device_id, msg)
                    continue
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            async with self._lock:
                current = self.connections.get(device_id)
                if current is conn:
                    self.connections.pop(device_id, None)
                    self.db.mark_offline(device_id)
                    await self._lifecycle(device_id, "disconnected")
                    for execution_id, job in list(self.jobs.items()):
                        if job.device_id == device_id and not job.future.done():
                            job.future.set_result(
                                JobResult(
                                    execution_id=execution_id,
                                    status="agent_disconnected",
                                    result=None,
                                    exit_code=None,
                                    stdout="".join(job.stdout_parts),
                                    stderr="".join(job.stderr_parts),
                                    error="agent disconnected while job was running",
                                )
                            )

    async def _send_connection_json(
        self, conn: AgentConnection, payload: dict[str, Any]
    ) -> None:
        async with conn.send_lock:
            await conn.websocket.send_json(payload)

    async def _handle_key_rotation_prepare(
        self,
        conn: AgentConnection,
        device_id: str,
        rotation_nonce: str,
        msg: dict[str, Any],
    ) -> None:
        request_id = str(msg.get("request_id", ""))
        new_public_key = str(msg.get("new_public_key_b64", ""))
        row = self.db.get_device_auth_row(device_id)
        if not row or not new_public_key:
            await self._send_connection_json(
                conn,
                {
                    "type": "device.key.rotate.error",
                    "request_id": request_id,
                    "error": "invalid_request",
                },
            )
            return
        message = f"commandcore-key-rotation-prepare-v1\n{device_id}\n{rotation_nonce}\n{new_public_key}".encode()
        old_ok = verify_device_signature(
            str(row["public_key_b64"]), str(msg.get("old_signature", "")), message
        )
        new_ok = verify_device_signature(
            new_public_key, str(msg.get("new_signature", "")), message
        )
        if not old_ok or not new_ok:
            self.db.add_audit(
                user_id=str(row["owner_id"]),
                client_id="agent-gateway",
                device_id=device_id,
                tool="device.key.rotate.prepare",
                args_summary="{}",
                execution_id=None,
                status="denied",
                duration_ms=0,
                exit_code=None,
                risk_class="critical",
            )
            await self._send_connection_json(
                conn,
                {
                    "type": "device.key.rotate.error",
                    "request_id": request_id,
                    "error": "invalid_rotation_proof",
                },
            )
            return
        try:
            prepared = self.db.prepare_device_key_rotation(
                device_id, str(row["public_key_b64"]), new_public_key, ttl_seconds=300
            )
        except Exception as exc:
            await self._send_connection_json(
                conn,
                {
                    "type": "device.key.rotate.error",
                    "request_id": request_id,
                    "error": str(exc),
                },
            )
            return
        self.db.add_audit(
            user_id=str(row["owner_id"]),
            client_id="agent-gateway",
            device_id=device_id,
            tool="device.key.rotate.prepare",
            args_summary=json.dumps(
                {"next_generation": prepared["key_generation"] + 1}
            ),
            execution_id=None,
            status="ok",
            duration_ms=0,
            exit_code=None,
            risk_class="critical",
        )
        await self._send_connection_json(
            conn,
            {
                "type": "device.key.rotate.prepared",
                "request_id": request_id,
                "rotation_id": prepared["rotation_id"],
                "expires_at": prepared["expires_at"],
                "current_generation": prepared["key_generation"],
            },
        )

    async def _handle_key_rotation_confirm(
        self, conn: AgentConnection, device_id: str, msg: dict[str, Any]
    ) -> None:
        request_id = str(msg.get("request_id", ""))
        rotation_id = str(msg.get("rotation_id", ""))
        pending = self.db.pending_device_key_rotation(device_id)
        if (
            not pending
            or str(pending.get("pending_key_rotation_id") or "") != rotation_id
        ):
            await self._send_connection_json(
                conn,
                {
                    "type": "device.key.rotate.error",
                    "request_id": request_id,
                    "error": "key_rotation_not_pending",
                },
            )
            return
        new_public_key = str(pending.get("pending_public_key_b64") or "")
        message = (
            f"commandcore-key-rotation-confirm-v1\n{device_id}\n{rotation_id}".encode()
        )
        if not verify_device_signature(
            new_public_key, str(msg.get("new_signature", "")), message
        ):
            await self._send_connection_json(
                conn,
                {
                    "type": "device.key.rotate.error",
                    "request_id": request_id,
                    "error": "invalid_new_key_proof",
                },
            )
            return
        try:
            generation = self.db.confirm_device_key_rotation(
                device_id, rotation_id, new_public_key
            )
        except Exception as exc:
            await self._send_connection_json(
                conn,
                {
                    "type": "device.key.rotate.error",
                    "request_id": request_id,
                    "error": str(exc),
                },
            )
            return
        row = self.db.get_device_auth_row(device_id)
        self.db.add_audit(
            user_id=str(row["owner_id"]) if row else "system",
            client_id="agent-gateway",
            device_id=device_id,
            tool="device.key.rotate.confirm",
            args_summary=json.dumps({"key_generation": generation}),
            execution_id=None,
            status="ok",
            duration_ms=0,
            exit_code=None,
            risk_class="critical",
        )
        await self._send_connection_json(
            conn,
            {
                "type": "device.key.rotate.ack",
                "request_id": request_id,
                "rotation_id": rotation_id,
                "key_generation": generation,
            },
        )

    async def _handle_output(self, device_id: str, msg: dict[str, Any]) -> None:
        execution_id = str(msg.get("execution_id", ""))
        job = self.jobs.get(execution_id)
        if not job or job.device_id != device_id:
            return
        text = str(msg.get("data", ""))
        raw_len = len(text.encode("utf-8", errors="replace"))
        job.observed_output_bytes += raw_len
        if job.output_bytes >= self.max_output_bytes:
            return
        remaining = self.max_output_bytes - job.output_bytes
        if raw_len > remaining:
            text = text.encode("utf-8", errors="replace")[:remaining].decode(
                "utf-8", errors="ignore"
            )
            raw_len = len(text.encode("utf-8", errors="replace"))
        job.output_bytes += raw_len
        if msg.get("stream") == "stderr":
            job.stderr_parts.append(text)
        else:
            job.stdout_parts.append(text)

    async def _handle_result(self, device_id: str, msg: dict[str, Any]) -> None:
        execution_id = str(msg.get("execution_id", ""))
        job = self.jobs.get(execution_id)
        if not job or job.device_id != device_id or job.future.done():
            return
        job.future.set_result(
            JobResult(
                execution_id=execution_id,
                status=str(msg.get("status", "error")),
                result=msg.get("result")
                if isinstance(msg.get("result"), dict)
                else None,
                exit_code=msg.get("exit_code")
                if isinstance(msg.get("exit_code"), int)
                else None,
                stdout="".join(job.stdout_parts),
                stderr="".join(job.stderr_parts),
                error=str(msg.get("error")) if msg.get("error") else None,
            )
        )

    async def dispatch(
        self,
        *,
        owner_id: str,
        device: dict[str, Any],
        tool: str,
        arguments: dict[str, Any],
        timeout_ms: int = 30000,
    ) -> JobResult:
        device_id = str(device["id"])
        async with self._lock:
            conn = self.connections.get(device_id)
        if not conn:
            raise RuntimeError("device_offline")
        execution_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        pending = PendingJob(
            execution_id=execution_id, device_id=device_id, future=loop.create_future()
        )
        self.jobs[execution_id] = pending
        self.db.create_job(execution_id, owner_id, device_id, tool)
        self.metrics.inc("commandcore_jobs_total")
        from .activity import ActivityEvent, argument_summary, notify, source

        activity = ActivityEvent(
            execution_id,
            str(uuid.uuid4()),
            device_id,
            str(device["display_name"]),
            tool,
            argument_summary(arguments),
            str(device["permission_profile"]),
            time.time(),
            source=dict(source.get()),
        )
        self.db.save_activity(activity.wire())
        await notify(activity.wire())
        payload = {
            "type": "job.request",
            "request_id": activity.request_id,
            "execution_id": execution_id,
            "protocol_version": AGENT_PROTOCOL_VERSION,
            "tool": tool,
            "arguments": arguments,
            "permission_profile": device["permission_profile"],
            "timeout_ms": timeout_ms,
            "activity": activity.wire(),
        }
        result = None
        try:
            try:
                async with conn.send_lock:
                    await conn.websocket.send_json(payload)
            except Exception:
                # The connection can disappear after lookup but before the frame
                # is written. Convert that transport race into the same durable
                # job result used when a running Agent disconnects, instead of
                # leaking an exception and leaving the DB job in `running`.
                result = JobResult(
                    execution_id=execution_id,
                    status="agent_disconnected",
                    result=None,
                    exit_code=None,
                    stdout="".join(pending.stdout_parts),
                    stderr="".join(pending.stderr_parts),
                    error="agent disconnected before job dispatch completed",
                )
                self.db.finish_job(
                    execution_id, result.status, result.exit_code, result.error
                )
                self.metrics.inc("commandcore_job_errors_total")
                return result
            try:
                result = await asyncio.wait_for(
                    pending.future, timeout=max(1.0, timeout_ms / 1000 + 5.0)
                )
            except asyncio.TimeoutError:
                try:
                    async with conn.send_lock:
                        await conn.websocket.send_json(
                            {"type": "job.cancel", "execution_id": execution_id}
                        )
                except Exception:
                    pass
                result = JobResult(
                    execution_id=execution_id,
                    status="timeout",
                    result=None,
                    exit_code=None,
                    stdout="".join(pending.stdout_parts),
                    stderr="".join(pending.stderr_parts),
                    error="server timeout waiting for agent",
                )
            self.db.finish_job(
                execution_id, result.status, result.exit_code, result.error
            )
            if result.status not in {"ok", "completed", "started"}:
                self.metrics.inc("commandcore_job_errors_total")
            return result
        finally:
            if result is not None:
                result.output_capture = {
                    "limit_bytes": self.max_output_bytes,
                    "observed_bytes": pending.observed_output_bytes,
                    "retained_bytes": pending.output_bytes,
                    "truncated": pending.observed_output_bytes > pending.output_bytes,
                    "transport_complete": result.status
                    in {"ok", "completed", "started"},
                }
            activity.finish(result)
            self.db.save_activity(activity.wire())
            await notify(activity.wire())
            self.jobs.pop(execution_id, None)
