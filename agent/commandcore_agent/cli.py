from __future__ import annotations

import argparse
import asyncio
import time
import base64
import json
import getpass
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

import httpx
from websockets.exceptions import ConnectionClosed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from . import activity
from .network import ConnectionFailure, connect as connect_websocket
from .capabilities import CAPABILITIES
from .executor import Executor
from .helper_client import build_runtime_capabilities
from .local_policy import load_local_policy
from .update_lifecycle import (
    activate_staged,
    fetch_manifest,
    rollback_last_update,
    rollout_status,
    select_artifact,
    stage_artifact,
    verify_manifest,
)
from .runtime_health import default_health_path, write_health
from .state import (
    AgentState,
    begin_key_rotation,
    clear_pending_key,
    default_state_path,
    load,
    promote_pending_key,
    save,
)

AGENT_PROTOCOL_VERSION = "1"


def _new_keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_bytes).decode(), base64.b64encode(
        public_bytes
    ).decode()


def _private_from_b64(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(value, validate=True))


def enroll(args: argparse.Namespace) -> int:
    if args.token.startswith(("https://", "http://")):
        from .onboarding import enroll_url

        return enroll_url(args)
    if not args.control_url or not args.agent_url:
        print(
            "Legacy token enrollment requires --control-url and --agent-url.",
            file=sys.stderr,
        )
        return 2
    state_path = Path(args.state).expanduser() if args.state else default_state_path()
    if state_path.exists() and not args.force:
        print(
            f"Refusing to overwrite existing Agent identity: {state_path}",
            file=sys.stderr,
        )
        print(
            "Use --force only when intentionally replacing this device identity.",
            file=sys.stderr,
        )
        return 2
    private_b64, public_b64 = _new_keypair()
    hostname = socket.gethostname()
    display_name = args.name or hostname
    try:
        capabilities = asyncio.run(build_runtime_capabilities(CAPABILITIES))
    except Exception:
        capabilities = dict(CAPABILITIES)
    payload = {
        "token": args.token,
        "display_name": display_name,
        "hostname": hostname,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "agent_version": __version__,
        "protocol_version": AGENT_PROTOCOL_VERSION,
        "public_key_b64": public_b64,
        "capabilities": capabilities,
    }
    url = args.control_url.rstrip("/") + "/api/agent/enroll"
    try:
        response = httpx.post(url, json=payload, timeout=20, verify=not args.insecure)
        response.raise_for_status()
    except Exception as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        return 1
    data = response.json()
    state = AgentState(
        device_id=data["device_id"],
        device_token=data["device_token"],
        private_key_b64=private_b64,
        public_key_b64=public_b64,
        control_url=args.control_url.rstrip("/"),
        agent_url=args.agent_url,
        display_name=display_name,
    )
    save(state, state_path)
    print(
        json.dumps(
            {
                "device_id": state.device_id,
                "status": data.get("status"),
                "state_file": str(state_path),
            },
            indent=2,
        )
    )
    if data.get("status") == "pending":
        print(
            "Device is pending approval in CommandCore. Approve it before starting the Agent."
        )
    return 0


async def _send_json(ws: Any, lock: asyncio.Lock, payload: dict[str, Any]) -> None:
    async with lock:
        await ws.send(json.dumps(payload, separators=(",", ":")))


async def _heartbeat(ws: Any, lock: asyncio.Lock) -> None:
    while True:
        await asyncio.sleep(15)
        await _send_json(
            ws,
            lock,
            {
                "type": "heartbeat",
                "capabilities": await build_runtime_capabilities(CAPABILITIES),
            },
        )


async def _connect_authenticated(
    state: AgentState, private_key_b64: str
) -> tuple[Any, dict[str, Any]]:
    private = _private_from_b64(private_key_b64)
    headers = {"Authorization": f"Device {state.device_id}:{state.device_token}"}
    ws = await connect_websocket(state.agent_url, headers)
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        challenge = json.loads(raw)
        if (
            challenge.get("type") != "challenge"
            or str(challenge.get("protocol_version")) != AGENT_PROTOCOL_VERSION
        ):
            raise RuntimeError("invalid server challenge or protocol mismatch")
        nonce = str(challenge["nonce"])
        message = f"commandcore-agent-auth-v1\n{state.device_id}\n{nonce}".encode()
        signature = base64.b64encode(private.sign(message)).decode()
        runtime_capabilities = await build_runtime_capabilities(CAPABILITIES)
        await ws.send(
            json.dumps(
                {
                    "type": "hello",
                    "device_id": state.device_id,
                    "protocol_version": AGENT_PROTOCOL_VERSION,
                    "agent_version": __version__,
                    "capabilities": runtime_capabilities,
                    "signature": signature,
                },
                separators=(",", ":"),
            )
        )
        ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if ack.get("type") != "hello.ack":
            raise RuntimeError("stage=authentication: Agent authentication rejected")
        return ws, ack
    except Exception as exc:
        await ws.close()
        failure = ConnectionFailure("authentication", "challenge/hello exchange failed")
        failure.rcvd = getattr(exc, "rcvd", None)
        raise failure from exc


def _promote_if_pending_authenticated(
    state: AgentState, state_path: Path, ack: dict[str, Any], used_pending: bool
) -> None:
    if not used_pending:
        return
    generation = int(ack.get("key_generation") or state.key_generation + 1)
    promote_pending_key(state, key_generation=generation)
    save(state, state_path)


async def run_agent(args: argparse.Namespace) -> int:
    state_path = Path(args.state).expanduser() if args.state else default_state_path()
    state = load(state_path)
    activity.register_secrets(
        [state.device_token, state.private_key_b64, state.pending_private_key_b64]
    )
    activity.register_secrets(
        v for k, v in os.environ.items() if activity.SECRET_KEY.search(k)
    )
    executor = Executor(
        max_transfer_bytes=int(
            os.getenv("COMMANDCORE_AGENT_MAX_TRANSFER_BYTES", str(10 * 1024 * 1024))
        )
    )
    backoff = 1.0
    prefer_pending = bool(state.pending_private_key_b64)
    while True:
        ws = None
        try:
            used_pending = bool(prefer_pending and state.pending_private_key_b64)
            selected_key = (
                state.pending_private_key_b64 if used_pending else state.private_key_b64
            )
            ws, ack = await _connect_authenticated(state, selected_key)
            _promote_if_pending_authenticated(state, state_path, ack, used_pending)
            prefer_pending = False
            health_path = default_health_path(state_path)
            write_health(
                health_path,
                version=__version__,
                device_id=state.device_id,
                protocol_version=AGENT_PROTOCOL_VERSION,
                key_generation=state.key_generation,
                connected=True,
                implementation="python",
            )
            try:
                send_lock = asyncio.Lock()
                activity.emit(
                    "CONNECTION", {"status": "connected", "device_id": state.device_id}
                )
                backoff = 1.0
                hb = asyncio.create_task(_heartbeat(ws, send_lock))
                running_tasks: dict[str, asyncio.Task[Any]] = {}

                async def handle_job(msg: dict[str, Any]) -> None:
                    execution_id = str(msg["execution_id"])
                    tool = str(msg["tool"])
                    arguments = (
                        msg.get("arguments")
                        if isinstance(msg.get("arguments"), dict)
                        else {}
                    )
                    profile = str(msg.get("permission_profile", "READ_ONLY"))
                    started_at = time.monotonic()
                    activity.emit("REQUEST", activity.request(msg))
                    streams: dict[str, str] = {}
                    counts: dict[str, int] = {}
                    seq = 0

                    async def output(stream: str, data: str) -> None:
                        nonlocal seq
                        seq += 1
                        if stream in {"stdout", "stderr"}:
                            counts[stream] = counts.get(stream, 0) + len(data.encode())
                            remaining = max(0, 16384 - len(streams.get(stream, "")))
                            streams[stream] = streams.get(stream, "") + data[:remaining]
                        await _send_json(
                            ws,
                            send_lock,
                            {
                                "type": "job.output",
                                "execution_id": execution_id,
                                "stream": stream,
                                "seq": seq,
                                "data": data,
                            },
                        )

                    try:
                        outcome = await executor.execute(
                            execution_id, profile, tool, arguments, output
                        )
                    except asyncio.CancelledError:
                        activity.emit(
                            "RESULT",
                            activity.result(
                                msg,
                                {"status": "cancelled"},
                                int((time.monotonic() - started_at) * 1000),
                                streams,
                            ),
                        )
                        raise
                    except Exception:
                        activity.emit(
                            "RESULT",
                            activity.result(
                                msg,
                                {"status": "error", "error": "executor failure"},
                                int((time.monotonic() - started_at) * 1000),
                                streams,
                            ),
                        )
                        raise
                    preview = (
                        {
                            **streams,
                            **{f"{k}_bytes": v for k, v in counts.items()},
                            "truncated": any(
                                n > activity.PREVIEW for n in counts.values()
                            ),
                        }
                        if counts
                        else None
                    )
                    activity.emit(
                        "RESULT",
                        activity.result(
                            msg,
                            outcome,
                            int((time.monotonic() - started_at) * 1000),
                            preview,
                        ),
                    )
                    payload = {
                        "type": "job.result",
                        "execution_id": execution_id,
                        **outcome,
                    }
                    result = payload.get("result")
                    if (
                        isinstance(result, dict)
                        and "exit_code" in result
                        and "exit_code" not in payload
                    ):
                        payload["exit_code"] = result.get("exit_code")
                    if outcome.get("status") == "timeout" and "exit_code" in outcome:
                        payload["exit_code"] = outcome.get("exit_code")
                    await _send_json(ws, send_lock, payload)

                try:
                    async for raw_msg in ws:
                        msg = json.loads(raw_msg)
                        if msg.get("type") == "job.request":
                            eid = str(msg.get("execution_id"))
                            task = asyncio.create_task(handle_job(msg))
                            running_tasks[eid] = task
                            task.add_done_callback(
                                lambda _t, e=eid: running_tasks.pop(e, None)
                            )
                        elif msg.get("type") == "job.cancel":
                            eid = str(msg.get("execution_id"))
                            await executor.cancel(eid)
                            # Let the handler observe process termination and emit a final job.result.
                finally:
                    hb.cancel()
                    await asyncio.gather(hb, return_exceptions=True)
                    if (
                        getattr(ws, "close_code", None) in {4001, 4002, 4401, 4403}
                        and load_local_policy().get("stop_managed_jobs_on_revocation")
                        is True
                    ):
                        await executor.cancel_all()
                    else:
                        await executor.cancel_requests()
                    tasks = list(running_tasks.values())
                    for task in tasks:
                        task.cancel()
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                if ws is not None:
                    await ws.close()
                try:
                    write_health(
                        default_health_path(state_path),
                        version=__version__,
                        device_id=state.device_id,
                        protocol_version=AGENT_PROTOCOL_VERSION,
                        key_generation=state.key_generation,
                        connected=False,
                        implementation="python",
                        detail="disconnected",
                    )
                except Exception:
                    pass
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            received_close = getattr(exc, "rcvd", None)
            rejected_status = getattr(
                getattr(exc, "response", None), "status_code", None
            )
            if (
                getattr(received_close, "code", None) in {4401, 4403}
                or rejected_status in {401, 403}
            ) and load_local_policy().get("stop_managed_jobs_on_revocation") is True:
                await executor.cancel_all()
            if state.pending_private_key_b64:
                # A crash can happen after server commit but before local promotion,
                # or before commit. Alternate pending/active proofs until one is
                # accepted, then converge the local state from hello.ack.
                prefer_pending = not prefer_pending
            stage = "stage=established: " if isinstance(exc, ConnectionClosed) else ""
            activity.emit(
                "CONNECTION",
                {
                    "status": "reconnecting",
                    "reason": "connection failed",
                    "retry_in_seconds": backoff,
                },
            )
            print(
                f"Agent connection error: {stage}{exc}; reconnecting in {backoff:.0f}s",
                file=sys.stderr,
                flush=True,
            )
            if args.once:
                await executor.cancel_all()
                return 1
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)


async def _rotate_key_async(args: argparse.Namespace) -> int:
    state_path = Path(args.state).expanduser() if args.state else default_state_path()
    try:
        state = load(state_path)
    except Exception as exc:
        print(f"No valid Agent state: {exc}", file=sys.stderr)
        return 1

    # Recovery path: if a previous rotation committed on the server before the
    # final local save, the pending key authenticates and can be promoted safely.
    if state.pending_private_key_b64:
        try:
            ws, ack = await _connect_authenticated(state, state.pending_private_key_b64)
        except Exception:
            ws = None
        else:
            await ws.close()
            promote_pending_key(
                state,
                key_generation=int(
                    ack.get("key_generation") or state.key_generation + 1
                ),
            )
            save(state, state_path)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "device_id": state.device_id,
                        "key_generation": state.key_generation,
                        "recovered": True,
                    },
                    indent=2,
                )
            )
            return 0

    try:
        ws, ack = await _connect_authenticated(state, state.private_key_b64)
    except Exception as exc:
        print(f"Device-key rotation authentication failed: {exc}", file=sys.stderr)
        return 1
    try:
        # Resume a prepared rotation if local pending state survived a disconnect.
        if (
            state.pending_private_key_b64
            and state.pending_public_key_b64
            and state.pending_rotation_id
        ):
            new_private = _private_from_b64(state.pending_private_key_b64)
            confirm_msg = f"commandcore-key-rotation-confirm-v1\n{state.device_id}\n{state.pending_rotation_id}".encode()
            await ws.send(
                json.dumps(
                    {
                        "type": "device.key.rotate.confirm",
                        "request_id": os.urandom(8).hex(),
                        "rotation_id": state.pending_rotation_id,
                        "new_signature": base64.b64encode(
                            new_private.sign(confirm_msg)
                        ).decode(),
                    },
                    separators=(",", ":"),
                )
            )
        else:
            private_b64, public_b64 = _new_keypair()
            new_private = _private_from_b64(private_b64)
            nonce = str(ack.get("key_rotation_nonce") or "")
            if not nonce:
                raise RuntimeError("server_does_not_support_key_rotation")
            proof = f"commandcore-key-rotation-prepare-v1\n{state.device_id}\n{nonce}\n{public_b64}".encode()
            old_private = _private_from_b64(state.private_key_b64)
            request_id = os.urandom(8).hex()
            await ws.send(
                json.dumps(
                    {
                        "type": "device.key.rotate.prepare",
                        "request_id": request_id,
                        "new_public_key_b64": public_b64,
                        "old_signature": base64.b64encode(
                            old_private.sign(proof)
                        ).decode(),
                        "new_signature": base64.b64encode(
                            new_private.sign(proof)
                        ).decode(),
                    },
                    separators=(",", ":"),
                )
            )
            prepared = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            if prepared.get("type") != "device.key.rotate.prepared":
                raise RuntimeError(f"key rotation prepare rejected: {prepared}")
            begin_key_rotation(
                state,
                private_key_b64=private_b64,
                public_key_b64=public_b64,
                rotation_id=str(prepared["rotation_id"]),
            )
            save(state, state_path)
            confirm_msg = f"commandcore-key-rotation-confirm-v1\n{state.device_id}\n{state.pending_rotation_id}".encode()
            await ws.send(
                json.dumps(
                    {
                        "type": "device.key.rotate.confirm",
                        "request_id": os.urandom(8).hex(),
                        "rotation_id": state.pending_rotation_id,
                        "new_signature": base64.b64encode(
                            new_private.sign(confirm_msg)
                        ).decode(),
                    },
                    separators=(",", ":"),
                )
            )

        confirmed = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if confirmed.get("type") != "device.key.rotate.ack":
            # If the server expired/cleared a prepared rotation while the local
            # machine was offline, discard only the pending candidate. The
            # still-active old identity remains valid, so a fresh rotation can
            # begin immediately without re-enrollment or manual state editing.
            error = str(confirmed.get("error") or "")
            if state.pending_private_key_b64 and error in {
                "key_rotation_not_pending",
                "key_rotation_expired",
            }:
                clear_pending_key(state)
                save(state, state_path)
                await ws.close()
                return await _rotate_key_async(args)
            raise RuntimeError(f"key rotation confirmation rejected: {confirmed}")
        promote_pending_key(state, key_generation=int(confirmed["key_generation"]))
        save(state, state_path)
        print(
            json.dumps(
                {
                    "ok": True,
                    "device_id": state.device_id,
                    "key_generation": state.key_generation,
                },
                indent=2,
            )
        )
        return 0
    except Exception as exc:
        # Intentionally keep pending state for deterministic recovery/resume.
        print(f"Device-key rotation incomplete: {exc}", file=sys.stderr)
        return 1
    finally:
        await ws.close()


def rotate_key(args: argparse.Namespace) -> int:
    return asyncio.run(_rotate_key_async(args))


def _update_public_key(args: argparse.Namespace) -> str:
    value = (
        args.public_key or os.getenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "")
    ).strip()
    if not value:
        raise ValueError(
            "trusted update public key required (--public-key or COMMANDCORE_UPDATE_PUBLIC_KEY_B64)"
        )
    return value


def update_check(args: argparse.Namespace) -> int:
    try:
        manifest = fetch_manifest(
            args.manifest, allow_insecure_http=args.allow_insecure_http
        )
        verify_manifest(manifest, _update_public_key(args))
        artifact = select_artifact(
            manifest, target_platform=args.platform, architecture=args.architecture
        )
    except Exception as exc:
        print(f"Update check failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "current_version": __version__,
                "available_version": manifest["version"],
                "signing_key_id": manifest.get("signing_key_id"),
                "artifact": {
                    k: artifact.get(k)
                    for k in ("platform", "architecture", "filename", "sha256", "size")
                },
                "note": "Signature and metadata verified. No binary was installed.",
            },
            indent=2,
        )
    )
    return 0


def update_stage(args: argparse.Namespace) -> int:
    try:
        manifest = fetch_manifest(
            args.manifest, allow_insecure_http=args.allow_insecure_http
        )
        verify_manifest(manifest, _update_public_key(args))
        artifact = select_artifact(
            manifest, target_platform=args.platform, architecture=args.architecture
        )
        root = (
            Path(args.stage_dir).expanduser()
            if args.stage_dir
            else default_state_path().parent / "updates"
        )
        result = stage_artifact(
            manifest,
            artifact,
            root=root,
            allow_insecure_http=args.allow_insecure_http,
            current_version=__version__,
            allow_downgrade=args.allow_downgrade,
        )
    except Exception as exc:
        print(f"Update staging failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                **result,
                "note": "Artifact staged only; activation requires an explicit local administrator step.",
            },
            indent=2,
        )
    )
    return 0


def update_activate(args: argparse.Namespace) -> int:
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "Update activation must run as root/local administrator.", file=sys.stderr
        )
        return 2
    try:
        result = activate_staged(
            Path(args.stage_metadata).expanduser(),
            _update_public_key(args),
            install_root=Path(args.install_root).expanduser(),
            health_file=Path(args.health_file).expanduser(),
            service_name=args.service,
            health_timeout=float(args.health_timeout),
            target_platform=args.platform,
            architecture=args.architecture,
            allow_downgrade=args.allow_downgrade,
        )
    except Exception as exc:
        print(f"Update activation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, indent=2))
    return 0


def update_rollback(args: argparse.Namespace) -> int:
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Update rollback must run as root/local administrator.", file=sys.stderr)
        return 2
    try:
        result = rollback_last_update(
            install_root=Path(args.install_root).expanduser(),
            health_file=Path(args.health_file).expanduser(),
            service_name=args.service,
            health_timeout=float(args.health_timeout),
        )
    except Exception as exc:
        print(f"Update rollback failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, indent=2))
    return 0


def update_status(args: argparse.Namespace) -> int:
    try:
        result = rollout_status(Path(args.install_root).expanduser())
    except Exception as exc:
        print(f"Update status failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def set_token(args: argparse.Namespace) -> int:
    state_path = Path(args.state).expanduser() if args.state else default_state_path()
    try:
        state = load(state_path)
    except Exception as exc:
        print(f"No valid Agent state: {exc}", file=sys.stderr)
        return 1
    if args.stdin:
        token = sys.stdin.readline().strip()
    else:
        token = getpass.getpass("New CommandCore device token: ").strip()
    if len(token) < 20:
        print("Refusing suspiciously short device token.", file=sys.stderr)
        return 2
    state.device_token = token
    save(state, state_path)
    print(
        json.dumps(
            {
                "ok": True,
                "device_id": state.device_id,
                "state_file": str(state_path),
                "note": "Restart the Agent service to use the new token.",
            },
            indent=2,
        )
    )
    return 0


def show_status(args: argparse.Namespace) -> int:
    path = Path(args.state).expanduser() if args.state else default_state_path()
    try:
        state = load(path)
    except Exception as exc:
        print(f"No valid Agent state: {exc}", file=sys.stderr)
        return 1
    try:
        runtime_capabilities = asyncio.run(build_runtime_capabilities(CAPABILITIES))
    except Exception:
        runtime_capabilities = dict(CAPABILITIES)
    print(
        json.dumps(
            {
                "device_id": state.device_id,
                "display_name": state.display_name,
                "control_url": state.control_url,
                "agent_url": state.agent_url,
                "state_file": str(path),
                "agent_version": __version__,
                "protocol_version": AGENT_PROTOCOL_VERSION,
                "key_generation": state.key_generation,
                "key_rotation_pending": bool(state.pending_private_key_b64),
                "local_max_permission_profile": runtime_capabilities.get(
                    "local_max_permission_profile"
                ),
                "configured_max_permission_profile": runtime_capabilities.get(
                    "configured_max_permission_profile"
                ),
                "privileged_helper": runtime_capabilities.get(
                    "privileged_helper", False
                ),
                "privileged_helper_version": runtime_capabilities.get(
                    "privileged_helper_version"
                ),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="commandcore-agent", description="CommandCore Agent"
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    full = sub.add_parser(
        "enable-full-control", help="Locally enable an installed Linux root helper"
    )
    full.add_argument("--agent-user", default="commandcore")
    full.add_argument(
        "--acknowledge-root-access",
        action="store_true",
        help="Explicit local automation acknowledgement",
    )
    sub.add_parser(
        "disable-full-control",
        help="Locally lower authority and stop the Linux root helper",
    )

    e = sub.add_parser("enroll", help="Enroll this machine with a one-time token")
    e.add_argument("token")
    e.add_argument("--control-url", help="API origin for legacy token enrollment")
    e.add_argument("--agent-url", help="WebSocket URL for legacy token enrollment")
    e.add_argument(
        "--no-connect",
        action="store_true",
        help="Enroll then exit; installer starts the service",
    )
    e.add_argument("--name", help="Display name (defaults to hostname)")
    e.add_argument("--state", help="Override Agent state file")
    e.add_argument(
        "--force", action="store_true", help="Replace an existing Agent identity"
    )
    e.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification for local development only",
    )

    r = sub.add_parser("run", help="Connect and serve CommandCore jobs")
    r.add_argument("--state", help="Override Agent state file")
    r.add_argument(
        "--once",
        action="store_true",
        help="Exit instead of reconnecting after an error (testing)",
    )

    s = sub.add_parser("status", help="Show local Agent identity/configuration")
    s.add_argument("--state", help="Override Agent state file")

    a = sub.add_parser(
        "activity", help="Watch the sanitized local AI execution timeline"
    )
    a.add_argument("--last", type=int)
    a.add_argument("--errors", action="store_true")
    a.add_argument("--json", action="store_true")
    a.add_argument("--service")

    uc = sub.add_parser(
        "update-check",
        help="Verify a signed Agent update manifest without installing it",
    )
    uc.add_argument("--manifest", required=True, help="HTTPS URL of update manifest v1")
    uc.add_argument(
        "--public-key",
        help="Trusted Ed25519 release public key (base64); prefer environment/config in automation",
    )
    uc.add_argument("--platform", help="Override target platform for validation/tests")
    uc.add_argument(
        "--architecture", help="Override target architecture for validation/tests"
    )
    uc.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow loopback HTTP only for development tests",
    )

    us = sub.add_parser(
        "update-stage",
        help="Verify and download an update into a versioned staging directory",
    )
    us.add_argument("--manifest", required=True, help="HTTPS URL of update manifest v1")
    us.add_argument("--public-key", help="Trusted Ed25519 release public key (base64)")
    us.add_argument("--stage-dir", help="Override staging root")
    us.add_argument("--platform", help="Override target platform")
    us.add_argument("--architecture", help="Override target architecture")
    us.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow loopback HTTP only for development tests",
    )
    us.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="Explicitly stage an older/equal signed release (local recovery only)",
    )

    ua = sub.add_parser(
        "update-activate",
        help="Activate a verified standalone Agent release with automatic health rollback",
    )
    ua.add_argument("--stage-metadata", required=True, help="Path to staged stage.json")
    ua.add_argument("--public-key", help="Trusted Ed25519 release public key (base64)")
    ua.add_argument(
        "--install-root",
        default="/opt/commandcore-agent",
        help="Versioned Agent install root",
    )
    ua.add_argument(
        "--health-file",
        default="/run/commandcore-agent/health.json",
        help="Authenticated runtime health marker",
    )
    ua.add_argument(
        "--service", default="commandcore-agent", help="systemd service name"
    )
    ua.add_argument("--health-timeout", type=float, default=45.0)
    ua.add_argument("--platform", help="Override target platform")
    ua.add_argument("--architecture", help="Override target architecture")
    ua.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="Explicitly activate an older/equal signed release (local recovery only)",
    )

    ur = sub.add_parser(
        "update-rollback", help="Roll back the last committed native Agent release"
    )
    ur.add_argument("--install-root", default="/opt/commandcore-agent")
    ur.add_argument("--health-file", default="/run/commandcore-agent/health.json")
    ur.add_argument("--service", default="commandcore-agent")
    ur.add_argument("--health-timeout", type=float, default=45.0)

    ust = sub.add_parser("update-status", help="Show local Agent rollout state")
    ust.add_argument("--install-root", default="/opt/commandcore-agent")

    k = sub.add_parser(
        "rotate-key",
        help="Rotate the durable Ed25519 device identity without re-enrollment",
    )
    k.add_argument("--state", help="Override Agent state file")

    t = sub.add_parser(
        "set-token",
        help="Replace the locally stored device token after server-side rotation",
    )
    t.add_argument(
        "--stdin",
        action="store_true",
        help="Read the new token from stdin instead of a hidden prompt",
    )
    t.add_argument("--state", help="Override Agent state file")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command in {"enable-full-control", "disable-full-control"}:
        from .full_control import configure

        return configure(
            args.command == "enable-full-control",
            getattr(args, "agent_user", "commandcore"),
            getattr(args, "acknowledge_root_access", False),
        )
    if args.command == "enroll":
        return enroll(args)
    if args.command == "run":
        return asyncio.run(run_agent(args))
    if args.command == "status":
        return show_status(args)
    if args.command == "activity":
        return activity.watch(args)
    if args.command == "update-check":
        return update_check(args)
    if args.command == "update-stage":
        return update_stage(args)
    if args.command == "update-activate":
        return update_activate(args)
    if args.command == "update-rollback":
        return update_rollback(args)
    if args.command == "update-status":
        return update_status(args)
    if args.command == "rotate-key":
        return rotate_key(args)
    if args.command == "set-token":
        return set_token(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
