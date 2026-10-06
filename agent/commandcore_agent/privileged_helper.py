from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import pwd
import secrets
import socket
import struct
import sys
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from . import __version__
from .executor import Executor
from .helper_client import DEFAULT_SECRET, DEFAULT_SOCKET, _canonical
from .local_policy import load_local_policy, normalize_profile
from .root_trust import check_root_directory, read_root_file

MAX_FRAME = 32 * 1024 * 1024
REPLAY_WINDOW_SECONDS = 60


def _peer_uid(writer: asyncio.StreamWriter) -> int | None:
    sock = writer.get_extra_info("socket")
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        raw = sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    except OSError:
        return None


def _load_secret(path: str) -> bytes:
    data = (
        read_root_file(path, secret=True)
        if os.geteuid() == 0
        else Path(path).read_bytes()
    ).strip()
    if len(data) < 32:
        raise RuntimeError("helper secret must contain at least 32 bytes")
    return data


def _safe_audit_value(value: Any, key: str | None = None) -> Any:
    lowered = (key or "").lower()
    if lowered in {"command", "data", "data_base64"} and isinstance(value, str):
        return {
            "redacted": True,
            "length": len(value),
            "sha256_16": hashlib.sha256(
                value.encode("utf-8", errors="replace")
            ).hexdigest()[:16],
        }
    if lowered == "patches" and isinstance(value, list):
        return {"redacted": True, "count": len(value)}
    if lowered == "env" and isinstance(value, dict):
        return {"redacted": True, "keys": sorted(str(k) for k in value.keys())[:50]}
    if isinstance(value, dict):
        return {
            k: (
                "[REDACTED]"
                if any(
                    x in k.lower()
                    for x in (
                        "token",
                        "secret",
                        "password",
                        "credential",
                        "private_key",
                    )
                )
                else _safe_audit_value(v, k)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_safe_audit_value(v) for v in value[:20]]
    if isinstance(value, str):
        return value[:300]
    return value


class HelperServer:
    def __init__(
        self,
        socket_path: str,
        secret_path: str,
        policy_path: str | None = None,
        audit_path: str | None = None,
    ):
        self.socket_path = socket_path
        self.secret_path = secret_path
        self.policy_path = policy_path
        self.audit_path = audit_path
        self.secret = _load_secret(secret_path)
        self.policy = {}
        self._refresh_policy()
        # The helper itself enforces its root-owned policy before invoking the
        # executor, so the executor must not re-read a potentially different
        # default policy path and accidentally reject an authorized request.
        self.executor = Executor(
            delegate_full_control=False, enforce_local_ceiling=False
        )
        self.seen_nonces: OrderedDict[str, float] = OrderedDict()
        self._audit_lock = asyncio.Lock()

    def _refresh_policy(self) -> None:
        if os.geteuid() == 0:
            try:
                policy = json.loads(
                    read_root_file(
                        self.policy_path or "/etc/commandcore/agent-policy.json"
                    )
                )
                if not isinstance(policy, dict):
                    raise ValueError("policy must be an object")
                self.policy = policy
            except (OSError, ValueError):
                self.policy = {
                    "configured_max_permission_profile": "READ_ONLY",
                    "policy_error": "untrusted_local_policy",
                }
        else:
            self.policy = load_local_policy(self.policy_path)

    def _allowed_uid(self, uid: int | None) -> bool:
        allowed = self.policy.get("allowed_helper_uids") or []
        if uid is None:
            return False
        return uid == 0 or uid in allowed

    def _verify(self, msg: dict[str, Any], uid: int | None) -> str | None:
        self._refresh_policy()
        if self.policy.get("policy_error"):
            return "untrusted_local_policy"
        if not self._allowed_uid(uid):
            return "peer_uid_not_authorized"
        try:
            ts = float(msg.get("timestamp"))
        except (TypeError, ValueError):
            return "missing_or_invalid_timestamp"
        now = time.time()
        if abs(now - ts) > REPLAY_WINDOW_SECONDS:
            return "request_timestamp_outside_replay_window"
        nonce = str(msg.get("nonce", ""))
        if len(nonce) < 16:
            return "invalid_nonce"
        while (
            self.seen_nonces
            and next(iter(self.seen_nonces.values())) < now - REPLAY_WINDOW_SECONDS
        ):
            self.seen_nonces.popitem(last=False)
        if nonce in self.seen_nonces:
            return "replayed_nonce"
        given = str(msg.get("mac", ""))
        expected = hmac.new(self.secret, _canonical(msg), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(given, expected):
            return "invalid_mac"
        self.seen_nonces[nonce] = now
        return None

    async def _write(
        self, writer: asyncio.StreamWriter, payload: dict[str, Any]
    ) -> None:
        writer.write(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            + b"\n"
        )
        await writer.drain()

    async def _audit(
        self,
        *,
        uid: int | None,
        action: str,
        execution_id: str | None,
        tool: str | None,
        status: str,
        duration_ms: int,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        if not self.audit_path:
            return
        record = {
            "timestamp": time.time(),
            "uid": uid,
            "action": action,
            "execution_id": execution_id,
            "tool": tool,
            "status": status,
            "duration_ms": duration_ms,
            "arguments": _safe_audit_value(arguments or {}),
        }
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        async with self._audit_lock:
            path = Path(self.audit_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(line)

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        uid = _peer_uid(writer)
        started = time.perf_counter()
        action = "unknown"
        execution_id = None
        tool = None
        arguments: dict[str, Any] = {}
        status = "error"
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=10)
            if not raw or len(raw) > MAX_FRAME:
                await self._write(
                    writer, {"type": "error", "error": "invalid_or_oversized_request"}
                )
                return
            msg = json.loads(raw)
            if not isinstance(msg, dict):
                raise ValueError("request must be an object")
            action = str(msg.get("action", ""))
            execution_id = (
                str(msg.get("execution_id")) if msg.get("execution_id") else None
            )
            tool = str(msg.get("tool")) if msg.get("tool") else None
            arguments = (
                msg.get("arguments") if isinstance(msg.get("arguments"), dict) else {}
            )
            error = self._verify(msg, uid)
            if error:
                await self._write(writer, {"type": "error", "error": error})
                return
            configured = normalize_profile(
                str(self.policy.get("configured_max_permission_profile", "STANDARD"))
            )
            if action == "probe":
                root_ready = configured == "FULL_CONTROL" and os.geteuid() == 0
                status = "ok"
                await self._write(
                    writer,
                    {
                        "type": "probe",
                        "available": root_ready,
                        "max_permission_profile": "FULL_CONTROL"
                        if root_ready
                        else ("READ_ONLY" if configured == "READ_ONLY" else "STANDARD"),
                        "helper_version": __version__,
                    },
                )
                return
            if configured != "FULL_CONTROL" or os.geteuid() != 0:
                await self._write(
                    writer,
                    {"type": "error", "error": "local_policy_denies_full_control"},
                )
                return
            if action == "cancel":
                if not execution_id:
                    await self._write(
                        writer, {"type": "error", "error": "execution_id_required"}
                    )
                    return
                await self.executor.cancel(execution_id)
                status = "ok"
                await self._write(
                    writer,
                    {
                        "type": "result",
                        "outcome": {
                            "status": "ok",
                            "result": {"cancel_requested": True},
                        },
                    },
                )
                return
            if action != "execute" or not execution_id or not tool:
                await self._write(writer, {"type": "error", "error": "invalid_action"})
                return
            if str(msg.get("permission_profile")) != "FULL_CONTROL":
                await self._write(
                    writer,
                    {"type": "error", "error": "helper_requires_full_control_profile"},
                )
                return

            async def output(stream: str, data: str) -> None:
                await self._write(
                    writer, {"type": "output", "stream": stream, "data": data}
                )

            outcome = await self.executor.execute(
                execution_id, "FULL_CONTROL", tool, arguments, output
            )
            status = str(outcome.get("status", "error"))
            await self._write(writer, {"type": "result", "outcome": outcome})
        except (asyncio.TimeoutError, json.JSONDecodeError, ValueError) as exc:
            try:
                await self._write(
                    writer, {"type": "error", "error": f"invalid_request: {exc}"}
                )
            except Exception:
                pass
        except Exception as exc:
            try:
                await self._write(
                    writer,
                    {
                        "type": "error",
                        "error": f"helper_internal_error: {type(exc).__name__}: {exc}",
                    },
                )
            except Exception:
                pass
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            await self._audit(
                uid=uid,
                action=action,
                execution_id=execution_id,
                tool=tool,
                status=status,
                duration_ms=duration_ms,
                arguments=arguments,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def serve(self) -> None:
        path = Path(self.socket_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        server = await asyncio.start_unix_server(
            self.handle, path=self.socket_path, limit=MAX_FRAME
        )
        os.chmod(self.socket_path, 0o660)
        group_name = os.getenv("COMMANDCORE_HELPER_SOCKET_GROUP", "commandcore")
        try:
            import grp

            gid = grp.getgrnam(group_name).gr_gid
            os.chown(self.socket_path, 0, gid)
        except (KeyError, PermissionError, OSError):
            pass
        async with server:
            await server.serve_forever()


def _write_initial_files(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        print("init-policy must run as root", file=sys.stderr)
        return 1
    try:
        uid = pwd.getpwnam(args.agent_user).pw_uid
    except KeyError:
        print(f"Agent user not found: {args.agent_user}", file=sys.stderr)
        return 1
    profile = normalize_profile(args.max_profile, "STANDARD")
    policy_path = Path(args.policy_file)
    secret_path = Path(args.secret_file)
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    check_root_directory(policy_path.parent)
    check_root_directory(secret_path.parent)
    policy = json.loads(read_root_file(policy_path)) if policy_path.exists() else {}
    if not isinstance(policy, dict):
        raise ValueError("Existing local policy must be an object")
    policy.update(configured_max_permission_profile=profile, allowed_helper_uids=[uid])
    if getattr(args, "update_public_key_b64", ""):
        policy["update_public_key_b64"] = str(args.update_public_key_b64).strip()
    origins = [
        str(x).strip().rstrip("/")
        for x in (getattr(args, "update_manifest_origin", None) or [])
        if str(x).strip()
    ]
    if origins:
        policy["update_manifest_origins"] = sorted(set(origins))
    policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    os.chown(policy_path, 0, 0)
    os.chmod(policy_path, 0o644)
    if secret_path.exists():
        read_root_file(secret_path, secret=True)
    else:
        descriptor = os.open(
            secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(secrets.token_bytes(48))
    try:
        import grp

        gid = grp.getgrnam(args.agent_user).gr_gid
    except KeyError:
        gid = 0
    os.chown(secret_path, 0, gid)
    os.chmod(secret_path, 0o640)
    print(
        json.dumps(
            {
                "policy_file": str(policy_path),
                "secret_file": str(secret_path),
                "max_profile": profile,
                "agent_uid": uid,
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="commandcore-helper", description="CommandCore privileged Linux helper"
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve")
    s.add_argument(
        "--socket", default=os.getenv("COMMANDCORE_HELPER_SOCKET", DEFAULT_SOCKET)
    )
    s.add_argument(
        "--secret-file", default=os.getenv("COMMANDCORE_HELPER_SECRET", DEFAULT_SECRET)
    )
    s.add_argument(
        "--policy-file",
        default=os.getenv(
            "COMMANDCORE_AGENT_POLICY", "/etc/commandcore/agent-policy.json"
        ),
    )
    s.add_argument(
        "--audit-file",
        default=os.getenv(
            "COMMANDCORE_HELPER_AUDIT", "/var/log/commandcore/helper-audit.jsonl"
        ),
    )
    i = sub.add_parser("init-policy")
    i.add_argument("--agent-user", default="commandcore")
    i.add_argument(
        "--max-profile",
        choices=["READ_ONLY", "STANDARD", "FULL_CONTROL"],
        default="STANDARD",
    )
    i.add_argument("--policy-file", default="/etc/commandcore/agent-policy.json")
    i.add_argument("--secret-file", default=DEFAULT_SECRET)
    i.add_argument(
        "--update-public-key-b64",
        default=os.getenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", ""),
        help="Trusted Ed25519 release public key stored in the root-owned local policy",
    )
    i.add_argument(
        "--update-manifest-origin",
        action="append",
        default=[],
        help="Allowed HTTPS origin for remote fleet manifests, e.g. https://updates.example.org",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "init-policy":
        return _write_initial_files(args)
    if args.command == "serve":
        server = HelperServer(
            args.socket, args.secret_file, args.policy_file, args.audit_file
        )
        try:
            asyncio.run(server.serve())
        except KeyboardInterrupt:
            return 0
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
