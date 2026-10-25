"""Owner-scoped in-flight and historical activity without content or secrets."""

from __future__ import annotations

import time
import uuid
import secrets
import hashlib
import hmac
import re
import shlex
from datetime import datetime, timezone
from typing import Any

from .models import Principal
from .auth import scope_allows, STANDARD_SCOPE
from .activity_trace import safe_trace
from .activity_visibility import safe_path


# Only confirm effects explicitly represented by a successfully completed
# device tool. Shell, Git, or Docker side effects require separate evidence.
_CONFIRMED_EFFECTS = {
    "fs.write": "File written (new vs replaced is not established)",
    "fs.patch": "Patch applied to target file",
    "fs.delete": "Target deleted",
    "fs.move": "Target moved",
    "fs.copy": "Target copied",
    "transfer.upload": "Upload completed",
}
_SAFE_LABEL = re.compile(r"[A-Za-z0-9._:/@+-]{1,128}\Z")


def _workflow_hint(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return None
    # Never label a compound script as if it were a single known command.
    if any(c in value for c in (";", "|", "&", "$", "`", ">", "<", "\n", "\r")):
        return None
    try:
        parts = shlex.split(value)
    except ValueError:
        return None
    if not parts:
        return None
    known = {
        ("docker", "build"): "Docker image build",
        ("docker", "compose", "build"): "Docker Compose build",
        ("docker", "compose", "up"): "Docker Compose deployment",
        ("docker", "compose", "down"): "Docker Compose shutdown",
        ("docker", "ps"): "Docker container inspection",
        ("docker", "inspect"): "Docker inspection",
        ("npm", "run"): "npm task",
        ("npm", "test"): "JavaScript tests",
        ("pytest",): "Python tests",
        ("python", "-m", "pytest"): "Python tests",
        ("python3", "-m", "pytest"): "Python tests",
        ("cargo", "build"): "Rust build",
        ("cargo", "test"): "Rust tests",
        ("git", "status"): "Git status",
    }
    for prefix, label in sorted(known.items(), key=lambda item: -len(item[0])):
        if tuple(parts[: len(prefix)]) == prefix:
            return label
    return None


def _enrich_request(
    tool: str, args: dict[str, Any], detail: dict[str, Any]
) -> dict[str, Any]:
    # Safe fixed metadata only. Never keep argv, URLs, typed browser values,
    # shell flags, file contents, secrets, output or unbounded exception text.
    detail["category"] = (
        "File operation"
        if tool.startswith("fs.")
        else "Build / container"
        if tool.startswith("docker.")
        else "Service"
        if tool.startswith("services.")
        else "Package"
        if tool.startswith("package.")
        else "Git"
        if tool.startswith("git.")
        else "Process"
        if tool.startswith("process.")
        else "Command"
        if tool == "shell.exec"
        else "System"
        if tool.startswith("system.")
        else "Operation"
    )
    if tool.startswith(("docker.", "services.", "package.")):
        for key in (
            "container",
            "container_id",
            "image",
            "service",
            "action",
            "manager",
        ):
            value = args.get(key)
            if (
                isinstance(value, str)
                and _SAFE_LABEL.fullmatch(value)
                and safe_path(value.replace(":", "/"))
                not in (None, "[restricted path]")
            ):
                detail[key] = value
        if tool == "package.install" and isinstance(args.get("packages"), list):
            detail["package_count"] = min(1000, len(args["packages"]))
    if tool == "shell.exec":
        workflow = _workflow_hint(args.get("command"))
        if workflow:
            detail["workflow"] = workflow
        detail["effect_limit"] = (
            "Shell filesystem changes are not verified by this operation"
        )
    return detail


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


class LiveActivity:
    def __init__(self) -> None:
        self.active: dict[str, dict[str, Any]] = {}
        # Bounded, ephemeral per-process trace. Raw arguments, command output,
        # patch payloads and file contents are NEVER retained here.
        self.completed: dict[str, dict[str, Any]] = {}
        self._session_key = secrets.token_bytes(32)
        self._viewers: dict[str, dict[str, Any]] = {}

    def session_tag(self, host_session: str | None) -> str | None:
        if not isinstance(host_session, str) or not 1 <= len(host_session) <= 256:
            return None
        # The documented identifier is opaque. Hash it without assuming
        # UUID, URL, base64 or hexadecimal formatting.
        if any(ord(c) < 32 or ord(c) == 127 for c in host_session):
            return None
        return hmac.new(
            self._session_key, host_session.encode(), hashlib.sha256
        ).hexdigest()

    def _expire_viewers(self) -> None:
        now = time.time()
        for ref, row in list(self._viewers.items()):
            if now - row["used_at"] > 3600:
                self._viewers.pop(ref, None)
        while len(self._viewers) > 150:
            self._viewers.pop(next(iter(self._viewers)))

    def issue_viewer(
        self, principal: Principal, host_session: str | None
    ) -> dict[str, Any]:
        tag = self.session_tag(host_session)
        if (
            not tag
            or principal.auth_kind != "oauth2"
            or not principal.issuer
            or not principal.subject
            or not principal.client_id
        ):
            return {"session_available": False}
        self._expire_viewers()
        ref = secrets.token_urlsafe(24)
        self._viewers[ref] = {
            "issuer": principal.issuer,
            "owner": principal.subject,
            "client": principal.client_id,
            "session_tag": tag,
            "used_at": time.time(),
        }
        return {"session_available": True, "session_ref": ref}

    def resolve_viewer(self, principal: Principal, ref: str) -> str | None:
        self._expire_viewers()
        if (
            principal.auth_kind != "oauth2"
            or not principal.issuer
            or not principal.subject
            or not principal.client_id
            or not isinstance(ref, str)
            or len(ref) > 128
        ):
            return None
        row = self._viewers.get(ref)
        if not row or (row["issuer"], row["owner"], row["client"]) != (
            principal.issuer,
            principal.subject,
            principal.client_id,
        ):
            return None
        row["used_at"] = time.time()
        return row["session_tag"]

    def begin(
        self,
        principal: Principal,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        host_session: str | None = None,
    ) -> str:
        key = str(uuid.uuid4())
        self.active[key] = {
            "key": key,
            "owner": principal.subject,
            "issuer": principal.issuer,
            "client_id": principal.client_id,
            "session_tag": self.session_tag(host_session),
            "tool": tool,
            "detail": _enrich_request(tool, args or {}, safe_trace(tool, args or {})),
            "device_id": None,
            "started_epoch": time.time(),
        }
        return key

    def set_device(self, key: str | None, device_id: str) -> None:
        if key in self.active:
            self.active[key]["device_id"] = device_id

    def finish(
        self,
        key: str | None,
        *,
        status: str = "ok",
        execution_id: str | None = None,
        audit_id: int | None = None,
        exit_code: int | None = None,
        managed_process_id: str | None = None,
    ) -> None:
        if key:
            entry = self.active.pop(key, None)
            if entry is not None:
                entry["status"] = (
                    status
                    if status
                    in {"ok", "started", "completed", "error", "timeout", "canceled"}
                    else "error"
                )
                if type(exit_code) is int and exit_code != 0:
                    entry["status"] = "error"
                entry["exit_code"] = exit_code if type(exit_code) is int else None
                if (
                    entry["status"] in {"ok", "completed"}
                    and entry["tool"] in _CONFIRMED_EFFECTS
                ):
                    entry["detail"]["verified_effect"] = _CONFIRMED_EFFECTS[
                        entry["tool"]
                    ]
                # The agent returned this ID for a CommandCore-managed process.
                # Only the verified originating OAuth client may see it via detailed feed.
                # It is never guessed from an OS PID or command text.
                if (
                    entry["tool"] == "process.start"
                    and entry["status"] in {"ok", "started", "completed"}
                    and isinstance(managed_process_id, str)
                    and re.fullmatch(r"[0-9a-fA-F-]{36}", managed_process_id)
                ):
                    entry["detail"]["managed_process_id"] = managed_process_id
                entry["finished_epoch"] = time.time()
                entry["execution_id"] = execution_id
                entry["audit_id"] = audit_id if type(audit_id) is int else None
                self.completed[key] = entry
        self._expire_completed()

    def _expire_completed(self) -> None:
        now = time.time()
        for key, row in list(self.completed.items()):
            if now - row["finished_epoch"] > 900:
                self.completed.pop(key, None)
        while len(self.completed) > 120:
            self.completed.pop(next(iter(self.completed)))

    def snapshot(
        self,
        principal: Principal,
        audits: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        limit: int,
        *,
        include_details: bool = False,
        stable_summary: bool = False,
        panel_details: bool = False,
        device_filter: str | None = None,
        session_tag: str | None = None,
    ) -> dict[str, Any]:
        if type(include_details) is not bool or type(panel_details) is not bool:
            raise ValueError("Activity detail flags must be boolean")
        if (
            include_details
            and not panel_details
            and not (
                principal.auth_kind == "oauth2"
                and principal.issuer
                and principal.subject
                and principal.client_id
                and scope_allows(principal.scopes, STANDARD_SCOPE)
            )
        ):
            raise ValueError(
                "Activity details require verified STANDARD OAuth identity"
            )
        # The first-party dashboard may bridge OAuth clients only for the
        # SAME verified issuer/subject with STANDARD authority. MCP detailed
        # feeds retain their existing client boundary.
        if panel_details and not (
            principal.auth_kind == "oauth2-panel"
            and principal.issuer
            and principal.subject
            and scope_allows(principal.scopes, STANDARD_SCOPE)
        ):
            raise ValueError(
                "Activity details require verified STANDARD panel identity"
            )
        authorized = {
            d["id"]: d["display_name"] for d in devices if not d.get("revoked_at")
        }
        now = time.time()
        self._expire_completed()
        rows = []
        scoped_completed = []
        if (
            include_details
            or stable_summary
            or panel_details
            or session_tag is not None
        ):
            scoped_completed = [
                entry
                for entry in self.completed.values()
                if entry["owner"] == principal.subject
                and entry["issuer"] == principal.issuer
                and (
                    stable_summary
                    or panel_details
                    or entry["client_id"] == principal.client_id
                )
                and (
                    session_tag is None
                    or (
                        entry.get("session_tag") == session_tag
                        and entry["client_id"] == principal.client_id
                    )
                )
                and (not device_filter or entry["device_id"] == device_filter)
                and (not entry["device_id"] or entry["device_id"] in authorized)
            ]
        for e in self.active.values():
            if session_tag is not None and (
                e.get("session_tag") != session_tag
                or e["client_id"] != principal.client_id
            ):
                continue
            if e["owner"] != principal.subject or e["issuer"] != principal.issuer:
                continue
            if e["device_id"] and e["device_id"] not in authorized:
                continue
            if device_filter and e["device_id"] != device_filter:
                continue
            entry = {
                "id": e["key"],
                "device_id": e["device_id"],
                "execution_id": None,
                "tool": e["tool"],
                "status": "running",
                "device": authorized.get(e["device_id"], "Control plane"),
                "started_at": _iso(e["started_epoch"]),
                "duration_ms": max(0, int((now - e["started_epoch"]) * 1000)),
            }
            if panel_details or (
                include_details and e["client_id"] == principal.client_id
            ):
                entry["detail"] = e["detail"]
                entry["operation_id"] = e["key"]
            rows.append(entry)
        if (
            include_details
            or stable_summary
            or panel_details
            or session_tag is not None
        ):
            for e in scoped_completed:
                rows.append(
                    {
                        "id": e["key"] if stable_summary else "trace-" + e["key"],
                        "device_id": e["device_id"],
                        "execution_id": e.get("execution_id"),
                        "operation_id": e["key"],
                        "exit_code": e.get("exit_code"),
                        "finished_at": _iso(e["finished_epoch"]),
                        "tool": e["tool"],
                        "status": e["status"],
                        "device": authorized.get(e["device_id"], "Control plane"),
                        "started_at": _iso(e["started_epoch"]),
                        "duration_ms": max(
                            0, int((e["finished_epoch"] - e["started_epoch"]) * 1000)
                        ),
                        **(
                            {"detail": e["detail"]}
                            if panel_details
                            or (
                                include_details
                                and e["client_id"] == principal.client_id
                            )
                            else {}
                        ),
                    }
                )
        for e in audits:
            if session_tag is not None:
                break  # Durable audits have no verified conversation attribution.
            if str(e.get("tool", "")) in {
                "activity.feed",
                "activity.watch",
                "commandcore.watch",
                "browser.watch",
                "browser.frame",
            }:
                continue
            device_id = e.get("device_id")
            if device_id and device_id not in authorized:
                continue
            if (
                include_details
                or stable_summary
                or panel_details
                or session_tag is not None
            ):
                # Match by the exact SQLite audit-row ID rather than
                # execution ID, matching tool name, or a ±3-second timestamp.
                # Those heuristics can hide *unrelated* user operations
                # during fast, concurrent agent workflows.
                if any(
                    row.get("audit_id") is not None and row["audit_id"] == e.get("id")
                    for row in scoped_completed
                ):
                    continue
            if device_filter and device_id != device_filter:
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
                    "device_id": device_id,
                    "execution_id": e.get("execution_id"),
                    "tool": str(e.get("tool") or "operation"),
                    "status": status,
                    "device": authorized.get(device_id, "Control plane"),
                    "started_at": str(e.get("timestamp") or ""),
                    "duration_ms": dur if type(dur) is int and dur >= 0 else None,
                }
            )
        if stable_summary:
            for row in rows:
                row["result_summary"] = (
                    "Operation in progress; output omitted"
                    if row["status"] in {"running", "started"}
                    else "Operation " + row["status"] + "; output omitted"
                )
        rows.sort(key=lambda x: x["started_at"], reverse=True)
        return {
            "events": rows[: max(1, min(limit, 50))],
            "refreshed_at": _iso(now),
            "privacy": (
                "Owner-scoped, 15-minute in-memory operation metadata; "
                "validated command grammar or redacted structure only. "
                "No raw output, file contents or diff text. HTTPS origins only."
                if include_details or panel_details
                else "Only tool, device, time and status. No arguments or output."
            ),
        }
