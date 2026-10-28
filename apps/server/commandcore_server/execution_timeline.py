"""Conversation-scoped, bounded Live Execution Timeline.

Not a general audit/logging database. No long-term raw credentials, argv or
unbounded output. Every read is bound to verified issuer/subject/client/session,
STANDARD OAuth scope and *current* device grants. This module never reads the
OS, infers paths, executes commands, or changes permissions.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import re
import time
import uuid
from typing import Any

from .activity_visibility import safe_operation_detail
from .auth import STANDARD_SCOPE, scope_allows
from .models import Principal

_TERMINAL_TOOLS = {"shell.exec", "process.start", "process.output"}
_FILE_TOOLS = {
    "fs.write",
    "fs.patch",
    "fs.copy",
    "fs.move",
    "fs.delete",
    "git.diff",
    "git.run",
}
# Default-deny for printing raw output. Explicitly structured, non-shell-interpreted
# read-only commands only. This is display policy, not execution permission.
_SAFE_OUTPUT_COMMANDS = {
    "hostname",
    "pwd",
    "uname",
    "uname -sr",
    "uname -m",
    "whoami",
    "date",
}
_SECRET_PATTERN = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+)"
)
_ALLOWED_STATUSES = {
    "running",
    "ok",
    "completed",
    "error",
    "timeout",
    "canceled",
    "started",
}
_MAX_EVENTS = 512
_MAX_AGE = 900
_MAX_CHUNK = 1024
_MAX_OUTPUT = 8192


def _safe_display(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    metadata = safe_operation_detail(tool, args)
    if tool not in _TERMINAL_TOOLS:
        return {
            "path": metadata.get("path")
            or metadata.get("source")
            or metadata.get("destination"),
            "effect": "attempted_write"
            if metadata.get("effect") == "write"
            else "read",
            "patch_count": metadata.get("patch_count"),
            "diff": (
                "Patch requested; file contents hidden."
                if tool == "fs.patch"
                else "Diff content requires a separate authorized read."
            ),
        }
    command_name = metadata.get("command_name", "[hidden]")
    raw = args.get("command")
    # No raw args in event history by default; only full names for strictly
    # allowlisted zero-argument, simple read-only commands without caller
    # environment or working-directory overrides that can change resolution.
    is_safe = (
        tool in {"shell.exec", "process.start"}
        and isinstance(raw, str)
        and args.get("env") in (None, {})
        and args.get("cwd") in (None, "")
        and raw.strip() in _SAFE_OUTPUT_COMMANDS
    )
    return {
        "command": raw.strip() if is_safe else command_name,
        "output_policy": "bounded_visible" if is_safe else "hidden",
    }


def _sanitized_chunk(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = "".join(
        char
        for char in value[: _MAX_CHUNK + 1]
        if char == "\n" or char == "\t" or ord(char) >= 32
    )
    return _SECRET_PATTERN.sub("[REDACTED]", text)


@dataclass
class _Row:
    operation_id: str
    issuer: str
    subject: str
    client_id: str
    session_tag: str
    tool: str
    started: float
    device_id: str | None = None
    status: str = "running"
    summary: dict[str, Any] = field(default_factory=dict)
    exit_code: int | None = None
    duration_ms: int | None = None
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False
    pending: dict[str, str] = field(default_factory=dict)
    discarding: set[str] = field(default_factory=set)
    unreliable_streams: set[str] = field(default_factory=set)
    finished: float | None = None
    last_seq: int = 0


class LiveExecutionTimeline:
    """One in-memory sequenced event stream, scoped to the same OAuth conversation."""

    def __init__(self, session_tag, *, clock=time.time):
        self._session_tag = session_tag
        self._clock = clock
        self._sequences: dict[tuple[str, str, str, str], tuple[int, float]] = {}
        self._rows: dict[str, _Row] = {}
        self._events: deque[tuple[float, dict[str, Any]]] = deque()
        self._managed_processes: dict[str, str] = {}
        self._process_offsets: dict[tuple[str, str], int] = {}

    def _identity(
        self, principal: Principal, session: str | None
    ) -> tuple[str, str, str, str] | None:
        if not (
            principal.auth_kind == "oauth2"
            and principal.subject
            and principal.issuer
            and principal.client_id not in ("", "unknown", "oauth-client")
            and scope_allows(principal.scopes, STANDARD_SCOPE)
        ):
            return None
        tag = self._session_tag(session)
        if not tag:
            return None
        return principal.issuer, principal.subject, principal.client_id, tag

    def _expire(self) -> None:
        now = self._clock()
        while self._events and now - self._events[0][0] > _MAX_AGE:
            self._events.popleft()
        for key, row in tuple(self._rows.items()):
            if (
                now - (row.finished if row.finished is not None else row.started)
                > _MAX_AGE
            ):
                self._rows.pop(key, None)
        self._managed_processes = {
            process_id: op
            for process_id, op in self._managed_processes.items()
            if op in self._rows
        }
        self._process_offsets = {
            key: pos
            for key, pos in self._process_offsets.items()
            if key[0] in self._managed_processes
        }
        while len(self._rows) > _MAX_EVENTS:
            self._rows.pop(next(iter(self._rows)))
        while len(self._events) > _MAX_EVENTS:
            self._events.popleft()
        active = {
            (row.issuer, row.subject, row.client_id, row.session_tag)
            for row in self._rows.values()
        }
        for identity, (_, last_used) in tuple(self._sequences.items()):
            if identity not in active and now - last_used > 3600:
                self._sequences.pop(identity, None)
        # Active rows are already bounded. Evict only inactive identities,
        # preserving their cursor for at least as long as the viewer lifetime.
        for identity in sorted(
            self._sequences, key=lambda key: self._sequences[key][1]
        ):
            if len(self._sequences) <= 4096:
                break
            if identity not in active:
                self._sequences.pop(identity, None)

    def _emit(self, row: _Row, kind: str, **data: Any) -> None:
        identity = (row.issuer, row.subject, row.client_id, row.session_tag)
        sequence = self._sequences.get(identity, (0, 0))[0] + 1
        self._sequences[identity] = (sequence, self._clock())
        row.last_seq = sequence
        event = {
            "seq": sequence,
            "operation_id": row.operation_id,
            "tool": row.tool,
            "device_id": row.device_id,
            "kind": kind,
            "status": row.status,
            "at": self._clock(),
            **data,
        }
        self._events.append((event["at"], event))
        self._expire()

    def begin(
        self,
        principal: Principal,
        host_session: str | None,
        operation_id: str,
        tool: str,
        args: dict[str, Any] | None = None,
    ) -> bool:
        identity = self._identity(principal, host_session)
        if identity is None or not isinstance(operation_id, str):
            return False
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                return False
        except (ValueError, TypeError):
            return False
        if operation_id in self._rows:
            return False
        self._expire()
        row = _Row(
            operation_id,
            *identity,
            tool,
            self._clock(),
            summary=_safe_display(tool, args or {}),
        )
        self._rows[operation_id] = row
        self._emit(row, "started", summary=row.summary)
        return True

    def device(self, operation_id: str | None, device_id: str) -> None:
        row = self._rows.get(operation_id or "")
        if row and isinstance(device_id, str) and device_id:
            row.device_id = device_id
            self._emit(row, "device")

    def attach_process(self, operation_id: str | None, process_id: str) -> None:
        row = self._rows.get(operation_id or "")
        if (
            row
            and row.tool == "process.start"
            and row.status in {"ok", "started", "completed"}
        ):
            if isinstance(process_id, str) and len(process_id) == 36:
                self._managed_processes[process_id] = row.operation_id

    def output(
        self,
        operation_id: str | None,
        stream: str,
        chunk: Any,
        *,
        source_process: str | None = None,
    ) -> None:
        row = self._rows.get(operation_id or "")
        if not row or stream not in {"stdout", "stderr"}:
            return
        if (
            source_process
            and self._managed_processes.get(source_process) != row.operation_id
        ):
            return
        if row.summary.get("output_policy") != "bounded_visible":
            return
        if row.finished is not None and not source_process:
            return
        if not isinstance(chunk, str) or not chunk:
            return
        # Hold incomplete lines so a secret label/value split across transport
        # chunks is redacted together. Drop oversized lines rather than emit a
        # potentially sensitive prefix before its meaning is known.
        for char in chunk[:_MAX_CHUNK]:
            if char == "\n":
                if stream not in row.discarding:
                    self._emit_line(row, stream, row.pending.get(stream, "") + "\n")
                row.pending.pop(stream, None)
                row.discarding.discard(stream)
            elif stream not in row.discarding:
                pending = row.pending.get(stream, "") + char
                if len(pending) > _MAX_CHUNK:
                    row.pending.pop(stream, None)
                    row.discarding.add(stream)
                    row.output_truncated = True
                else:
                    row.pending[stream] = pending
        if len(chunk) > _MAX_CHUNK:
            row.pending.pop(stream, None)
            row.discarding.add(stream)
            row.output_truncated = True

    def _emit_line(self, row: _Row, stream: str, value: str) -> None:
        sanitized = _sanitized_chunk(value)
        if not sanitized:
            return
        prior = getattr(row, stream)
        room = max(0, _MAX_OUTPUT - len(prior))
        retained = sanitized[:room]
        if len(sanitized) > room:
            row.output_truncated = True
        if retained:
            setattr(row, stream, prior + retained)
            self._emit(
                row,
                "output",
                stream=stream,
                chunk=retained,
                truncated=row.output_truncated,
            )

    def process_output(
        self,
        principal: Principal,
        host_session: str | None,
        process_id: str,
        stream: str,
        chunk: Any,
        *,
        offset: int = 0,
    ) -> None:
        op = self._managed_processes.get(process_id)
        row = self._rows.get(op or "")
        if not row or self._identity(principal, host_session) != (
            row.issuer,
            row.subject,
            row.client_id,
            row.session_tag,
        ):
            return
        if (
            stream not in {"stdout", "stderr"}
            or stream in row.unreliable_streams
            or type(offset) is not int
            or offset < 0
            or not isinstance(chunk, str)
            or not chunk
        ):
            return

        def withhold_stream() -> None:
            # Lossy decoding makes byte offsets and line boundaries ambiguous.
            row.pending.pop(stream, None)
            row.discarding.add(stream)
            row.unreliable_streams.add(stream)
            row.output_truncated = True

        try:
            if "\ufffd" in chunk:
                withhold_stream()
                return
            data = chunk.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            withhold_stream()
            return
        key = (process_id, stream)
        old = self._process_offsets.get(key, 0)
        if offset < old:
            # Agent offsets count bytes, not Unicode characters.
            data = data[old - offset :]
            offset = old
        elif offset > old:
            # A skipped prefix could contain a secret label: discard that line.
            row.pending.pop(stream, None)
            row.discarding.add(stream)
            row.output_truncated = True
        if not data:
            return
        try:
            chunk = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            withhold_stream()
            return
        self._process_offsets[key] = offset + len(data)
        self.output(op, stream, chunk, source_process=process_id)

    def complete_process_output(
        self,
        principal: Principal,
        host_session: str | None,
        process_id: str,
        *,
        offset: int,
    ) -> None:
        """Flush only streams whose observed end matches an empty terminal poll."""
        op = self._managed_processes.get(process_id)
        row = self._rows.get(op or "")
        if (
            not row
            or self._identity(principal, host_session)
            != (row.issuer, row.subject, row.client_id, row.session_tag)
            or type(offset) is not int
            or offset < 0
        ):
            return
        for stream, pending in tuple(row.pending.items()):
            if (
                stream not in row.discarding
                and self._process_offsets.get((process_id, stream)) == offset
            ):
                self._emit_line(row, stream, pending)
                row.pending.pop(stream, None)

    def finish(
        self,
        operation_id: str | None,
        *,
        status: str,
        exit_code: int | None,
        duration_ms: int | None,
    ) -> None:
        row = self._rows.get(operation_id or "")
        if row is None or row.finished is not None:
            return
        if row.tool == "shell.exec":
            for stream, pending in tuple(row.pending.items()):
                if stream not in row.discarding:
                    self._emit_line(row, stream, pending)
            row.pending.clear()
            row.discarding.clear()
        row.status = status if status in _ALLOWED_STATUSES else "error"
        if type(exit_code) is int and exit_code != 0:
            row.status = "error"
        row.exit_code = exit_code if type(exit_code) is int else None
        row.duration_ms = max(0, duration_ms) if type(duration_ms) is int else None
        row.finished = self._clock()
        if row.tool in {"fs.write", "fs.patch", "fs.copy", "fs.move", "fs.delete"}:
            verified = row.status in {"ok", "completed"}
            if verified:
                row.summary["effect"] = "verified_write"
                if row.tool == "fs.patch":
                    row.summary["diff"] = (
                        f"{row.summary.get('patch_count') or 0} patch(es) applied; "
                        "content hidden until separately authorized diff."
                    )
            else:
                row.summary["effect"] = "failed_or_unverified"
        self._emit(
            row,
            "finished",
            exit_code=row.exit_code,
            duration_ms=row.duration_ms,
            summary=row.summary,
            truncated=row.output_truncated,
        )

    def read(
        self,
        principal: Principal,
        host_session: str | None,
        devices: list[dict[str, Any]],
        *,
        after_seq: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        return self._read_authorized(
            principal,
            self._identity(principal, host_session),
            devices,
            after_seq=after_seq,
            limit=limit,
        )

    def read_verified_viewer(
        self,
        principal: Principal,
        session_tag: str | None,
        devices: list[dict[str, Any]],
        *,
        after_seq: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        # Only the server should call this with a tag previously verified
        # by LiveActivity.resolve_viewer(principal, session_ref).
        if not (
            session_tag
            and isinstance(session_tag, str)
            and len(session_tag) == 64
            and principal.auth_kind == "oauth2"
            and principal.issuer
            and principal.subject
            and principal.client_id not in ("", "unknown", "oauth-client")
            and scope_allows(principal.scopes, STANDARD_SCOPE)
        ):
            raise PermissionError("Verified STANDARD OAuth viewer required")
        identity = (
            principal.issuer,
            principal.subject,
            principal.client_id,
            session_tag,
        )
        return self._read_authorized(
            principal, identity, devices, after_seq=after_seq, limit=limit
        )

    def _read_authorized(
        self,
        principal: Principal,
        identity,
        devices: list[dict[str, Any]],
        *,
        after_seq: int,
        limit: int,
    ) -> dict[str, Any]:
        if identity is None:
            raise PermissionError("Verified STANDARD OAuth conversation required")
        if (
            type(after_seq) is not int
            or after_seq < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise ValueError("Invalid timeline cursor or limit")
        if identity in self._sequences:
            sequence, _ = self._sequences[identity]
            self._sequences[identity] = (sequence, self._clock())
        self._expire()
        ids = {
            item["id"]
            for item in devices
            if not item.get("revoked_at")
            and "id" in item
            and item.get("access_max_permission_profile")
            in {"STANDARD", "FULL_CONTROL"}
            and item.get("permission_profile") in {"STANDARD", "FULL_CONTROL"}
            and item.get("capabilities", {}).get(
                "local_max_permission_profile", "STANDARD"
            )
            in {"STANDARD", "FULL_CONTROL"}
        }
        result = []
        for _, event in self._events:
            if event["seq"] <= after_seq:
                continue
            row = self._rows.get(event["operation_id"])
            if (
                row is None
                or (row.issuer, row.subject, row.client_id, row.session_tag) != identity
            ):
                continue
            if row.device_id:
                if row.device_id not in ids:
                    continue
            elif not row.tool.startswith("browser."):
                continue
            result.append(dict(event))
            if len(result) >= limit:
                break
        return {
            "events": result,
            "latest_sequence": self._sequences.get(identity, (0, 0))[0],
            "next_after_seq": result[-1]["seq"] if result else after_seq,
            "truncated": bool(result and result[0]["seq"] > after_seq + 1),
            "retention_seconds": _MAX_AGE,
            "output_policy": "Only simple allowlisted read-only commands display bounded, redacted output.",
        }
