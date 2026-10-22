"""One content-free Activity Event for dispatch, journal, panel and MCP.

Arguments and outcomes are untrusted. Never copy free text, even error text,
into persisted diagnostics. In particular command hashes can disclose guessed
secrets, so these summaries contain only types, counts and bounded numbers.
"""

from __future__ import annotations

import time
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from types import MappingProxyType
from typing import Any

observer: ContextVar[Any] = ContextVar("activity_observer", default=None)
source: ContextVar[dict[str, str]] = ContextVar(
    "activity_source", default=MappingProxyType({})
)


async def notify(event: dict[str, Any]) -> None:
    sink = observer.get()
    if sink is not None:
        await sink(event)


def argument_summary(arguments: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in (
        "path",
        "source",
        "destination",
        "root",
        "repo",
        "cwd",
        "command",
        "query",
        "data",
        "data_base64",
        "text",
    ):
        value = arguments.get(key)
        if isinstance(value, str):
            summary[key] = {"redacted": True, "characters": len(value)}
    for key in ("env", "patches", "args", "paths", "argv"):
        value = arguments.get(key)
        if isinstance(value, (dict, list)):
            summary[key] = {"redacted": True, "count": len(value)}
    window = arguments.get("window_id")
    if (
        isinstance(window, str)
        and window.startswith("0x")
        and len(window) <= 18
        and all(c in "0123456789abcdefABCDEF" for c in window[2:])
    ):
        summary["window_id"] = window
    for key in ("offset", "length", "limit", "timeout_ms", "pid"):
        value = arguments.get(key)
        if type(value) is int and 0 <= value <= 2**63 - 1:
            summary[key] = value
    return summary


@dataclass
class ActivityEvent:
    execution_id: str
    request_id: str
    device_id: str
    device_name: str
    tool: str
    argument_summary: dict[str, Any]
    permission: str
    started_at: float
    completed_at: float | None = None
    duration_ms: int | None = None
    status: str = "running"
    exit_code: int | None = None
    signal: str | None = None
    termination_reason: str | None = None
    result_summary: str = "Operation dispatched; contents omitted"
    kind: str = "operation"
    source: dict[str, str] = field(default_factory=dict)
    health_summary: dict[str, Any] = field(default_factory=dict)
    domain_state: str | None = None

    def wire(self) -> dict[str, Any]:
        return asdict(self)

    def finish(self, result: Any) -> None:
        self.completed_at = time.time()
        self.duration_ms = max(0, int((self.completed_at - self.started_at) * 1000))
        status = getattr(result, "status", "error")
        self.status = (
            status
            if status
            in {
                "ok",
                "completed",
                "started",
                "error",
                "timeout",
                "agent_disconnected",
                "canceled",
            }
            else "error"
        )
        code = getattr(result, "exit_code", None)
        self.exit_code = code if type(code) is int else None
        payload = getattr(result, "result", None)
        if isinstance(payload, dict):
            domain = payload.get("reason")
            if isinstance(domain, str) and domain in {
                "file_not_found",
                "unknown_process",
                "output_unavailable",
                "worker_lost",
            }:
                self.domain_state = domain
            health = payload.get("health_at_start") or payload.get("health")
            if (
                isinstance(health, dict)
                and isinstance(health.get("state"), str)
                and health["state"] in {"ok", "warning", "unknown"}
            ):
                conditions = health.get("conditions")
                conditions = conditions[:32] if isinstance(conditions, list) else []
                self.health_summary = {
                    "state": health["state"],
                    "conditions": [
                        c["code"]
                        for c in conditions
                        if isinstance(c, dict)
                        and isinstance(c.get("code"), str)
                        and c["code"]
                        in {
                            "disk_capacity_low",
                            "memory_pressure",
                            "accelerator_capacity_low",
                        }
                    ],
                }
            signal = payload.get("signal")
            reason = payload.get("termination_reason")
            if isinstance(signal, str) and signal in {
                "SIGTERM",
                "SIGKILL",
                "SIGINT",
                "SIGHUP",
            }:
                self.signal = signal
            if isinstance(reason, str) and reason in {
                "stopped_by_request",
                "exited",
                "timeout",
                "worker_lost",
                "host_rebooted",
                "local_policy_revocation",
                "workload_oom",
                "user_manager_lost",
                "terminated_by_signal",
            }:
                self.termination_reason = reason
        self.result_summary = f"{self.status}; output and contents omitted"
        # No free-form agent error strings enter Activity. Only a short,
        # explicitly allowed diagnostic set may be surfaced.
        if self.status != "ok" and self.tool.startswith("agents."):
            safe_failures = {
                "target_window_title_changed": "Window title changed; no input sent",
                "target_window_not_found": "Window not found; no input sent",
                "target_window_identity_changed": "Window identity changed; no input sent",
                "draft_expired": "Draft expired; no input sent",
                "human_takeover_active": "Human has control; no input sent",
                "collaboration_send_already_active": "Another collaboration delivery is active",
                "target_window_changed_during_approval": "Window changed during approval; no input sent",
                "target_not_active_abort": "Target not active; input stopped",
                "draft_process_start_missing": "Draft identity incomplete; no input sent",
                "input_point_outside_target_window": "Input point outside window; no input sent",
            }
            error_code = getattr(result, "error", None)
            if isinstance(error_code, str) and error_code in safe_failures:
                self.domain_state = error_code
                self.result_summary = f"{self.status}; {safe_failures[error_code]}"
        if self.status == "ok" and isinstance(payload, dict):
            public_states = {
                (
                    "agents.prepare",
                    "awaiting_local_human_approval",
                ): "Draft prepared; waiting for local human approval",
                ("agents.deliver", "declined"): "Human declined; no message sent",
                (
                    "agents.deliver",
                    "input_submitted_response_unverified",
                ): "Human approved; input submitted; agent response unverified",
            }
            observed_state = payload.get("state")
            key = (self.tool, observed_state if isinstance(observed_state, str) else "")
            if key in public_states:
                self.result_summary = public_states[key]
                self.domain_state = key[1]
            elif self.tool == "agents.observe":
                self.result_summary = "Existing window observed; no input sent"
                self.domain_state = "observed"
        if self.exit_code is not None:
            self.result_summary += f"; exit={self.exit_code}"
