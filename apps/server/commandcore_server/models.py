from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Principal:
    subject: str
    client_id: str = "unknown"
    auth_kind: str = "bootstrap-bearer"
    scopes: tuple[str, ...] = ()
    issuer: str = ""


@dataclass
class JobResult:
    execution_id: str
    status: str
    result: dict[str, Any] | None
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    output_capture: dict[str, Any] = field(default_factory=dict)
