from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def default_health_path(state_path: Path | None = None) -> Path:
    configured = os.getenv("COMMANDCORE_AGENT_HEALTH_FILE", "").strip()
    if configured:
        return Path(configured).expanduser()
    if state_path is not None:
        return state_path.parent / "health.json"
    return (
        Path("/run/commandcore-agent/health.json")
        if os.name != "nt"
        else Path.home() / ".commandcore-health.json"
    )


def write_health(
    path: Path,
    *,
    version: str,
    device_id: str,
    protocol_version: str,
    key_generation: int,
    connected: bool,
    implementation: str = "python",
    detail: str | None = None,
) -> None:
    """Atomically publish local runtime health for update commit/rollback gates.

    The marker contains no credentials. A privileged updater treats it only as
    liveness evidence after independently verifying a signed release artifact.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "version": version,
        "implementation": implementation,
        "device_id": device_id,
        "protocol_version": protocol_version,
        "key_generation": int(key_generation),
        "connected": bool(connected),
        "observed_at_unix": time.time(),
        "pid": os.getpid(),
    }
    if detail:
        payload["detail"] = detail
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
