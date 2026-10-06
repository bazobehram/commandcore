from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, fields
from pathlib import Path


def _protect_windows_file(path: Path) -> None:
    """Set a protected DACL before writing credentials: owner and SYSTEM only."""
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    apply = advapi.SetFileSecurityW
    apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    apply.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    if not convert("D:P(A;;FA;;;SY)(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not apply(str(path.resolve()), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def default_state_path() -> Path:
    env = os.getenv("COMMANDCORE_AGENT_STATE")
    if env:
        return Path(env).expanduser()
    if os.name == "nt":
        base = Path(os.getenv("APPDATA", Path.home()))
        return base / "CommandCore" / "agent.json"
    return Path.home() / ".config" / "commandcore" / "agent.json"


@dataclass
class AgentState:
    device_id: str
    device_token: str
    private_key_b64: str
    public_key_b64: str
    control_url: str
    agent_url: str
    display_name: str
    key_generation: int = 1
    pending_private_key_b64: str | None = None
    pending_public_key_b64: str | None = None
    pending_rotation_id: str | None = None
    state_version: int = 2
    enrollment_id: str | None = None
    enrollment_poll_token: str | None = None
    enrollment_uri: str | None = None
    enrollment_code: str | None = None
    enrollment_expires_at: float = 0


def load(path: Path | None = None) -> AgentState:
    p = path or default_state_path()
    data = json.loads(p.read_text(encoding="utf-8"))
    # Forward-compatible local state: ignore fields written by a newer Agent
    # rather than making an older binary unable to inspect/recover the device.
    allowed = {f.name for f in fields(AgentState)}
    return AgentState(**{k: v for k, v in data.items() if k in allowed})


def save(state: AgentState, path: Path | None = None) -> Path:
    """Atomically persist Agent identity with owner-only permissions.

    Device identity is a recovery-critical credential. A crash during a normal
    write must never leave a truncated JSON file that bricks the service.
    """
    p = path or default_state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{p.name}.", dir=p.parent)
    temp = Path(temp_name)
    try:
        if os.name == "nt":
            try:
                _protect_windows_file(temp)
            except Exception:
                os.close(fd)
                raise
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(asdict(state), handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temp, 0o600)
        os.replace(temp, p)
        if os.name != "nt":
            os.chmod(p, 0o600)
            # Best effort directory sync so the rename survives sudden power loss.
            try:
                dir_fd = os.open(p.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    return p


def begin_key_rotation(
    state: AgentState, *, private_key_b64: str, public_key_b64: str, rotation_id: str
) -> None:
    state.pending_private_key_b64 = private_key_b64
    state.pending_public_key_b64 = public_key_b64
    state.pending_rotation_id = rotation_id


def promote_pending_key(state: AgentState, *, key_generation: int) -> None:
    if not state.pending_private_key_b64 or not state.pending_public_key_b64:
        raise ValueError("no_pending_device_key")
    state.private_key_b64 = state.pending_private_key_b64
    state.public_key_b64 = state.pending_public_key_b64
    state.key_generation = max(int(key_generation), state.key_generation + 1)
    state.pending_private_key_b64 = None
    state.pending_public_key_b64 = None
    state.pending_rotation_id = None


def clear_pending_key(state: AgentState) -> None:
    state.pending_private_key_b64 = None
    state.pending_public_key_b64 = None
    state.pending_rotation_id = None
