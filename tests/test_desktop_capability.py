import asyncio
from unittest.mock import AsyncMock, patch

from commandcore_agent.executor import Executor
from commandcore_agent import desktop_backend


async def _out(*_):
    pass


def test_desktop_tools_permission_boundary():
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    r = asyncio.run(ex.execute("x", "READ_ONLY", "mouse.click", {"x": 1, "y": 2}, _out))
    assert r["status"] == "error" and "permission_denied" in r["error"]


def test_screen_capture_read_only_dispatch():
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    with patch.object(
        desktop_backend,
        "screenshot",
        new=AsyncMock(
            return_value={"mime_type": "image/png", "data_base64": "AA==", "bytes": 1}
        ),
    ):
        r = asyncio.run(ex.execute("x", "READ_ONLY", "screen.capture", {}, _out))
    assert r["status"] == "ok" and r["result"]["mime_type"] == "image/png"


def test_clipboard_write_standard_dispatch():
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    with patch.object(
        desktop_backend,
        "clipboard_write",
        new=AsyncMock(return_value={"characters": 3}),
    ):
        r = asyncio.run(
            ex.execute("x", "STANDARD", "clipboard.write", {"text": "abc"}, _out)
        )
    assert r["status"] == "ok" and r["result"]["characters"] == 3


def test_capability_detection_is_boolean():
    caps = desktop_backend.desktop_capabilities()
    assert set(caps) == {"desktop", "screen", "keyboard", "mouse", "clipboard"}
    assert all(isinstance(v, bool) for v in caps.values())


def test_full_control_desktop_stays_in_interactive_agent_session():
    helper = AsyncMock()
    helper.probe = AsyncMock(
        return_value={"available": True, "max_permission_profile": "FULL_CONTROL"}
    )
    ex = Executor(
        helper_client=helper, delegate_full_control=True, enforce_local_ceiling=False
    )
    with patch.object(
        desktop_backend,
        "screenshot",
        new=AsyncMock(
            return_value={"mime_type": "image/png", "data_base64": "AA==", "bytes": 1}
        ),
    ):
        r = asyncio.run(ex.execute("x", "FULL_CONTROL", "screen.capture", {}, _out))
    assert r["status"] == "ok"
    helper.execute.assert_not_called()
