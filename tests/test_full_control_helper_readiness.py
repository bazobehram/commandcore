"""Authenticated helper startup readiness regression tests."""
import asyncio
from commandcore_agent import full_control

def test_probe_retries_then_succeeds(monkeypatch):
    values = [
        {"available": False, "max_permission_profile": "STANDARD"},
        {"available": True, "max_permission_profile": "STANDARD"},
        {"available": True, "max_permission_profile": "FULL_CONTROL"},
    ]
    class Client:
        def __init__(self, *args):
            pass
        async def probe(self):
            return values.pop(0)
    monkeypatch.setattr(full_control, "HelperClient", Client)
    result = asyncio.run(full_control._wait_for_authenticated_helper_ready("socket", "secret", attempts=3, delay=0))
    assert result["available"] is True
    assert result["max_permission_profile"] == "FULL_CONTROL"
    assert not values

def test_probe_bounded_failure(monkeypatch):
    class Client:
        def __init__(self, *args):
            pass
        async def probe(self):
            return {"available": False, "max_permission_profile": "STANDARD"}
    monkeypatch.setattr(full_control, "HelperClient", Client)
    result = asyncio.run(full_control._wait_for_authenticated_helper_ready("socket", "secret", attempts=3, delay=0))
    assert result["available"] is False
