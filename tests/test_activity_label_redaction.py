"""Detailed activity must not expose sensitive operation labels."""

import json

from commandcore_server.live_activity import LiveActivity
from commandcore_server.models import Principal


def test_container_and_service_labels_filter_sensitive_and_opaque_values():
    live = LiveActivity()
    owner = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://issuer.test"
    )
    for args in (
        {"image": "registry.example/app:v1", "container": "web"},
        {"image": "registry.example/private-image", "container": "token-fixture"},
        {"service": "a" * 49, "manager": "systemd"},
    ):
        operation = live.begin(owner, "docker.inspect", args, host_session="chat")
        live.set_device(operation, "device")
        live.finish(operation, status="ok")
    events = live.snapshot(
        owner,
        [],
        [{"id": "device", "display_name": "fixture"}],
        10,
        include_details=True,
        session_tag=live.session_tag("chat"),
    )["events"]
    details = [event["detail"] for event in events]
    rendered = json.dumps(details)
    assert "token-fixture" not in rendered
    assert "private-image" not in rendered
    assert "a" * 49 not in rendered
    assert any(d.get("image") == "registry.example/app:v1" for d in details)
    assert any(d.get("container") == "web" for d in details)
    assert any(d.get("manager") == "systemd" for d in details)
