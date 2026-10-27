"""Exercise bounded Activity display projections, not command execution."""

import json

from commandcore_server.activity_visibility import (
    command_projection,
    visible_public_url,
)
from commandcore_server.live_activity import LiveActivity
from commandcore_server.models import Principal


def test_validated_commands_retain_only_approved_steps():
    result = command_projection("pwd && git status --short")
    assert result["command_visibility"] == "validated"
    assert result["command_display"] == "pwd && git status --short"
    assert result["command_steps"] == ["pwd", "git status --short"]
    assert result["step_operators"] == ["&&"]


def test_unknown_and_sensitive_shell_fragments_are_never_displayed():
    fake_access_key = "AKIA" + "1234567890123456"
    for command in (
        "pwd && echo token=private-value",
        "python -c 'print(private_value)'",
        "ls $(cat /etc/passwd)",
        "ls '&&'",
        "echo " + fake_access_key,
        "ls foo > output",
    ):
        result = command_projection(command)
        assert "command_display" not in result
        assert "private-value" not in json.dumps(result)
        assert "private_value" not in json.dumps(result)
        assert fake_access_key not in json.dumps(result)
    structure = command_projection("pwd && custom-tool arbitrary-argument")
    assert structure["command_visibility"] == "structure"
    assert "arbitrary-argument" not in json.dumps(structure)
    assert "custom-tool" not in json.dumps(structure)


def test_browser_projection_exposes_only_safe_https_origin():
    assert (
        visible_public_url("https://example.com/product?token=fixture#fragment")
        == "https://example.com/"
    )
    for url in (
        "http://example.com/",
        "https://user:password@example.com/",
        "https://example.com:8443/",
        "https://auth.example.com/",
        "https://example.com\\other",
    ):
        assert visible_public_url(url) is None


def test_projection_remains_bound_to_authorized_conversation():
    live = LiveActivity()
    owner = Principal(
        "owner", "client", "oauth2", ("commandcore:standard",), "https://issuer.test"
    )
    other = Principal(
        "other", "client", "oauth2", ("commandcore:standard",), "https://issuer.test"
    )
    op = live.begin(
        owner,
        "shell.exec",
        {"command": "pwd && git status --short"},
        host_session="chat-a",
    )
    live.set_device(op, "device")
    live.finish(op, status="ok", exit_code=0)
    devices = [{"id": "device", "display_name": "fixture"}]
    tag = live.session_tag("chat-a")
    rows = live.snapshot(owner, [], devices, 10, include_details=True, session_tag=tag)[
        "events"
    ]
    assert rows[0]["detail"]["command_display"] == "pwd && git status --short"
    assert (
        live.snapshot(other, [], devices, 10, include_details=True, session_tag=tag)[
            "events"
        ]
        == []
    )
    assert (
        live.snapshot(owner, [], [], 10, include_details=True, session_tag=tag)[
            "events"
        ]
        == []
    )
