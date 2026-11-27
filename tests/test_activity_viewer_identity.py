"""Activity detail authorization belongs inside the broker, not just callers."""

from dataclasses import replace

import pytest
from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.live_activity import LiveActivity
from commandcore_server.models import Principal

OWNER = Principal(
    subject="fixture-owner",
    issuer="https://fixture.invalid/",
    client_id="fixture-client",
    auth_kind="oauth2",
    scopes=(READ_SCOPE, STANDARD_SCOPE),
)


@pytest.mark.parametrize(
    "changes",
    [
        {"auth_kind": "oauth2-panel"},
        {"auth_kind": "bootstrap-bearer"},
        {"issuer": ""},
        {"subject": ""},
        {"client_id": ""},
    ],
)
def test_incomplete_or_wrong_authentication_cannot_issue_or_resolve(changes):
    live = LiveActivity()
    ref = live.issue_viewer(OWNER, "fixture-chat")["session_ref"]
    bad = replace(OWNER, **changes)
    assert live.issue_viewer(bad, "fixture-chat") == {"session_available": False}
    assert live.resolve_viewer(bad, ref) is None
    assert live.resolve_viewer(OWNER, ref) == live.session_tag("fixture-chat")


@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": (READ_SCOPE,)},
        {"auth_kind": "bootstrap-bearer"},
        {"auth_kind": "oauth2-panel"},
        {"issuer": ""},
        {"subject": ""},
        {"client_id": ""},
    ],
)
def test_mcp_details_require_complete_standard_identity(changes):
    with pytest.raises(ValueError, match="verified STANDARD OAuth"):
        LiveActivity().snapshot(
            replace(OWNER, **changes), [], [], 10, include_details=True
        )


@pytest.mark.parametrize("flag", ["include_details", "panel_details"])
def test_nonboolean_detail_flags_rejected(flag):
    with pytest.raises(ValueError, match="boolean"):
        LiveActivity().snapshot(OWNER, [], [], 10, **{flag: "false"})


def test_read_only_summary_and_verified_detail_paths_remain_available():
    live = LiveActivity()
    reader = replace(OWNER, scopes=(READ_SCOPE,))
    assert live.issue_viewer(reader, "fixture-chat")["session_available"]
    assert live.snapshot(reader, [], [], 10)["events"] == []
    assert live.snapshot(OWNER, [], [], 10, include_details=True)["events"] == []
    panel = replace(OWNER, auth_kind="oauth2-panel")
    assert live.snapshot(panel, [], [], 10, panel_details=True)["events"] == []
    with pytest.raises(ValueError, match="STANDARD panel"):
        live.snapshot(OWNER, [], [], 10, panel_details=True)
