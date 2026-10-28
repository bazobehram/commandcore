"""Defense-in-depth checks for the live activity identity boundary."""

import pytest

from commandcore_server.live_activity import LiveActivity
from commandcore_server.activity_visibility import safe_path
from commandcore_server.models import Principal


OWNER = Principal(
    "owner", "client", "oauth2", ("commandcore:standard",), "https://issuer.test"
)


def test_activity_path_hints_reject_long_opaque_components():
    assert safe_path("/tmp/" + "a" * 49) is None
    assert safe_path("/tmp/" + "a" * 48) == "/tmp/" + "a" * 48
    assert safe_path("/tmp/secret-" + "a" * 49) == "[restricted path]"
    for component in (
        "auth-cache",
        "passwd",
        "session-id",
        "api_key",
        "access-key",
        "bearer",
    ):
        assert safe_path("/tmp/" + component) == "[restricted path]"


def test_viewer_requires_complete_oauth_identity_for_issue_and_resolution():
    activity = LiveActivity()
    viewer = activity.issue_viewer(OWNER, "chat")["session_ref"]
    assert activity.resolve_viewer(OWNER, viewer) == activity.session_tag("chat")
    rejected = [
        Principal(
            "", "client", "oauth2", ("commandcore:standard",), "https://issuer.test"
        ),
        Principal(
            "owner", "", "oauth2", ("commandcore:standard",), "https://issuer.test"
        ),
        Principal(
            "owner",
            "client",
            "bootstrap-bearer",
            ("commandcore:standard",),
            "https://issuer.test",
        ),
        Principal("owner", "client", "oauth2", ("commandcore:standard",), ""),
    ]
    for principal in rejected:
        assert activity.issue_viewer(principal, "chat")["session_available"] is False
        assert activity.resolve_viewer(principal, viewer) is None


def test_activity_snapshot_requires_valid_detail_flags_and_standard_identity():
    activity = LiveActivity()
    with pytest.raises(ValueError, match="flags must be boolean"):
        activity.snapshot(OWNER, [], [], 10, include_details=1)
    with pytest.raises(ValueError, match="flags must be boolean"):
        activity.snapshot(OWNER, [], [], 10, panel_details="yes")
    read_only = Principal(
        "owner", "client", "oauth2", ("commandcore:read",), "https://issuer.test"
    )
    with pytest.raises(ValueError, match="STANDARD OAuth"):
        activity.snapshot(read_only, [], [], 10, include_details=True)
    spoofed = Principal(
        "owner",
        "client",
        "bootstrap-bearer",
        ("commandcore:standard",),
        "https://issuer.test",
    )
    with pytest.raises(ValueError, match="STANDARD OAuth"):
        activity.snapshot(spoofed, [], [], 10, include_details=True)
    assert activity.snapshot(OWNER, [], [], 10, include_details=True)["events"] == []
    panel = Principal(
        "owner",
        "panel",
        "oauth2-panel",
        ("commandcore:standard",),
        "https://issuer.test",
    )
    assert (
        activity.snapshot(panel, [], [], 10, include_details=True, panel_details=True)[
            "events"
        ]
        == []
    )
