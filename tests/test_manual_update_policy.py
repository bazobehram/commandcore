"""Manual updates are operator-initiated and fail closed by default."""

from commandcore_server.update_policy import (
    manual_update_info,
    release_key,
    trusted_manifest_url,
)


def ready_device():
    return {
        "agent_version": "0.9.0-rc7",
        "permission_profile": "FULL_CONTROL",
        "access_max_permission_profile": "FULL_CONTROL",
        "capabilities": {
            "local_max_permission_profile": "FULL_CONTROL",
            "agent_update": True,
            "agent_update_trust_configured": True,
        },
    }


def information(device=None, **changes):
    opts = dict(
        target_version="0.9.0-rc8",
        manifest_url="https://commandcore.example.org/releases/agent/manifest.json",
        connected=True,
        operator_full=True,
    )
    opts.update(changes)
    return manual_update_info(device or ready_device(), **opts)


def test_newer_release_is_available_but_not_auto_installed():
    result = information()
    assert result["state"] == "available"
    assert result["available"] and result["can_start"]
    assert result["automatic_updates"] is False


def test_same_version_and_older_recommendation_never_dispatch():
    assert information(target_version="0.9.0-rc7")["state"] == "up_to_date"
    assert not information(target_version="0.9.0-rc7")["can_start"]
    assert information(target_version="0.9.0-rc6")["state"] == "ahead"
    assert not information(target_version="0.9.0-rc6")["can_start"]


def test_untrusted_update_feed_cannot_be_submitted():
    for url in (
        "",
        "http://example.com/a",
        "https://example.com/x#fragment",
        "https://example.com/has space",
    ):
        assert not trusted_manifest_url(url)
        assert (
            "signed_release_feed_not_configured"
            in information(manifest_url=url)["blockers"]
        )


def test_explicit_full_access_and_device_trust_are_required():
    assert (
        "operator_full_scope_required" in information(operator_full=False)["blockers"]
    )
    assert "device_offline" in information(connected=False)["blockers"]
    device = ready_device()
    device["capabilities"]["agent_update_trust_configured"] = False
    assert "signed_update_trust_not_configured" in information(device)["blockers"]
    device["capabilities"]["agent_update_trust_configured"] = True
    device["access_max_permission_profile"] = "STANDARD"
    assert "account_full_grant_required" in information(device)["blockers"]


def test_versions_handle_prerelease_safely():
    assert release_key("0.9.0-rc7") < release_key("0.9.0")
    assert release_key("0.9.0-rc8") > release_key("0.9.0-rc7")
    assert release_key("0.9.1") > release_key("0.9.0")
    assert release_key("../0.9.1") is None
    assert information(target_version="../0.9.1")["state"] == "unknown"
