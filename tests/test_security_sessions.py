from commandcore_server.security import issue_panel_session, verify_panel_session


def test_panel_session_round_trip():
    secret = "this-is-a-long-enough-test-secret-123456"
    token = issue_panel_session(secret=secret, subject="owner-a", ttl_seconds=60)
    assert verify_panel_session(secret=secret, token=token) == "owner-a"


def test_panel_session_rejects_wrong_secret_and_tampering():
    token = issue_panel_session(
        secret="secret-a-that-is-long-enough-123456", subject="owner-a", ttl_seconds=60
    )
    assert (
        verify_panel_session(secret="secret-b-that-is-long-enough-123456", token=token)
        is None
    )
    assert (
        verify_panel_session(
            secret="secret-a-that-is-long-enough-123456", token=token + "x"
        )
        is None
    )


def test_panel_session_expiration():
    secret = "this-is-a-long-enough-test-secret-123456"
    token = issue_panel_session(secret=secret, subject="owner-a", ttl_seconds=-1)
    assert verify_panel_session(secret=secret, token=token) is None
