import pytest
from commandcore_server.config import Settings


def test_server_refuses_missing_or_short_bootstrap_secret():
    with pytest.raises(RuntimeError, match="required"):
        Settings(api_token="").validate()
    with pytest.raises(RuntimeError, match="required"):
        Settings(api_token="short").validate()


def test_server_accepts_explicit_strong_bootstrap_secret_when_enabled():
    Settings(api_token="x" * 32, public_bootstrap_enabled=True).validate()


def test_public_bootstrap_defaults_disabled():
    settings = Settings(api_token="x" * 32, panel_session_secret="y" * 32)
    assert settings.public_bootstrap_enabled is False
    settings.validate()
