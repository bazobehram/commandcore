"""Auth0 custom API JWT audience parameter regression guard."""

from pathlib import Path


def test_auth0_custom_api_uses_audience_on_authorize_and_token_exchange():
    source = (
        Path(__file__).resolve().parents[1]
        / "apps/server/commandcore_server/onboarding_routes.py"
    ).read_text()
    assert source.count('"audience": settings.oauth_audience') == 2
    assert '"resource": settings.oauth_audience' not in source
