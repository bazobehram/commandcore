"""Check draft legal page assets without network or operator identity."""

from __future__ import annotations

from pathlib import Path

import pytest

PUBLIC_ASSETS = Path(__file__).resolve().parents[1] / "apps/workspace-angular/public"


@pytest.mark.parametrize("page", ("privacy", "terms"))
def test_hosted_legal_page_is_explicitly_unapproved(page):
    html = (PUBLIC_ASSETS / page / "index.html").read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    other_page = "terms" if page == "privacy" else "privacy"
    assert f'<a href="/{other_page}/">' in html
    assert 'name="robots" content="noindex, nofollow"' in html
    assert "DRAFT — NOT APPROVED FOR PUBLICATION." in html
    assert "<script" not in html.lower()
    assert "<form" not in html.lower()
    assert "Publication blocker:" in html
