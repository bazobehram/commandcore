"""Keep the public release homepage consistent with the private CommandCore design."""

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "deploy/public/site"


class PageRefs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []

    def handle_starttag(self, tag, attrs):
        for field, value in attrs:
            if field in ("src", "href") and value:
                self.refs.append(value)


def test_public_home_is_the_approved_workspace_landing():
    html = (SITE / "index.html").read_text()
    refs = PageRefs()
    refs.feed(html)
    assert "Your AI." in html
    assert "One quiet workspace" in html
    assert "Real work, one surface" in html
    assert "/site/landing.css?v=public-home-20261030" in refs.refs
    assert "/site/landing.js?v=public-home-20261030" in refs.refs
    assert "/auth/login" in refs.refs
    assert "/workspace/" in refs.refs
    assert 'href="/app/"' not in html
    assert "ascent-gx10" not in html and "homeserver" not in html
    assert (SITE / "site/landing.css").stat().st_size > 1000
    assert (SITE / "site/landing.js").stat().st_size > 100


def test_one_workspace_in_build_and_redirect():
    builder = (ROOT / "scripts/build_public_site.py").read_text()
    nginx = (ROOT / "deploy/public/nginx-public.conf").read_text()
    assert 'shutil.copytree(ANGULAR, OUT / "workspace")' in builder
    assert 'href="/workspace/"' in builder
    assert "location = /workspace/" in nginx
    assert "location = /app/" in nginx
    assert "return 302 https://commandcore.app/workspace/;" in nginx
    assert "location = /auth/callback" in nginx
    assert "/app/index.html =404" not in nginx
