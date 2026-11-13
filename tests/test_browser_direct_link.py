"""One-click, owner-bound Browser link: no Workspace hop or implicit handoff."""

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from commandcore_server.browser_viewer import install_browser_viewer
from commandcore_server.browser_worker_pool import OwnerBrowserWorkerPool
from commandcore_server.onboarding_routes import (
    _browser_login_landing,
    _panel_return_path,
)


class BrowserDirectLinkTests(unittest.TestCase):
    def test_direct_browser_page_and_static_assets(self):
        app = FastAPI()
        install_browser_viewer(app, None, lambda: None, lambda _r: False, None)
        client = TestClient(app)
        page = client.get("/browser/live", follow_redirects=False)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Remote Chromium", page.text)
        self.assertIn('src="/browser-live.js"', page.text)
        self.assertIn('href="/browser-live.css"', page.text)
        self.assertNotIn("handoff_token", page.text)
        self.assertIn("no-store", page.headers["cache-control"])
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertIn("default-src 'none'", page.headers["content-security-policy"])
        for route, media_type in (
            ("/browser-live.js", "application/javascript"),
            ("/browser-live.css", "text/css"),
        ):
            result = client.get(route)
            self.assertEqual(result.status_code, 200)
            self.assertIn(media_type, result.headers["content-type"])
            self.assertIn("no-store", result.headers["cache-control"])

    def test_oauth_return_path_exact_allowlist(self):
        self.assertEqual(_panel_return_path("browser_live", ""), "/browser/live")
        self.assertEqual(_panel_return_path("browser_live", "invalid"), "/browser/live")
        self.assertEqual(_panel_return_path("browser", ""), "/")
        self.assertEqual(_panel_return_path("custom", "/browser/live"), "/")
        response = _browser_login_landing("/browser/live")
        self.assertIn("Continue to live Browser", response.body.decode())
        self.assertNotIn("AI control stays paused", response.body.decode())
        self.assertIn("no-store", response.headers["cache-control"])
        with self.assertRaises(ValueError):
            _browser_login_landing("https://other.example.invalid/")


class BrowserLiveUrlTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_calls_expose_token_free_url(self):
        pool = OwnerBrowserWorkerPool.__new__(OwnerBrowserWorkerPool)
        pool.public_base_url = "https://control.example.invalid/"
        seen = []

        class Worker:
            async def call(self, **kwargs):
                seen.append(kwargs["name"])
                return {"status": "ok", "session_id": "session-example"}

        pool._find_worker = lambda _owner: Worker()
        pool._verify_physical_assignment = lambda _worker: None
        for name in ("browser.open", "browser.watch"):
            result = await pool.call(
                subject="subject",
                issuer="https://issuer.example.invalid/",
                client_id="client",
                name=name,
                args={},
            )
            self.assertEqual(
                result["browser_live_url"],
                "https://control.example.invalid/browser/live",
            )
            self.assertNotIn("console", result["browser_live_url"])
            self.assertNotIn("token", result["browser_live_url"])
        result = await pool.call(
            subject="subject",
            issuer="https://issuer.example.invalid/",
            client_id="client",
            name="browser.click",
            args={"x": 1, "y": 1},
        )
        self.assertNotIn("browser_live_url", result)
        self.assertEqual(seen, ["browser.open", "browser.watch", "browser.click"])


if __name__ == "__main__":
    unittest.main()
