"""MCP Apps Browser V28: explicit initialization, real frames and legacy URLs."""

from types import SimpleNamespace
import unittest

from commandcore_server.mcp import (
    BROWSER_WIDGET_URI,
    BROWSER_WIDGET_MIME,
    BROWSER_WIDGET_V26_URI,
    BROWSER_WIDGET_V27_URI,
    MCPHandler,
)
from commandcore_server.web_assets import web_asset


class BrowserEmbedV28Tests(unittest.TestCase):
    def test_current_widget_and_cached_versions(self):
        html = web_asset("browser-live-v28.html").read_text(encoding="utf-8")
        self.assertIn("ui/initialize", html)
        self.assertIn("ui/notifications/initialized", html)
        self.assertIn("content_items", html)
        self.assertIn("Control here", html)
        self.assertIn("browser.click", html)
        self.assertIn("browser.scroll", html)
        self.assertIn("Take private control", html)
        self.assertNotEqual(BROWSER_WIDGET_URI, BROWSER_WIDGET_V26_URI)
        self.assertNotEqual(BROWSER_WIDGET_URI, BROWSER_WIDGET_V27_URI)

    def test_browser_watch_only_declares_own_resources(self):
        svc = SimpleNamespace(live_activity=SimpleNamespace(), db=SimpleNamespace())
        handler = MCPHandler(
            svc,
            SimpleNamespace(inc=lambda *args: None),
            "test-browser-v28",
            definitions=[
                {
                    "name": "browser.watch",
                    "description": "Browser viewer",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        self.assertEqual(handler.ui_specs["browser.watch"][0], BROWSER_WIDGET_URI)
        self.assertEqual(handler.ui_specs["browser.watch"][1], BROWSER_WIDGET_MIME)
        self.assertIn(BROWSER_WIDGET_URI, handler.ui_resources)
        self.assertIn(BROWSER_WIDGET_V26_URI, handler.ui_resources)
        self.assertIn(BROWSER_WIDGET_V27_URI, handler.ui_resources)
        entry = next(x for x in handler.definitions if x["name"] == "browser.watch")
        self.assertEqual(entry["_meta"]["ui"]["resourceUri"], BROWSER_WIDGET_URI)

    def test_web_assets_are_distinct(self):
        v26 = web_asset("browser-live-v26.html").read_text()
        v27 = web_asset("browser-live-v27.html").read_text()
        v28 = web_asset("browser-live-v28.html").read_text()
        self.assertNotEqual(v26, v27)
        self.assertNotEqual(v27, v28)
        self.assertIn("content_items", v28)


if __name__ == "__main__":
    unittest.main()
