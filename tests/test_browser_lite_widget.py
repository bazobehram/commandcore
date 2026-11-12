"""Contract tests for the isolated lightweight MCP Browser renderer."""

import unittest

from commandcore_server.mcp import BROWSER_WIDGET_URI, WORKSPACE_UI_URI
from commandcore_server.web_assets import web_asset


class BrowserLiteWidgetTests(unittest.TestCase):
    def test_browser_resource_is_separate_and_versioned(self):
        self.assertNotEqual(BROWSER_WIDGET_URI, WORKSPACE_UI_URI)
        self.assertIn("browser-live-lite-v26", BROWSER_WIDGET_URI)

    def test_browser_asset_is_self_contained_and_small(self):
        html = web_asset("browser-live-lite.html").read_text(encoding="utf-8")
        self.assertLess(len(html.encode("utf-8")), 16_000)
        self.assertIn("<!doctype html>", html.lower())
        self.assertIn('id="frame"', html)
        self.assertIn('id="manual"', html)
        self.assertIn("browser.frame", html)
        self.assertIn("browser.handoff", html)
        self.assertIn("commandcore.viewer", html)
        self.assertIn("ui/notifications/initialized", html)
        self.assertIn("awaiting_human", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("eval(", html)


if __name__ == "__main__":
    unittest.main()
