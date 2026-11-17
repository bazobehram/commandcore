"""Regression tests for origin-only Browser Activity hints.

Only a validated public HTTPS origin is eligible for display. Never copy URL
paths, query strings, credentials, browser content or typed values into Activity.
"""
import json
import unittest

from commandcore_server.activity_trace import safe_trace
from commandcore_server.activity_visibility import (
    safe_operation_detail,
    visible_public_url,
)


class BrowserOriginProjectionTests(unittest.TestCase):
    def test_public_https_origin_only(self):
        self.assertEqual(
            visible_public_url("https://WWW.Example.org/private/report?token=fixture#password"),
            "https://www.example.org/",
        )
        self.assertEqual(
            visible_public_url("https://docs.example.co.uk/one/two"),
            "https://docs.example.co.uk/",
        )

    def test_browser_hint_never_persists_path_query_fragment_or_typed_data(self):
        private = "super-sensitive-fixture-NOT-LOGGED"
        detail = safe_trace(
            "browser.open",
            {
                "url": "https://news.example.org/hidden/" + private
                + "?access_token=" + private + "#section-" + private,
                "text": private,
                "password": private,
                "data": private,
            },
        )
        self.assertEqual(detail["public_url"], "https://news.example.org/")
        self.assertIn("origin", detail["note"])
        serialized = json.dumps(detail)
        self.assertNotIn(private, serialized)
        self.assertNotIn("access_token", serialized)

    def test_non_browser_operation_never_inherits_url(self):
        detail = safe_operation_detail(
            "shell.exec", {"url": "https://example.org/secret", "command": "pwd"}
        )
        self.assertNotIn("public_url", detail)

    def test_browser_without_safe_url_is_redacted(self):
        detail = safe_trace("browser.type", {
            "url": "http://example.org/private?token=NOPE",
            "text": "do-not-show",
        })
        self.assertNotIn("public_url", detail)
        self.assertIn("omitted", detail["note"])
        self.assertNotIn("do-not-show", json.dumps(detail))

    def test_reject_internal_or_local_endpoints(self):
        for url in (
            "http://example.org/",
            "https://localhost/",
            "https://homeserver/",
            "https://homeserver.local/",
            "https://app.internal/",
            "https://router.lan/",
            "https://192.168.1.146/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://example.org:8443/",
            "https://example.org:bad/",
            "https://user:pass@example.org/",
            "https://user@example.org/",
            "https://example.org\\evil.org/",
            "https://example.org/evil\nmore",
            "https://example.org /",
            "ftp://example.org/",
            "//example.org/",
            "https://token-secret.example.org/",
            "https://a..example.org/",
            "https://-bad.example.org/",
            "https://example.org./",
            "https://malicious.example.org%0a.test/",
            "https://☃.example.org/",
            "https://example.org/?bad=\\",
        ):
            with self.subTest(url=url):
                self.assertIsNone(visible_public_url(url))

    def test_bounded_input_and_unexpected_types(self):
        for value in (None, "", 123, {}, [], "https://example.org/" * 300):
            with self.subTest(value_type=type(value).__name__):
                self.assertIsNone(visible_public_url(value))


if __name__ == "__main__":
    unittest.main()
