"""Ensure the remote parity gate accepts only safe, absolute first-party assets."""

import importlib.util
from pathlib import Path

import pytest


script = Path(__file__).resolve().parents[1] / "scripts/check_dual_workspace_parity.py"
spec = importlib.util.spec_from_file_location("dual_workspace_parity", script)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_extract_workspace_assets_and_ignore_query():
    html = """<link rel="stylesheet" href="/styles-ABC123.css?v=1">
    <script src="/main-ABC123.js?v=2" type="module"></script>"""
    assert module.parse_assets(html) == {
        "stylesheet": "/styles-ABC123.css",
        "javascript": "/main-ABC123.js",
    }


def test_external_assets_not_accepted():
    with pytest.raises(ValueError, match="missing workspace"):
        module.parse_assets("""<script src="https://other.test/main-ABC123.js"></script>
        <link rel="stylesheet" href="//other.test/styles-ABC123.css">""")


def test_duplicate_assets_rejected():
    with pytest.raises(ValueError, match="multiple javascript"):
        module.parse_assets("""<script src="/main-ABC.js"></script>
        <script src="/main-DEF.js"></script><link rel="stylesheet" href="/styles-ABC.css">""")
