"""Locate reviewed web assets in source checkouts and installed wheels."""

import hashlib
import sys
from pathlib import Path


def web_asset(name: str) -> Path:
    if name not in {
        "index.html",
        "onboarding.html",
        "legacy-admin.html",
        "legacy-admin.css",
        "legacy-admin.js",
        "onboarding.css",
        "onboarding.js",
        "panel.css",
        "panel.js",
        "commandcore-logo.webp",
        "commandcore-icon.webp",
    }:
        raise ValueError("unknown web asset")
    source = Path(__file__).resolve().parents[2] / "web" / name
    return (
        source
        if source.is_file()
        else Path(sys.prefix) / "share/commandcore/web" / name
    )


def web_page(path: Path) -> str:
    """Give reviewed static dependencies a content identity across releases."""
    html = path.read_text(encoding="utf-8")
    for name in (
        "panel.css",
        "panel.js",
        "commandcore-logo.webp",
        "commandcore-icon.webp",
        "onboarding.css",
        "onboarding.js",
        "legacy-admin.css",
        "legacy-admin.js",
    ):
        reference = f'="/{name}"'
        if reference in html:
            digest = hashlib.sha256(web_asset(name).read_bytes()).hexdigest()[:16]
            html = html.replace(reference, f'="/{name}?v={digest}"')
    return html
