"""Read-only public/private CommandCore workspace artifact parity check.

This check does NOT assert backend, authorization, or database equivalence.
No tokens or credentials are used. Distinct tenants/data remain mandatory.
"""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import re
import subprocess
import time
from urllib.parse import urlsplit


_ASSET_PATTERNS = {
    "javascript": re.compile(r"^/main-[A-Za-z0-9]+\.js$"),
    "stylesheet": re.compile(r"^/styles-[A-Za-z0-9]+\.css$"),
}


class WorkspaceAssets(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script":
            name, value = "javascript", values.get("src", "")
        elif tag == "link" and "stylesheet" in (values.get("rel") or "").split():
            name, value = "stylesheet", values.get("href", "")
        else:
            return
        # Require same-origin relative URLs; never fetch arbitrary HTML-provided hosts.
        path = urlsplit(value or "").path
        if (
            value
            and value.startswith("/")
            and not value.startswith("//")
            and _ASSET_PATTERNS[name].fullmatch(path)
        ):
            if name in self.assets:
                raise ValueError(f"multiple {name} workspace assets")
            self.assets[name] = path


def parse_assets(html: str) -> dict[str, str]:
    parser = WorkspaceAssets()
    parser.feed(html)
    if set(parser.assets) != set(_ASSET_PATTERNS):
        raise ValueError(
            f"missing workspace assets: {set(_ASSET_PATTERNS) - set(parser.assets)}"
        )
    return parser.assets


def download(origin: str, path: str, nonce: str) -> bytes:
    if (
        not origin.startswith("https://")
        or not path.startswith("/")
        or path.startswith("//")
    ):
        raise ValueError("expected HTTPS origin and safe absolute asset path")
    if urlsplit(origin).path or urlsplit(origin).query:
        raise ValueError("origin must not contain a path or query")
    url = (
        origin.rstrip("/") + path + ("&" if "?" in path else "?") + "cc_parity=" + nonce
    )
    completed = subprocess.run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "20",
            url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=25,
    )
    if completed.returncode:
        raise RuntimeError(
            f"GET failed for {origin}{urlsplit(path).path}: curl exit {completed.returncode}"
        )
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", default="https://commandcore.app")
    parser.add_argument("--private", default="https://commandcore.synovaq.org")
    args = parser.parse_args()
    nonce = str(int(time.time()))
    origins = {"public": args.public, "private": args.private}
    indexes = {
        name: download(origin, "/workspace/", nonce).decode("utf-8")
        for name, origin in origins.items()
    }
    refs = {name: parse_assets(html) for name, html in indexes.items()}
    if refs["public"] != refs["private"]:
        raise ValueError(
            "frontend artifact names differ across public and private deployments"
        )
    for name, path in {
        **refs["public"],
        "octopus_brand": "/brand/octopus-idle.svg",
    }.items():
        payloads = {
            label: download(origin, path, nonce) for label, origin in origins.items()
        }
        digests = {
            label: hashlib.sha256(data).hexdigest() for label, data in payloads.items()
        }
        if len(set(digests.values())) != 1:
            raise ValueError(f"frontend content differs for {name} ({path})")
        print(f"PARITY_PASS {name} {path} sha256={digests['public'][:16]}")
    print("DUAL_ENV_WORKSPACE_PARITY_PASS (UI artifacts only; not backend/permissions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
