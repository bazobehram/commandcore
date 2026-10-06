"""Public, read-only routes for explicitly published release files."""

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse


def install_distribution_routes(app: FastAPI, directory: str) -> None:
    root = Path(directory).absolute() if directory else None

    def published(relative: str, media_type: str, immutable: bool = False):
        if root is None:
            raise HTTPException(404, "Distribution is not published")
        file = root / relative
        # No directory listings, arbitrary paths, or symlinks outside the feed.
        if file.resolve() != file or not file.is_file():
            raise HTTPException(404, "Release file is not published")
        return FileResponse(
            file,
            media_type=media_type,
            headers={
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "public, max-age=31536000, immutable"
                if immutable
                else "no-cache",
            },
        )

    @app.get("/install/linux", include_in_schema=False)
    @app.head("/install/linux", include_in_schema=False)
    def linux_installer():
        return published("linux.sh", "text/x-shellscript")

    @app.get("/install/uninstall-linux", include_in_schema=False)
    @app.head("/install/uninstall-linux", include_in_schema=False)
    def linux_uninstaller():
        return published("uninstall-linux.sh", "text/x-shellscript")

    @app.get("/install/windows", include_in_schema=False)
    @app.head("/install/windows", include_in_schema=False)
    def windows_installer():
        return published("windows.ps1", "text/plain")

    @app.get("/install/uninstall-windows", include_in_schema=False)
    @app.head("/install/uninstall-windows", include_in_schema=False)
    def windows_uninstaller():
        return published("uninstall-windows.ps1", "text/plain")

    @app.get("/releases/agent/manifest.json", include_in_schema=False)
    @app.head("/releases/agent/manifest.json", include_in_schema=False)
    def current_manifest():
        return published("manifest.json", "application/json")

    @app.get("/releases/agent/{version}/{filename}", include_in_schema=False)
    @app.head("/releases/agent/{version}/{filename}", include_in_schema=False)
    def version_file(version: str, filename: str):
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
            raise HTTPException(404, "Unknown release")
        if filename == "manifest.json":
            return published(f"{version}/manifest.json", "application/json", True)
        if filename == "linux.sh":
            return published(f"{version}/linux.sh", "text/x-shellscript", True)
        if filename not in {
            "commandcore-agent-linux-x86_64",
            "commandcore-agent-linux-arm64",
            "commandcore-agent-windows-x86_64.exe",
        }:
            raise HTTPException(404, "Unknown artifact")
        return published(f"{version}/{filename}", "application/octet-stream", True)
