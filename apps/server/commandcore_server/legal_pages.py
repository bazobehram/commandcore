"""Serve only explicitly published public policy documents.

Policy text is supplied and reviewed by the operator; the app does not create
or publish legal promises automatically.
"""

import stat
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

MAX_POLICY_BYTES = 131_072


def install_legal_pages(app: FastAPI, directory: str) -> None:
    root = Path(directory).absolute() if directory else None

    def approved_page(name: str) -> Response:
        if root is None:
            raise HTTPException(404, "Approved public policy is not published")
        document = root / name
        try:
            details = document.lstat()
            if not stat.S_ISREG(details.st_mode) or document.resolve() != document:
                raise ValueError("Policy must be a regular file without symlinks")
            if not 0 < details.st_size <= MAX_POLICY_BYTES:
                raise ValueError("Policy file size is outside allowed bounds")
            content = document.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            raise HTTPException(
                404, "Approved public policy is not published"
            ) from None
        return Response(
            content=content,
            media_type="text/html",
            headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
        )

    @app.api_route("/privacy", methods=["GET", "HEAD"], include_in_schema=False)
    def privacy() -> Response:
        return approved_page("privacy.html")

    @app.api_route("/terms", methods=["GET", "HEAD"], include_in_schema=False)
    def terms() -> Response:
        return approved_page("terms.html")
