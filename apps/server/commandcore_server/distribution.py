"""Public, read-only routes for explicitly published release files."""

import base64
import hashlib
import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response


def _read_published(root: Path, name: str, limit: int) -> bytes:
    path = root / name
    if path.resolve() != path or not path.is_file():
        raise ValueError("unpublished file")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError("invalid published file size")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate release field")
        result[key] = value
    return result


def _standard_linux_script(root: Path, public_base_url: str) -> str:
    """Only generate a Standard wrapper for an explicitly pinned signed local feed.

    The operator verifies artifact provenance and lifecycle before publication.
    At runtime verify the signed manifest, pinned script and artifact presence;
    the installer verifies downloaded artifact bytes again before activation.
    """
    config = json.loads(
        _read_published(root, "linux-standard-onboarding.json", 8192),
        object_pairs_hook=_unique_object,
    )
    if (
        not isinstance(config, dict)
        or set(config)
        != {"schema_version", "server_url", "agent_public_key_b64", "installer_sha256"}
        or config["schema_version"] != 1
    ):
        raise ValueError("invalid onboarding config")
    origin = config["server_url"]
    if not isinstance(origin, str):
        raise TypeError("invalid origin")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(ord(c) <= 32 or ord(c) == 127 for c in origin)
        or origin.rstrip("/") != public_base_url.rstrip("/")
    ):
        raise ValueError("release origin mismatch")
    origin = origin.rstrip("/")
    public = base64.b64decode(config["agent_public_key_b64"], validate=True)
    if len(public) != 32:
        raise ValueError("invalid public key")
    script = _read_published(root, "linux.sh", 65536)
    if hashlib.sha256(script).hexdigest() != config["installer_sha256"]:
        raise ValueError("installer pin mismatch")
    body = script.decode("utf-8")
    if (
        not body.startswith("#!/bin/sh\n")
        or "--no-full-control-preparation" not in body
    ):
        raise ValueError("unsupported installer")
    manifest = json.loads(
        _read_published(root, "manifest.json", 1048576),
        object_pairs_hook=_unique_object,
    )
    if not isinstance(manifest, dict):
        raise TypeError("invalid manifest")
    version = manifest.get("version")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("product") != "commandcore-agent"
        or not isinstance(version, str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", version)
        or manifest.get("signing_key_id") != hashlib.sha256(public).hexdigest()[:16]
    ):
        raise ValueError("invalid manifest identity")
    signature = base64.b64decode(manifest["signature"], validate=True)
    Ed25519PublicKey.from_public_bytes(public).verify(
        signature,
        json.dumps(
            {k: v for k, v in manifest.items() if k != "signature"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode(),
    )
    names = {
        "x86_64": "commandcore-agent-linux-x86_64",
        "arm64": "commandcore-agent-linux-arm64",
    }
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise ValueError("both native Linux architectures required")
    seen = set()
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("architecture"), str):
            raise TypeError("invalid artifact")
        arch = item["architecture"]
        if arch in seen or arch not in names:
            raise ValueError("duplicate or unsupported architecture")
        seen.add(arch)
        name = names[arch]
        relative = f"{version}/{name}"
        file = root / relative
        size = item["size"]
        if (
            item.get("filename") != name
            or item.get("platform") != "linux"
            or item.get("kind") != "executable"
            or item.get("implementation", "rust") != "rust"
            or item.get("url") != f"{origin}/releases/agent/{relative}"
            or not isinstance(item.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
            or type(size) is not int
            or not 0 < size <= 134217728
            or file.resolve() != file
            or not file.is_file()
            or file.stat().st_size != size
        ):
            raise ValueError("invalid or missing artifact")
    return (
        "#!/bin/sh\n# Reviewed Standard-only installation pins.\n"
        + "export COMMANDCORE_RELEASE_PUBLIC_KEY_B64="
        + shlex.quote(config["agent_public_key_b64"])
        + "\n"
        + "set -- --server "
        + shlex.quote(origin)
        + " --no-full-control-preparation\n"
        + body
    )


def install_distribution_routes(
    app: FastAPI, directory: str, *, public_base_url: str = ""
) -> None:
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

    @app.api_route(
        "/install/linux-standard-ready",
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )
    def linux_standard_ready():
        try:
            if root is None:
                raise ValueError("unpublished")
            content = _standard_linux_script(root, public_base_url)
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
            InvalidSignature,
        ):
            raise HTTPException(503, "Signed Standard installer is not ready") from None
        return Response(
            content=content,
            media_type="text/x-shellscript",
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        )

    def one_command_linux_script() -> str:
        # The published feed operator supplies *public*, out-of-band-reviewed
        # release pins. Never retrieve trust anchors from the helper artifact.
        if root is None:
            raise HTTPException(503, "Signed one-command installer is not published")
        settings = root / "linux-onboarding.json"
        script = root / "linux.sh"
        if any(f.resolve() != f or not f.is_file() for f in (settings, script)):
            raise HTTPException(503, "Signed one-command installer is not published")
        if settings.stat().st_size > 8192 or script.stat().st_size > 65536:
            raise HTTPException(503, "Invalid published onboarding assets")
        try:

            def unique_keys(pairs):
                values = {}
                for key, value in pairs:
                    if key in values:
                        raise ValueError("Duplicate onboarding field")
                    values[key] = value
                return values

            data = json.loads(settings.read_text(), object_pairs_hook=unique_keys)
            keys = {
                "schema_version",
                "server_url",
                "agent_public_key_b64",
                "helper_release_url",
                "helper_public_key_b64",
                "helper_release_version",
                "helper_bootstrap_url",
                "helper_bootstrap_sha256",
            }
            if set(data) != keys or data["schema_version"] != 1:
                raise ValueError("Wrong onboarding schema")
            for field in ("agent_public_key_b64", "helper_public_key_b64"):
                if len(base64.b64decode(data[field], validate=True)) != 32:
                    raise ValueError("Invalid Ed25519 public key")
            if not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", data["helper_release_version"]
            ):
                raise ValueError("Invalid helper release version")
            if not re.fullmatch(r"[a-f0-9]{64}", data["helper_bootstrap_sha256"]):
                raise ValueError("Invalid helper bootstrap digest")
            for field in ("server_url", "helper_release_url", "helper_bootstrap_url"):
                url = urlsplit(data[field])
                if (
                    url.scheme != "https"
                    or not url.hostname
                    or url.username
                    or url.password
                    or url.query
                    or url.fragment
                    or any(ord(c) < 33 or ord(c) == 127 for c in data[field])
                ):
                    raise ValueError("Invalid onboarding HTTPS URL")
            if urlsplit(data["server_url"]).path not in ("", "/"):
                raise ValueError("Server URL must be an HTTPS origin")
            body = script.read_text()
            if (
                not body.startswith("#!/bin/sh\n")
                or "--prepare-full-control" not in body
            ):
                raise ValueError("Published installer cannot prepare the helper")
        except (
            OSError,
            UnicodeError,
            TypeError,
            KeyError,
            ValueError,
            base64.binascii.Error,
        ):
            raise HTTPException(
                503, "Signed one-command installer is not ready"
            ) from None
        exports = {
            "COMMANDCORE_RELEASE_PUBLIC_KEY_B64": data["agent_public_key_b64"],
            "COMMANDCORE_HELPER_RELEASE_URL": data["helper_release_url"],
            "COMMANDCORE_HELPER_RELEASE_PUBLIC_KEY_B64": data["helper_public_key_b64"],
            "COMMANDCORE_HELPER_RELEASE_VERSION": data["helper_release_version"],
            "COMMANDCORE_HELPER_BOOTSTRAP_URL": data["helper_bootstrap_url"],
            "COMMANDCORE_HELPER_BOOTSTRAP_SHA256": data["helper_bootstrap_sha256"],
        }
        prefix = "#!/bin/sh\n# Public, reviewed installation pins; never contains private keys.\n"
        for name, value in exports.items():
            prefix += f"export {name}={shlex.quote(value)}\n"
        prefix += f"set -- --server {shlex.quote(data['server_url'])} --prepare-full-control\n"
        return prefix + body

    @app.api_route(
        "/install/linux-ready", methods=["GET", "HEAD"], include_in_schema=False
    )
    def linux_ready():
        content = one_command_linux_script()
        return Response(
            content=content,
            media_type="text/x-shellscript",
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        )

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

    @app.api_route(
        "/releases/helper/{release_id}/{filename}",
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )
    def helper_release_file(release_id: str, filename: str):
        # Immutable, architecture- and Python-specific releases. A caller
        # cannot request secret files or arbitrary paths from the feed.
        scope = re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?-linux-(x86_64|arm64)-py3(11|12|13)",
            release_id,
        )
        if scope is None:
            raise HTTPException(404, "Unknown signed helper release")
        arch = scope.group(1)
        if filename == "manifest.signed.json":
            media = "application/json"
        elif filename == f"commandcore-helper-linux-{arch}.tar.gz":
            media = "application/octet-stream"
        elif (
            re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,180}\.whl", filename)
            and ".." not in filename
        ):
            media = "application/octet-stream"
        else:
            raise HTTPException(404, "Unknown signed helper artifact")
        return published(f"helpers/{release_id}/{filename}", media, True)
