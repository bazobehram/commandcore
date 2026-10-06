from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .download import download, download_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST_SCHEMA_VERSION = 1
PRODUCT = "commandcore-agent"
MAX_UPDATE_BYTES = 256 * 1024 * 1024
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    signed = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(
        signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_manifest(manifest: dict[str, Any], public_key_b64: str) -> None:
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported_update_manifest_schema")
    if manifest.get("product") != PRODUCT:
        raise ValueError("wrong_update_product")
    version = str(manifest.get("version", ""))
    if not _VERSION_RE.match(version):
        raise ValueError("invalid_update_version")
    signature_b64 = str(manifest.get("signature", ""))
    if not signature_b64:
        raise ValueError("unsigned_update_manifest")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64, validate=True)
        )
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, canonical_manifest_bytes(manifest))
    except Exception as exc:
        raise ValueError("invalid_update_manifest_signature") from exc
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("update_manifest_has_no_artifacts")


def _semver_key(value: str) -> tuple[int, int, int, int, tuple[tuple[int, str], ...]]:
    match = re.fullmatch(
        r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value
    )
    if not match:
        raise ValueError("invalid_update_version")
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return major, minor, patch, 1, ()
    parts = []
    for part in prerelease.split("."):
        parts.append((0, f"{int(part):020d}") if part.isdigit() else (1, part))
    return major, minor, patch, 0, tuple(parts)


def is_newer_version(candidate: str, current: str) -> bool:
    return _semver_key(candidate) > _semver_key(current)


def normalized_platform() -> str:
    value = platform.system().lower()
    return {"darwin": "macos"}.get(value, value)


def normalized_architecture() -> str:
    value = platform.machine().lower()
    return {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}.get(value, value)


def select_artifact(
    manifest: dict[str, Any],
    *,
    target_platform: str | None = None,
    architecture: str | None = None,
) -> dict[str, Any]:
    target_platform = (target_platform or normalized_platform()).lower()
    architecture = (architecture or normalized_architecture()).lower()
    architecture = {"aarch64": "arm64", "amd64": "x86_64"}.get(
        architecture, architecture
    )
    for item in manifest.get("artifacts", []):
        if not isinstance(item, dict):
            continue
        item_arch = str(item.get("architecture", "")).lower()
        item_arch = {"aarch64": "arm64", "amd64": "x86_64"}.get(item_arch, item_arch)
        if (
            str(item.get("platform", "")).lower() == target_platform
            and item_arch == architecture
        ):
            digest = str(item.get("sha256", "")).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid_update_artifact_sha256")
            url = str(item.get("url", ""))
            if not url:
                raise ValueError("missing_update_artifact_url")
            kind = str(item.get("kind", "executable"))
            if kind != "executable":
                raise ValueError("unsupported_update_artifact_kind")
            return dict(item)
    raise LookupError(f"no_update_artifact_for:{target_platform}/{architecture}")


def _require_safe_url(url: str, allow_insecure_http: bool) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if (
        allow_insecure_http
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        return
    raise ValueError("update_url_must_use_https")


def fetch_manifest(url: str, *, allow_insecure_http: bool = False) -> dict[str, Any]:
    _require_safe_url(url, allow_insecure_http)
    raw = download_bytes(
        url, max_bytes=1024 * 1024, timeout=20, allow_loopback=allow_insecure_http
    )
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid_update_manifest")
    return data


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            out.flush()
            os.fsync(out.fileno())
        if os.name != "nt":
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def stage_artifact(
    manifest: dict[str, Any],
    artifact: dict[str, Any],
    *,
    root: Path,
    allow_insecure_http: bool = False,
    max_bytes: int = MAX_UPDATE_BYTES,
    current_version: str | None = None,
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    url = str(artifact["url"])
    _require_safe_url(url, allow_insecure_http)
    expected = str(artifact["sha256"]).lower()
    declared_size = artifact.get("size")
    if isinstance(declared_size, int) and declared_size > max_bytes:
        raise ValueError("update_artifact_too_large")
    version = str(manifest["version"])
    if (
        current_version
        and not allow_downgrade
        and not is_newer_version(version, current_version)
    ):
        raise ValueError("update_not_newer_than_current")
    stage_dir = root / version
    stage_dir.mkdir(parents=True, exist_ok=True)
    filename = str(
        artifact.get("filename")
        or Path(urlparse(url).path).name
        or "commandcore-agent.update"
    )
    if filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise ValueError("unsafe_update_filename")
    destination = stage_dir / filename
    fd, tmp_name = tempfile.mkstemp(prefix=f".{filename}.", dir=stage_dir)
    digest = hashlib.sha256()
    total = 0
    try:
        os.close(fd)
        download(
            url, Path(tmp_name), max_bytes=max_bytes, allow_loopback=allow_insecure_http
        )
        with open(tmp_name, "rb") as downloaded:
            while chunk := downloaded.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("update_artifact_too_large")
                digest.update(chunk)
        with open(tmp_name, "r+b") as downloaded:
            os.fsync(downloaded.fileno())
        actual = digest.hexdigest()
        if actual != expected:
            raise ValueError("update_artifact_hash_mismatch")
        if isinstance(declared_size, int) and total != declared_size:
            raise ValueError("update_artifact_size_mismatch")
        os.replace(tmp_name, destination)
        metadata = {
            "state_version": 2,
            "status": "staged",
            "product": PRODUCT,
            "version": version,
            "previous_version": current_version,
            "artifact": filename,
            "artifact_kind": str(artifact.get("kind", "executable")),
            "sha256": actual,
            "size": total,
            "manifest_sha256": hashlib.sha256(
                canonical_manifest_bytes(manifest)
            ).hexdigest(),
            "signing_key_id": manifest.get("signing_key_id"),
            # Keep the signed manifest so root activation can re-verify trust
            # instead of trusting mutable metadata written by the Agent user.
            "manifest": manifest,
        }
        meta_path = stage_dir / "stage.json"
        _atomic_json(meta_path, metadata)
        if os.name != "nt":
            os.chmod(destination, 0o600)
            os.chmod(meta_path, 0o600)
        _fsync_dir(stage_dir)
        return {
            **{k: v for k, v in metadata.items() if k != "manifest"},
            "path": str(destination),
            "metadata_path": str(meta_path),
        }
    finally:
        try:
            Path(tmp_name).unlink()
        except FileNotFoundError:
            pass


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), total


def verify_staged(
    stage_metadata_path: Path,
    public_key_b64: str,
    *,
    target_platform: str | None = None,
    architecture: str | None = None,
) -> tuple[dict[str, Any], Path]:
    data = json.loads(stage_metadata_path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("product") != PRODUCT
        or data.get("status") != "staged"
    ):
        raise ValueError("invalid_staged_update_metadata")
    manifest = data.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("staged_update_missing_signed_manifest")
    verify_manifest(manifest, public_key_b64)
    artifact = select_artifact(
        manifest, target_platform=target_platform, architecture=architecture
    )
    if str(manifest.get("version")) != str(data.get("version")):
        raise ValueError("staged_update_version_mismatch")
    filename = str(data.get("artifact", ""))
    if filename != str(
        artifact.get("filename")
        or Path(urlparse(str(artifact.get("url"))).path).name
        or "commandcore-agent.update"
    ):
        raise ValueError("staged_update_artifact_mismatch")
    artifact_path = stage_metadata_path.parent / filename
    if not artifact_path.is_file() or artifact_path.is_symlink():
        raise ValueError("staged_update_artifact_missing_or_unsafe")
    digest, total = _sha256_file(artifact_path)
    if (
        digest != str(artifact.get("sha256", "")).lower()
        or digest != str(data.get("sha256", "")).lower()
    ):
        raise ValueError("staged_update_artifact_hash_mismatch")
    declared_size = artifact.get("size")
    if isinstance(declared_size, int) and total != declared_size:
        raise ValueError("staged_update_artifact_size_mismatch")
    if int(data.get("size", -1)) != total:
        raise ValueError("staged_update_metadata_size_mismatch")
    return data, artifact_path


def _release_metadata(path: Path) -> dict[str, Any]:
    try:
        data = json.loads((path / "release.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _atomic_symlink(link: Path, target: str | None) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if target is None:
        try:
            link.unlink()
        except FileNotFoundError:
            pass
        _fsync_dir(link.parent)
        return
    temp = link.parent / f".{link.name}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        os.symlink(target, temp)
        os.replace(temp, link)
        _fsync_dir(link.parent)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _systemd_restart(service: str) -> None:
    if not _SERVICE_RE.fullmatch(service):
        raise ValueError("invalid_systemd_service_name")
    subprocess.run(["systemctl", "restart", service], check=True, timeout=45)


def _read_health(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def wait_for_health(
    path: Path,
    *,
    expected_version: str,
    not_before: float,
    timeout: float = 45.0,
    poll_interval: float = 0.25,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(timeout, 0.1)
    while time.monotonic() < deadline:
        health = _read_health(path)
        if (
            health
            and health.get("connected") is True
            and str(health.get("version")) == expected_version
        ):
            observed = float(health.get("observed_at_unix", 0.0) or 0.0)
            if observed >= not_before:
                return health
        time.sleep(poll_interval)
    raise TimeoutError("agent_update_health_timeout")


def activate_staged(
    stage_metadata_path: Path,
    public_key_b64: str,
    *,
    install_root: Path,
    health_file: Path,
    service_name: str = "commandcore-agent",
    health_timeout: float = 45.0,
    restart_fn: Callable[[], None] | None = None,
    target_platform: str | None = None,
    architecture: str | None = None,
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    """Install a verified standalone Agent executable and commit or rollback atomically.

    The unprivileged Agent may write the staging directory, so activation always
    re-verifies the signed manifest and artifact hash while running as local
    administrator. `current` is an atomic symlink. A fresh authenticated health
    marker is required after service restart; failure restores the prior target.
    """
    metadata, artifact_path = verify_staged(
        stage_metadata_path,
        public_key_b64,
        target_platform=target_platform,
        architecture=architecture,
    )
    version = str(metadata["version"])
    digest = str(metadata["sha256"])
    release_id = f"{version}-native-{digest[:12]}"
    releases = install_root / "releases"
    release_dir = releases / release_id
    release_dir.mkdir(parents=True, exist_ok=True)
    candidate = release_dir / "commandcore-agent"
    tmp = release_dir / f".commandcore-agent.{os.getpid()}.{time.time_ns()}.tmp"
    shutil.copyfile(artifact_path, tmp, follow_symlinks=False)
    if os.name != "nt":
        os.chmod(tmp, 0o755)
    actual, size = _sha256_file(tmp)
    if actual != digest or size != int(metadata["size"]):
        tmp.unlink(missing_ok=True)
        raise ValueError("activation_copy_verification_failed")
    os.replace(tmp, candidate)
    _atomic_json(
        release_dir / "release.json",
        {
            "schema_version": 1,
            "version": version,
            "implementation": "native",
            "sha256": digest,
            "size": size,
            "installed_at_unix": time.time(),
        },
        mode=0o644,
    )
    _fsync_dir(release_dir)

    current = install_root / "current"
    previous_target = os.readlink(current) if current.is_symlink() else None
    previous_dir = (
        (install_root / previous_target).resolve() if previous_target else None
    )
    previous_meta = (
        _release_metadata(previous_dir)
        if previous_dir and previous_dir.exists()
        else {}
    )
    previous_version = (
        str(previous_meta.get("version")) if previous_meta.get("version") else None
    )
    if (
        previous_version
        and not allow_downgrade
        and not is_newer_version(version, previous_version)
    ):
        raise ValueError("update_not_newer_than_installed")
    candidate_target = str(Path("releases") / release_id)
    rollout_path = install_root / "rollout.json"
    started = time.time()
    rollout = {
        "schema_version": 1,
        "status": "activating",
        "candidate_version": version,
        "candidate_target": candidate_target,
        "previous_target": previous_target,
        "previous_version": previous_version,
        "started_at_unix": started,
    }
    _atomic_json(rollout_path, rollout, mode=0o644)
    restart = restart_fn or (lambda: _systemd_restart(service_name))
    _atomic_symlink(current, candidate_target)
    try:
        restart()
        health = wait_for_health(
            health_file,
            expected_version=version,
            not_before=started,
            timeout=health_timeout,
        )
    except Exception as exc:
        rollback_started = time.time()
        _atomic_symlink(current, previous_target)
        rollback_error: str | None = None
        try:
            restart()
            if previous_version:
                wait_for_health(
                    health_file,
                    expected_version=previous_version,
                    not_before=rollback_started,
                    timeout=health_timeout,
                )
        except Exception as rb_exc:
            rollback_error = str(rb_exc)
        failed = {
            **rollout,
            "status": "rolled_back" if rollback_error is None else "rollback_failed",
            "failed_at_unix": time.time(),
            "error": str(exc),
            "rollback_error": rollback_error,
        }
        _atomic_json(rollout_path, failed, mode=0o644)
        raise RuntimeError(f"update_activation_failed:{failed['status']}") from exc
    committed = {
        **rollout,
        "status": "committed",
        "committed_at_unix": time.time(),
        "health": health,
    }
    _atomic_json(rollout_path, committed, mode=0o644)
    return committed


def rollback_last_update(
    *,
    install_root: Path,
    health_file: Path,
    service_name: str = "commandcore-agent",
    health_timeout: float = 45.0,
    restart_fn: Callable[[], None] | None = None,
) -> dict[str, Any]:
    rollout_path = install_root / "rollout.json"
    data = json.loads(rollout_path.read_text(encoding="utf-8"))
    previous_target = data.get("previous_target")
    previous_version = data.get("previous_version")
    if not previous_target or not previous_version:
        raise ValueError("no_previous_release_available")
    current = install_root / "current"
    started = time.time()
    restart = restart_fn or (lambda: _systemd_restart(service_name))
    _atomic_symlink(current, str(previous_target))
    restart()
    health = wait_for_health(
        health_file,
        expected_version=str(previous_version),
        not_before=started,
        timeout=health_timeout,
    )
    result = {
        **data,
        "status": "manual_rollback",
        "rolled_back_at_unix": time.time(),
        "health": health,
    }
    _atomic_json(rollout_path, result, mode=0o644)
    return result


def rollout_status(install_root: Path) -> dict[str, Any]:
    path = install_root / "rollout.json"
    if not path.exists():
        return {"status": "none"}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {"status": "invalid"}
