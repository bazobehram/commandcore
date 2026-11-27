#!/usr/bin/env python3
"""Verify the running server's application bytes against a clean release checkout.

Unlike the overlay-only audit, this detects stale images, parent-directory
mounts, in-container edits and missing or extra MCP/UI assets. It never
reads /data, distribution, environment variables, or private configuration.
The expected image ID must come from a separately verified release digest.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

APP_ROOTS = ("apps/server/commandcore_server", "apps/web")
MAX_FILES = 4096
MAX_BYTES = 128 * 1024 * 1024


def inventory(roots):
    """Hash all installed application files, excluding Python bytecode caches."""
    found = {}
    total = 0
    for prefix, root in roots.items():
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("application root missing or symbolic link")
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for name in dirs:
                if (Path(directory) / name).is_symlink():
                    raise ValueError("symbolic link in application directory")
            for name in sorted(files):
                path = Path(directory) / name
                if path.suffix in (".pyc", ".pyo"):
                    continue
                if path.is_symlink() or not path.is_file():
                    raise ValueError("nonregular application file")
                total += path.stat().st_size
                if total > MAX_BYTES or len(found) >= MAX_FILES:
                    raise ValueError("application inventory exceeds limit")
                key = prefix + "/" + path.relative_to(root).as_posix()
                with path.open("rb") as handle:
                    found[key] = hashlib.file_digest(handle, "sha256").hexdigest()
    if not found:
        raise ValueError("empty application inventory")
    return found


def run(*args):
    return subprocess.run(
        args, capture_output=True, text=True, timeout=30, check=True
    ).stdout


def source_inventory(root):
    """Use committed file paths, rejecting modified tracked source."""
    if run(
        "git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"
    ).strip():
        raise ValueError("release checkout has tracked changes")
    revision = run("git", "-C", str(root), "rev-parse", "HEAD").strip()
    paths = run("git", "-C", str(root), "ls-files", "-z", "--", *APP_ROOTS)
    expected = {}
    for name in paths.split("\0"):
        if not name:
            continue
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("nonregular committed application file")
        with path.open("rb") as handle:
            expected[name] = hashlib.file_digest(handle, "sha256").hexdigest()
    if not expected:
        raise ValueError("empty source inventory")
    return revision, expected


def intersecting_mounts(mounts, roots):
    """Reject every mount intersecting an app root, including parent mounts."""
    blocked = []
    for mount in mounts:
        destination = PurePosixPath(mount["Destination"])
        if not destination.is_absolute() or ".." in destination.parts:
            raise ValueError("invalid mount destination")
        for root in roots:
            app = PurePosixPath(root)
            if (
                destination == app
                or destination in app.parents
                or app in destination.parents
            ):
                # Report only the affected application root, not host paths.
                blocked.append(str(app))
    return sorted(set(blocked))


def compare(expected, actual):
    return {
        "missing": sorted(expected.keys() - actual.keys()),
        "extra": sorted(actual.keys() - expected.keys()),
        "changed": sorted(
            k for k in expected.keys() & actual.keys() if expected[k] != actual[k]
        ),
    }


def container_identity(container):
    # No Config.Env, mount sources, or secret values leave Docker.
    raw = run(
        "docker",
        "inspect",
        "--type",
        "container",
        "--format",
        "{{json .Id}} {{json .Image}} {{json .State.StartedAt}} {{json .State.Running}} {{json .Mounts}}",
        container,
    ).strip()
    decoder = json.JSONDecoder()
    values = []
    for _ in range(5):
        item, end = decoder.raw_decode(raw.lstrip())
        values.append(item)
        raw = raw.lstrip()[end:]
    ident, image, started, running, mounts = values
    if raw.strip() or not running or not isinstance(mounts, list):
        raise ValueError("invalid or stopped container")
    # Strip host sources immediately.
    return (
        ident,
        image,
        started,
        sorted(
            ({"Destination": m["Destination"]} for m in mounts),
            key=lambda mount: mount["Destination"],
        ),
    )


def live_inventory(container_id):
    # Run only a bounded application-file hashing operation inside the container.
    program = (
        "import hashlib,json,os,sysconfig\nfrom pathlib import Path\n"
        + f"MAX_FILES={MAX_FILES}\nMAX_BYTES={MAX_BYTES}\n"
        + inspect.getsource(inventory)
        + "\nroots={'apps/server/commandcore_server': "
        "str(Path(sysconfig.get_path('purelib'))/'commandcore_server'),"
        "'apps/web': str(Path(sysconfig.get_path('data'))/'share/commandcore/web')}\n"
        "print(json.dumps({'roots':list(roots.values()),'files':inventory(roots)},sort_keys=True))\n"
    )
    data = json.loads(
        run("docker", "exec", container_id, "python", "-B", "-c", program)
    )
    if len(data["roots"]) != 2 or not isinstance(data["files"], dict):
        raise ValueError("invalid runtime inventory")
    return data


def audit(container, root, expected_image):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image):
        raise ValueError("expected immutable image ID required")
    revision, expected = source_inventory(root)
    before = container_identity(container)
    ident, image, _, mounts = before
    live = live_inventory(ident)
    label = run(
        "docker",
        "image",
        "inspect",
        "--format",
        '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        image,
    ).strip()
    after = container_identity(container)
    if before != after:
        raise ValueError("container identity changed during audit")
    delta = compare(expected, live["files"])
    blocked_mounts = intersecting_mounts(mounts, live["roots"])
    problems = []
    if image != expected_image:
        problems.append("image_id_mismatch")
    if label != revision:
        problems.append("source_revision_mismatch")
    if blocked_mounts:
        problems.append("application_mounts")
    if any(delta.values()):
        problems.append("application_bytes_mismatch")
    return {
        "gate": "BLOCK" if problems else "PASS",
        "source_commit": revision,
        "expected_image_id": expected_image,
        "actual_image_id": image,
        "image_revision": label,
        "expected_files": len(expected),
        "actual_files": len(live["files"]),
        "intersecting_application_mounts": blocked_mounts,
        "differences": delta,
        "problems": problems,
        "scope": "server Python package and packaged web/MCP assets only",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--expected-image-id", required=True)
    args = parser.parse_args()
    try:
        report = audit(args.container, args.source_root, args.expected_image_id)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({"gate": "BLOCK", "error": type(exc).__name__}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["gate"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
