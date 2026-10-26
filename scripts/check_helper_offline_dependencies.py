"""Fail-closed check for a complete, binary-only, offline Python wheelhouse.

This verifies dependency closure, not provenance: every wheel must also be
covered by the externally signed release manifest before root installation.
"""

from __future__ import annotations

import email
import zipfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename


def check(wheelhouse: Path, *, python_version: str = "3.12") -> dict:
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ValueError("offline wheelhouse directory missing")
    wheels = sorted(wheelhouse.iterdir())
    if not wheels or len(wheels) > 128:
        raise ValueError("offline wheelhouse size invalid")
    provided = {}
    required = []
    for path in wheels:
        if path.is_symlink() or not path.is_file() or path.suffix != ".whl":
            raise ValueError("only regular wheels allowed")
        name, version, build, tags = parse_wheel_filename(path.name)
        if name in provided:
            raise ValueError("duplicate distribution in wheelhouse")
        with zipfile.ZipFile(path) as z:
            metadata = [x for x in z.namelist() if x.endswith(".dist-info/METADATA")]
            if len(metadata) != 1 or z.testzip() is not None:
                raise ValueError("invalid wheel metadata")
            message = email.message_from_bytes(z.read(metadata[0]))
            if canonicalize_name(message.get("Name", "")) != name:
                raise ValueError("metadata distribution mismatch")
            for expression in message.get_all("Requires-Dist", []):
                req = Requirement(expression)
                if req.marker is not None and not req.marker.evaluate(
                    {
                        "python_version": python_version,
                        "extra": "",
                        "sys_platform": "linux",
                    }
                ):
                    continue
                required.append((name, req))
        provided[name] = version
    if canonicalize_name("commandcore-agent") not in provided:
        raise ValueError("CommandCore Agent wheel missing")
    for parent, req in required:
        dependency = canonicalize_name(req.name)
        if dependency not in provided or provided[dependency] not in req.specifier:
            raise ValueError(
                f"missing or incompatible offline dependency for {parent}: {dependency}"
            )
    return {
        "wheel_count": len(wheels),
        "complete": True,
        "signed_manifest_required": True,
    }
