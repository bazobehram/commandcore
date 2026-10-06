"""Generate application dependency CycloneDX inventories from the build environment."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from datetime import UTC, datetime
from importlib.metadata import distributions
from pathlib import Path


def bom(components):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": datetime.now(UTC).isoformat()},
        "components": sorted(components, key=lambda item: item["name"].lower()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--outdir", type=Path)
    args = parser.parse_args()
    out = args.outdir or args.root / "docs/sbom"
    out.mkdir(parents=True, exist_ok=True)
    lock = (args.root / "requirements-server.lock").read_text()
    pins = {
        name.lower().replace("_", "-"): version
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==([^\s]+)", lock, re.MULTILINE
        )
    }
    python = []
    for distribution in distributions():
        name = distribution.metadata["Name"]
        normalized = name.lower().replace("_", "-")
        if normalized not in pins:
            continue
        if pins[normalized] != distribution.version:
            raise RuntimeError(f"Build environment does not match lock: {name}")
        component = {
            "type": "library",
            "name": name,
            "version": distribution.version,
            "purl": f"pkg:pypi/{normalized}@{distribution.version}",
        }
        expression = distribution.metadata.get("License-Expression")
        if expression:
            component["licenses"] = [{"expression": expression}]
        python.append(component)
    if len(python) != len(pins):
        raise RuntimeError("Build environment is missing locked runtime distributions")
    cargo = tomllib.loads((args.root / "agent/rust/Cargo.lock").read_text())
    recorded = json.loads((args.root / "docs/dependency-inventory.json").read_text())
    licenses = {
        (package["name"], package["version"]): package.get("license")
        for package in recorded["rust"]
    }
    rust = []
    for package in cargo["package"]:
        if package.get("source", "").startswith("registry+"):
            component = {
                "type": "library",
                "name": package["name"],
                "version": package["version"],
                "purl": f"pkg:cargo/{package['name']}@{package['version']}",
                "hashes": [{"alg": "SHA-256", "content": package["checksum"]}],
            }
            expression = licenses.get((package["name"], package["version"]))
            if expression:
                component["licenses"] = [{"expression": expression}]
            rust.append(component)
    (out / "server.cdx.json").write_text(json.dumps(bom(python), indent=2) + "\n")
    (out / "rust-agent.cdx.json").write_text(json.dumps(bom(rust), indent=2) + "\n")
    print(
        f"Inventories: {len(python)} locked server packages; {len(rust)} locked registry crates. These exclude OS libraries and do not certify license clearance."
    )


if __name__ == "__main__":
    main()
