#!/usr/bin/env python3
"""Fail closed on private branding, stale private artifacts, and broken doc links."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BANNED_TEXT = {
    "private brand": "syn" + "ovaq",
    "private device": "ascent-" + "g" + "x10",
    "private device family": "g" + "x10",
    "private host": "home" + "server",
    "private disposable device": "disposable" + "-linux-v1",
    "private disposable host": "commandcore-" + "linux-v1",
    "private project": "de" + "vim",
    "private oauth tenant": "dev-dq08t0q7q57n" + "5bc5",
}

BANNED_PATHS = {
    "docs/FINAL_HANDOFF_PROMPT.md",
    "docs/" + "HOME" + "SERVER_AGENT_PROMPT.md",
    "docs/RC4_ACCEPTANCE.md",
    "docs/RC4_HARDENING.md",
    "docs/RC5_ACCEPTANCE.md",
    "docs/RC5_INCIDENT.md",
    "docs/RC6_DUAL_STACK.md",
    "docs/RC7_LOCAL_ACTIVITY_RELEASE.md",
    "docs/auth0-verification-policy.md",
    "docs/LICENSE_DECISION.md",
    "docs/DESKTOP_COMMANDER_REUSE.md",
    "docs/V1_RELEASE_CHECKLIST.md",
    "BUILD_INFO.md",
    "release-hardening.Dockerfile",
    "scripts/linux_resilience_acceptance.py",
    "scripts/linux_installer_lifecycle_acceptance.py",
    "scripts/linux_transport_pressure_acceptance.py",
    "scripts/linux_user_manager_acceptance.py",
    "scripts/linux_systemd_lifecycle.py",
}

BANNED_SUFFIXES = {".tar", ".gz", ".zip", ".pyc"}
SKIP_DIRS = {".git", ".venv", "target", "__pycache__", "node_modules", ".pytest_cache"}
TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".sh",
    ".ps1",
    ".html",
    ".css",
    ".js",
    ".mjs",
    ".rs",
    ".service",
    ".example",
    ".lock",
}
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def text_of(path: Path) -> str | None:
    if path.name in {
        "Dockerfile",
        "Makefile",
        ".gitignore",
        ".dockerignore",
        ".gitattributes",
    }:
        pass
    elif path.suffix.lower() not in TEXT_SUFFIXES:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def check_links(path: Path, text: str, errors: list[str]) -> None:
    if path.suffix.lower() != ".md":
        return
    for match in LINK_RE.finditer(text):
        target = match.group(1).strip()
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        candidate = (path.parent / target).resolve()
        try:
            candidate.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(
                f"{path.relative_to(ROOT)}: link escapes repository: {target}"
            )
            continue
        if not candidate.exists():
            errors.append(f"{path.relative_to(ROOT)}: broken relative link: {target}")


def main() -> int:
    errors: list[str] = []

    for rel in BANNED_PATHS:
        if (ROOT / rel).exists():
            errors.append(f"private/internal artifact must not ship: {rel}")

    for path in files():
        rel = path.relative_to(ROOT)
        if path.suffix.lower() in BANNED_SUFFIXES:
            errors.append(f"generated/archive artifact must not be tracked: {rel}")

        text = text_of(path)
        if text is None:
            continue
        low = text.lower()
        for label, token in BANNED_TEXT.items():
            if token.lower() in low:
                errors.append(f"{rel}: contains {label} token")
        check_links(path, text, errors)

    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace")
    if "GNU AFFERO GENERAL PUBLIC LICENSE" not in license_text:
        errors.append("LICENSE is not the GNU Affero General Public License text")

    metadata = [
        ROOT / "pyproject.toml",
        ROOT / "agent/pyproject.toml",
        ROOT / "agent/rust/Cargo.toml",
    ]
    for path in metadata:
        text = path.read_text(encoding="utf-8")
        if "AGPL-3.0-or-later" not in text:
            errors.append(
                f"{path.relative_to(ROOT)}: missing AGPL-3.0-or-later metadata"
            )

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    version_checks = {
        "pyproject.toml": rf'^version = "{re.escape(version)}"$',
        "agent/pyproject.toml": rf'^version = "{re.escape(version)}"$',
        "agent/rust/Cargo.toml": rf'^version = "{re.escape(version)}"$',
        "apps/server/commandcore_server/__init__.py": rf'^__version__ = "{re.escape(version)}"$',
        "docker-compose.yml": re.escape(f"${{COMMANDCORE_VERSION:-{version}}}"),
        ".env.example": rf"^COMMANDCORE_RECOMMENDED_AGENT_VERSION={re.escape(version)}$",
    }
    for rel, pattern in version_checks.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        if not re.search(pattern, text, re.MULTILINE):
            errors.append(f"{rel}: version is not consistent with VERSION={version}")

    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for setting in (
        "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED=false",
        "COMMANDCORE_RECOVERY_ENABLED=false",
    ):
        if not re.search(rf"^{re.escape(setting)}$", env_example, re.MULTILINE):
            errors.append(f".env.example: unsafe default, expected {setting}")

    config_text = (ROOT / "apps/server/commandcore_server/config.py").read_text(
        encoding="utf-8"
    )
    safe_defaults = {
        "public bootstrap": "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED",
        "recovery": "COMMANDCORE_RECOVERY_ENABLED",
    }
    for label, variable in safe_defaults.items():
        pattern = rf'_bool\(\s*"{re.escape(variable)}",\s*False\s*\)'
        if not re.search(pattern, config_text):
            errors.append(f"server config: {label} must default to disabled")

    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    if '"127.0.0.1:8787:8787"' not in compose_text:
        errors.append(
            "docker-compose.yml: public example must bind port 8787 to localhost"
        )

    if errors:
        print("Public repository policy check FAILED:")
        for error in sorted(set(errors)):
            print(f"  - {error}")
        return 1

    print("Public repository policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
