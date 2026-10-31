"""Fast Windows CI preflight: prove disposable standard user can be created.

No installer, network, runner secrets or personal device required. The same
PowerShell driver is reused by the full signed installer acceptance test.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if os.name != "nt" or os.environ.get("CI") != "true":
        print("NOT_RUN: disposable Windows CI runner required")
        return 2
    env = os.environ.copy()
    env["COMMANDCORE_CI_USER_PASSWORD"] = "Cc!" + secrets.token_urlsafe(18).replace(
        "-", "a"
    ).replace("_", "b")
    name = "cc" + secrets.token_hex(5)
    driver = Path(__file__).resolve().with_name("windows_signed_installer_driver.ps1")
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(driver),
            "-UserName",
            name,
            "-FixtureRoot",
            os.environ["PROGRAMDATA"],
            "-Origin",
            "https://localhost",
            "-OnlyAccount",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    env.pop("COMMANDCORE_CI_USER_PASSWORD", None)
    if result.returncode == 0:
        print("PASS: disposable Windows local-account creation/cleanup")
        return 0
    # Only print fixed diagnostic identifiers or a numeric HRESULT. Never log
    # the complete PowerShell output, arguments, username or temporary password.
    for key in (
        "CI_INSTALL_STAGE",
        "CI_USER_CREATE_CATEGORY",
        "CI_USER_CREATE_HRESULT",
        "CI_USER_CREATE_ERROR_CLASS",
    ):
        found = re.findall(rf"(?m)^{key}:([-A-Za-z0-9_]+)\s*$", result.stdout)
        if found:
            print("FAIL: " + key + "=" + found[-1])
    return 1


if __name__ == "__main__":
    sys.exit(main())
