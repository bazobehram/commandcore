"""Fast disposable Windows CI gates for local users and Scheduled Tasks.

No native build, installer, external network, or personal device is required.
The same PowerShell driver is used by the signed installer acceptance job.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def fixture_env() -> dict[str, str]:
    env = os.environ.copy()
    env["COMMANDCORE_CI_USER_PASSWORD"] = "Cc!" + secrets.token_urlsafe(18).replace(
        "-", "a"
    ).replace("_", "b")
    return env


def run_driver(
    driver: Path, root: Path, mode: str, *, timeout: int
) -> bool:
    env = fixture_env()
    name = "cc" + secrets.token_hex(5)
    result = subprocess.run(
        [
            "pwsh.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(driver),
            "-UserName",
            name,
            "-FixtureRoot",
            str(root),
            "-Origin",
            "https://localhost",
            mode,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    env.pop("COMMANDCORE_CI_USER_PASSWORD", None)
    if result.returncode == 0:
        return True
    # Fixed diagnostic codes only; no raw stdout/stderr, user, path or password.
    for key in (
        "CI_INSTALL_STAGE",
        "CI_USER_CREATE_CATEGORY",
        "CI_USER_CREATE_HRESULT",
        "CI_USER_CREATE_ERROR_CLASS",
        "CI_USER_CREATE_ERROR_ID",
        "CI_USER_CREATE_EXCEPTION_TYPE",
        "CI_USER_CREATE_MESSAGE_HINT",
        "CI_TASK_LAST_RESULT",
        "CI_TASK_STATE",
        "CI_TASK_DIAGNOSTIC",
    ):
        found = re.findall(rf"(?m)^{key}:([-A-Za-z0-9_]+)\s*$", result.stdout)
        if found:
            print("FAIL: " + key + "=" + found[-1])
    return False


def main() -> int:
    if os.name != "nt" or os.environ.get("CI") != "true":
        print("NOT_RUN: disposable Windows CI runner required")
        return 2
    root = Path(os.environ["PROGRAMDATA"])
    driver = Path(__file__).resolve().with_name("windows_signed_installer_driver.ps1")
    if not run_driver(driver, root, "-OnlyAccount", timeout=30):
        return 1
    print("PASS: disposable Windows local-account creation/cleanup")
    with tempfile.TemporaryDirectory(prefix="commandcore-task-preflight-", dir=root) as tmp:
        fixture = Path(tmp)
        (fixture / "installers").mkdir()
        (fixture / "result").mkdir()
        shutil.copyfile(
            Path(__file__).resolve().with_name("windows_task_preflight_worker.ps1"),
            fixture / "installers" / "worker.ps1",
        )
        if not run_driver(driver, fixture, "-OnlyTask", timeout=40):
            return 1
    print("PASS: disposable Windows standard-user Scheduled Task/cleanup")
    return 0


if __name__ == "__main__":
    sys.exit(main())
