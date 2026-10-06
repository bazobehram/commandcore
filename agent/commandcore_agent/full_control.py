"""Explicit local administration of an installed Linux privileged helper."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from .helper_client import HelperClient
from .root_trust import check_root_directory, read_root_file

POLICY = Path("/etc/commandcore/agent-policy.json")
SECRET = Path("/etc/commandcore/helper.key")
HELPER = Path("/opt/commandcore-agent/helper/venv/bin/commandcore-helper")
UNIT = Path("/etc/systemd/system/commandcore-helper.service")


def _write_policy(policy: dict) -> None:
    check_root_directory(POLICY.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".policy-", dir=POLICY.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(policy, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, POLICY)
    finally:
        Path(temporary).unlink(missing_ok=True)


def configure(enable: bool, agent_user: str, acknowledge: bool = False) -> int:
    if sys.platform != "linux" or os.geteuid() != 0:
        print(
            "This command requires local root on Linux. Windows helper support is not available.",
            file=sys.stderr,
        )
        return 1
    import grp
    import pwd

    changed = False
    try:
        if enable:
            account = pwd.getpwnam(agent_user)
            if account.pw_uid == 0:
                raise ValueError("The network Agent must run as a nonroot account")
            # The helper runtime is installed separately from user-writable Agent releases.
            read_root_file(HELPER)
            check_root_directory(HELPER.parent)
            runtime = HELPER.parents[2]
            for item in runtime.rglob("*"):
                info = item.lstat()
                if info.st_uid != 0 or (not item.is_symlink() and info.st_mode & 0o022):
                    raise PermissionError(
                        "Privileged helper runtime contains an untrusted writable path"
                    )
                if item.is_symlink():
                    resolved = item.resolve(strict=True)
                    if resolved.is_dir():
                        check_root_directory(resolved)
                    else:
                        read_root_file(resolved)
            if not os.access(HELPER, os.X_OK):
                raise ValueError("Installed helper is not executable")
            if UNIT.exists():
                unit = read_root_file(UNIT).decode()
                if (
                    "[Service]" not in unit
                    or "CommandCore Privileged Helper" not in unit
                    or "commandcore-helper" not in unit
                ):
                    raise ValueError("Refusing to replace an unrelated systemd unit")
            print(
                "FULL_CONTROL permits root administration through authenticated local IPC.\n"
                "Only explicitly granted OAuth principals can request it. This changes no server grant.\n"
                "Restart your Agent after enabling the helper."
            )
            if not acknowledge and (
                not sys.stdin.isatty()
                or input("Type ENABLE FULL_CONTROL to continue: ")
                != "ENABLE FULL_CONTROL"
            ):
                raise ValueError("Local FULL_CONTROL acknowledgement required")
        if POLICY.exists():
            policy = json.loads(read_root_file(POLICY))
            if not isinstance(policy, dict):
                raise ValueError("Existing policy must be an object")
        else:
            if not enable:
                print("No local privileged policy exists; FULL_CONTROL is disabled.")
                return 0
            POLICY.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            check_root_directory(POLICY.parent)
            policy = {}
        if enable:
            if SECRET.exists():
                read_root_file(SECRET, secret=True)
            else:
                descriptor = os.open(
                    SECRET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(secrets.token_bytes(48))
            os.chown(SECRET, 0, account.pw_gid)
            SECRET.chmod(0o640)
            unit = (
                "[Unit]\nDescription=CommandCore Privileged Helper\nAfter=local-fs.target\n"
                "[Service]\nType=simple\nUser=root\nGroup=root\n"
                "Environment=COMMANDCORE_AGENT_POLICY=/etc/commandcore/agent-policy.json\n"
                "Environment=COMMANDCORE_HELPER_SECRET=/etc/commandcore/helper.key\n"
                "Environment=COMMANDCORE_HELPER_SOCKET=/run/commandcore/helper.sock\n"
                f"Environment=COMMANDCORE_HELPER_SOCKET_GROUP={grp.getgrgid(account.pw_gid).gr_name}\n"
                "Environment=COMMANDCORE_HELPER_AUDIT=/var/log/commandcore/helper-audit.jsonl\n"
                f"ExecStart={HELPER} serve\nRestart=on-failure\nRuntimeDirectory=commandcore\n"
                "RuntimeDirectoryMode=0755\nLogsDirectory=commandcore\nLogsDirectoryMode=0750\n"
                "[Install]\nWantedBy=multi-user.target\n"
            )
            # Keep the old unit if it already matches an installed trusted helper.
            if not UNIT.exists():
                UNIT.write_text(unit, encoding="utf-8")
                UNIT.chmod(0o644)
            policy["allowed_helper_uids"] = [account.pw_uid]
            # Fail closed if service activation fails: publish FULL_CONTROL only after it starts.
            policy["configured_max_permission_profile"] = "STANDARD"
            _write_policy(policy)
            changed = True
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(
                ["systemctl", "enable", "--now", "commandcore-helper.service"],
                check=True,
            )
            subprocess.run(
                ["systemctl", "restart", "commandcore-helper.service"], check=True
            )
            policy["configured_max_permission_profile"] = "FULL_CONTROL"
            _write_policy(policy)
            probe = asyncio.run(
                HelperClient("/run/commandcore/helper.sock", str(SECRET)).probe()
            )
            if (
                not probe.get("available")
                or probe.get("max_permission_profile") != "FULL_CONTROL"
            ):
                raise ValueError("Authenticated helper health check failed")
        else:
            # Lower authority before stopping the service; requests re-read this policy.
            policy["configured_max_permission_profile"] = "STANDARD"
            _write_policy(policy)
            subprocess.run(
                ["systemctl", "disable", "--now", "commandcore-helper.service"],
                check=True,
            )
        print(
            "Local ceiling: "
            + ("FULL_CONTROL" if enable else "STANDARD")
            + ". Server grants are unchanged."
        )
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        if enable and changed:
            policy["configured_max_permission_profile"] = "STANDARD"
            _write_policy(policy)
        print(
            f"Local helper configuration failed: {exc}\nInstall the separately reviewed root helper runtime first; do not run a user-writable helper as root.",
            file=sys.stderr,
        )
        return 1
