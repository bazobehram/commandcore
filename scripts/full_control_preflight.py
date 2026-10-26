"""Read-only Linux Full Control capability preflight; no privilege elevation."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

POLICY = Path("/etc/commandcore/agent-policy.json")
HELPER = Path("/opt/commandcore-agent/helper/venv/bin/commandcore-helper")
UNIT = Path("/etc/systemd/system/commandcore-helper.service")


def inspect(policy: Path = POLICY, helper: Path = HELPER, unit: Path = UNIT) -> dict:
    checks = {}
    for name, path in [("policy", policy), ("helper", helper), ("service", unit)]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            checks[name] = "missing"
            continue
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            checks[name] = "untrusted"
        elif name == "helper" and not stat.S_ISREG(info.st_mode):
            checks[name] = "untrusted"
        elif name == "service" and not stat.S_ISREG(info.st_mode):
            checks[name] = "untrusted"
        elif name == "policy" and not stat.S_ISREG(info.st_mode):
            checks[name] = "untrusted"
        else:
            checks[name] = "present"
    return {
        "platform": sys.platform,
        "helper_files": checks,
        "ready_for_local_approval": sys.platform == "linux"
        and all(v == "present" for v in checks.values()),
        "message": "No permissions were changed. A trusted signed helper installation and local approval are required before Full Control.",
    }


def main() -> int:
    print(json.dumps(inspect(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
