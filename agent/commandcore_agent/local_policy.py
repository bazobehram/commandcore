from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

PROFILE_RANK = {"READ_ONLY": 0, "STANDARD": 1, "FULL_CONTROL": 2}
DEFAULT_POLICY_PATH = "/etc/commandcore/agent-policy.json"


def normalize_profile(value: str | None, default: str = "STANDARD") -> str:
    v = (value or "").strip().upper()
    return v if v in PROFILE_RANK else default


def load_local_policy(path: str | None = None) -> dict[str, Any]:
    policy_path = Path(
        path or os.getenv("COMMANDCORE_AGENT_POLICY", DEFAULT_POLICY_PATH)
    )
    policy: dict[str, Any] = {
        "path": str(policy_path),
        "configured_max_permission_profile": "STANDARD",
        "allowed_helper_uids": [],
        "update_public_key_b64": "",
        "update_manifest_origins": [],
    }
    try:
        initial = policy_path.lstat()
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("invalid_policy_file")
        # Read one protected descriptor: never follow a replaced policy symlink.
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(policy_path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
                raise ValueError("invalid_policy_file")
            if os.name == "posix" and (
                info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022
            ):
                raise PermissionError("untrusted_policy")
            raw = json.loads(os.read(descriptor, 1048577).decode("utf-8"))
        finally:
            os.close(descriptor)
        if (
            not isinstance(raw, dict)
            or raw.get("configured_max_permission_profile") not in PROFILE_RANK
        ):
            raise ValueError("invalid_policy_profile")
        if os.name == "posix" and (
            str(policy_path) == DEFAULT_POLICY_PATH
            or raw["configured_max_permission_profile"] == "FULL_CONTROL"
        ):
            from .root_trust import check_root_directory

            if info.st_uid != 0:
                raise PermissionError("root_policy_required")
            check_root_directory(policy_path.absolute().parent)
        elif raw["configured_max_permission_profile"] == "FULL_CONTROL":
            raise PermissionError("root_trust_unavailable")
        policy.update(raw)
    except FileNotFoundError:
        if os.path.lexists(policy_path):
            policy["policy_error"] = "invalid_or_unreadable_or_untrusted"
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        policy["policy_error"] = "invalid_or_unreadable_or_untrusted"
    if policy.get("policy_error"):
        policy["configured_max_permission_profile"] = "READ_ONLY"
    policy["configured_max_permission_profile"] = normalize_profile(
        str(policy.get("configured_max_permission_profile", "STANDARD")), "READ_ONLY"
    )
    # Environment may lower the local policy, but never enable the helper.
    environment_ceiling = os.getenv("COMMANDCORE_AGENT_MAX_PERMISSION_PROFILE")
    if environment_ceiling is not None:
        ceiling = normalize_profile(environment_ceiling, "READ_ONLY")
        policy["configured_max_permission_profile"] = min_profile(
            policy["configured_max_permission_profile"], ceiling
        )
    uids = policy.get("allowed_helper_uids")
    if not isinstance(uids, list):
        uids = []
    clean_uids: list[int] = []
    for value in uids:
        try:
            n = int(value)
        except (TypeError, ValueError):
            continue
        if n >= 0:
            clean_uids.append(n)
    policy["allowed_helper_uids"] = sorted(set(clean_uids))
    origins = policy.get("update_manifest_origins")
    if not isinstance(origins, list):
        origins = []
    policy["update_manifest_origins"] = sorted(
        {str(x).strip().rstrip("/") for x in origins if str(x).strip()}
    )
    return policy


def min_profile(a: str, b: str) -> str:
    aa = normalize_profile(a)
    bb = normalize_profile(b)
    return aa if PROFILE_RANK[aa] <= PROFILE_RANK[bb] else bb
