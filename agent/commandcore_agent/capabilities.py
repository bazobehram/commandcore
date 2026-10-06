from __future__ import annotations

from .desktop_backend import desktop_capabilities

CAPABILITIES = {
    "agent_implementation": "python",
    "filesystem": True,
    "shell": True,
    "process": True,
    "system": True,
    "transfer": True,
    "git": False,
    "docker": False,
    "services": False,
    "packages": False,
    "system_power": False,
    "browser": False,
    "desktop": False,
    "screen": False,
    "keyboard": False,
    "mouse": False,
    "clipboard": False,
    "privileged_helper": False,
    "agent_update": True,
    "agent_update_version": "1",
    "configured_max_permission_profile": "STANDARD",
    "local_max_permission_profile": "STANDARD",
    "filesystem_version": "1",
    "shell_version": "1",
    "process_version": "1",
    "system_version": "1",
    "transfer_version": "1",
    "git_version": "1",
    "docker_version": "1",
    "services_version": "1",
    "packages_version": "1",
    "system_power_version": "1",
}

CAPABILITIES.update(desktop_capabilities())
