from __future__ import annotations

READ_ONLY = {
    "fs.list",
    "fs.stat",
    "fs.read",
    "fs.search",
    "process.list",
    "process.status",
    "process.output",
    "system.info",
    "system.metrics",
    "transfer.download",
    "git.status",
    "git.diff",
    "git.log",
    "agent.update.status",
    "desktop.windows",
    "screen.capture",
    "clipboard.read",
}
STANDARD = READ_ONLY | {
    "fs.write",
    "fs.patch",
    "fs.copy",
    "fs.move",
    "fs.delete",
    "shell.exec",
    "process.start",
    "process.stop",
    "transfer.upload",
    "git.run",
    "mouse.click",
    "keyboard.type",
    "keyboard.keypress",
    "clipboard.write",
}
FULL_CONTROL = STANDARD | {
    "services.manage",
    "package.install",
    "system.reboot",
    "system.shutdown",
    "docker.ps",
    "docker.inspect",
    "docker.logs",
    "docker.exec",
    "docker.run",
    "agent.update.stage",
    "agent.update.activate",
    "agent.update.rollback",
}


def is_allowed(profile: str, tool: str) -> bool:
    if profile == "READ_ONLY":
        return tool in READ_ONLY
    if profile == "STANDARD":
        return tool in STANDARD
    if profile == "FULL_CONTROL":
        return tool in FULL_CONTROL
    return False
