from __future__ import annotations

READ_ONLY_TOOLS = {
    "devices.list",
    "devices.info",
    "devices.select",
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
    "activity.feed",
    "activity.watch",
}
STANDARD_TOOLS = READ_ONLY_TOOLS | {
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
    "browser.open",
    "browser.observe",
    "browser.move",
    "browser.click",
    "browser.type",
    "browser.keypress",
    "browser.scroll",
    "browser.close",
    "browser.handoff",
    "browser.watch",
}
# Docker daemon access is root-equivalent on typical Linux installations, so
# Docker tools intentionally require FULL_CONTROL even when a local user happens
# to belong to the docker group.
FULL_CONTROL_TOOLS = STANDARD_TOOLS | {
    "services.manage",
    "system.reboot",
    "system.shutdown",
    "package.install",
    "docker.ps",
    "docker.inspect",
    "docker.logs",
    "docker.exec",
    "docker.run",
    "agent.update.stage",
    "agent.update.activate",
    "agent.update.rollback",
}

RISK = {
    "devices.list": "low",
    "devices.info": "low",
    "devices.select": "low",
    "activity.feed": "low",
    "activity.watch": "low",
    "fs.list": "low",
    "fs.stat": "low",
    "fs.read": "low",
    "fs.search": "low",
    "process.list": "low",
    "process.status": "low",
    "process.output": "low",
    "system.info": "low",
    "system.metrics": "low",
    "transfer.download": "medium",
    "git.status": "low",
    "git.diff": "low",
    "git.log": "low",
    "git.run": "high",
    "fs.write": "medium",
    "fs.patch": "medium",
    "fs.copy": "medium",
    "fs.move": "high",
    "fs.delete": "high",
    "shell.exec": "high",
    "process.start": "high",
    "process.stop": "high",
    "transfer.upload": "medium",
    "services.manage": "critical",
    "system.reboot": "critical",
    "system.shutdown": "critical",
    "package.install": "critical",
    "docker.ps": "high",
    "docker.inspect": "high",
    "docker.logs": "high",
    "docker.exec": "critical",
    "docker.run": "critical",
    "agent.update.status": "low",
    "agent.update.stage": "critical",
    "agent.update.activate": "critical",
    "agent.update.rollback": "critical",
    "desktop.windows": "low",
    "screen.capture": "medium",
    "clipboard.read": "medium",
    "mouse.click": "high",
    "keyboard.type": "high",
    "keyboard.keypress": "high",
    "clipboard.write": "high",
    "browser.open": "medium",
    "browser.observe": "medium",
    "browser.move": "medium",
    "browser.click": "high",
    "browser.type": "high",
    "browser.keypress": "high",
    "browser.scroll": "medium",
    "browser.close": "medium",
    "browser.handoff": "medium",
    "browser.watch": "medium",
}


def allowed(profile: str, tool: str) -> bool:
    if profile == "READ_ONLY":
        return tool in READ_ONLY_TOOLS
    if profile == "STANDARD":
        return tool in STANDARD_TOOLS
    if profile == "FULL_CONTROL":
        return tool in FULL_CONTROL_TOOLS
    return False


def risk_class(tool: str) -> str:
    return RISK.get(tool, "high")
