"""Bounded disposable timeline workload; no enrollment, network, or helper."""

import asyncio
import shlex
import sys
import time
import uuid
from pathlib import Path

from commandcore_agent import activity
from commandcore_agent.executor import Executor


async def main(root):
    root = Path(root).resolve(strict=True)
    path = root / "config.py"
    script = root / "check_config.py"
    ex = Executor(delegate_full_control=False)
    jobs = [
        ("fs.write", {"path": str(path), "data": "value = 1\n"}),
        ("fs.read", {"path": str(path), "offset": 0, "length": 8192}),
        (
            "fs.write",
            {
                "path": str(script),
                "data": "from config import value\nassert value in (1, 2)\nprint('Configuration valid; tests pass')\n",
            },
        ),
        (
            "shell.exec",
            {
                "command": f"{shlex.quote(sys.executable)} check_config.py",
                "cwd": str(root),
                "timeout_ms": 5000,
            },
        ),
        (
            "fs.patch",
            {
                "path": str(path),
                "patches": [{"search": "value = 1", "replace": "value = 2"}],
            },
        ),
        ("fs.read", {"path": str(path)}),
        (
            "shell.exec",
            {
                "command": f"{shlex.quote(sys.executable)} check_config.py",
                "cwd": str(root),
                "timeout_ms": 5000,
            },
        ),
        (
            "shell.exec",
            {
                "command": "printf '%s\\n' \"$TOKEN\"; printf 'result row\\n%.0s' $(seq 1 500)",
                "cwd": str(root),
                "env": {"TOKEN": "canary-secret-must-not-display"},
                "timeout_ms": 5000,
            },
        ),
    ]
    activity.emit(
        "CONNECTION",
        {"status": "connected", "source": {"channel": "disposable-fixture"}},
    )
    try:
        for tool, args in jobs:
            msg = {
                "tool": tool,
                "arguments": args,
                "execution_id": str(uuid.uuid4()),
                "request_id": str(uuid.uuid4()),
                "activity": {"source": {"channel": "disposable-fixture"}},
            }
            started = time.monotonic()
            activity.emit("REQUEST", activity.request(msg))
            streams = {}
            counts = {}

            async def output(stream, data):
                counts[stream] = counts.get(stream, 0) + len(data.encode())
                streams[stream] = (streams.get(stream, "") + data)[:16384]

            outcome = await ex.execute(
                msg["execution_id"], "STANDARD", tool, args, output
            )
            previews = (
                {
                    **streams,
                    **{f"{k}_bytes": v for k, v in counts.items()},
                    "truncated": any(v > activity.PREVIEW for v in counts.values()),
                }
                if counts
                else None
            )
            activity.emit(
                "RESULT",
                activity.result(
                    msg, outcome, int((time.monotonic() - started) * 1000), previews
                ),
            )
            if outcome["status"] != "ok":
                raise RuntimeError("Disposable workload failed")
    finally:
        await ex.cancel_all()
    activity.emit(
        "CONNECTION",
        {"status": "disconnected", "reason": "disposable fixture complete"},
    )


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
