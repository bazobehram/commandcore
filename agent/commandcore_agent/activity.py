"""Local execution timeline. Only sanitized objects cross the journal boundary.

Not the server audit policy: local operators can see bounded ordinary text.
Never log raw messages, raw exception strings, or unfiltered journal entries.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from importlib.resources import files

PREFIX = "COMMANDCORE_ACTIVITY "
POLICY = json.loads(
    files(__package__).joinpath("activity_policy.json").read_text(encoding="utf-8")
)
FIELDS = set(POLICY["fields"].split())
PATTERNS = [
    (re.compile(pattern), re.sub(r"\$(\d)", r"\\g<\1>", replacement))
    for pattern, replacement in POLICY["patterns"]
]
SECRET_KEY = re.compile(
    r"password|passwd|secret|token|authorization|cookie|private.?key|api.?key|credential",
    re.I,
)
KNOWN: set[str] = set()
PREVIEW = 2048


def register_secrets(values):
    KNOWN.update(str(v) for v in values if v)


def text(value: str) -> str:
    for secret in sorted(KNOWN, key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    for pattern, _ in PATTERNS[3:6]:
        register_secrets(
            m.group(2).strip("\"'")
            for m in pattern.finditer(value)
            if not m.group(2).startswith("[REDACTED")
        )
    for secret in sorted(KNOWN, key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    for pattern, replacement in PATTERNS:
        value = pattern.sub(replacement, value)
    # JSON escaping also prevents terminal control sequences from executing.
    value = "".join(c for c in value if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)
    return value


def _sanitize(value, depth=0):
    if depth > 6:
        return "[BOUNDED]"
    if isinstance(value, dict):
        return {
            k: _sanitize(v, depth + 1)
            for k, v in list(value.items())[:64]
            if k in FIELDS
        }
    if isinstance(value, list):
        return [_sanitize(v, depth + 1) for v in value[:32]]
    if isinstance(value, str):
        safe = text(value)
        return safe[:PREVIEW] + ("… [truncated]" if len(safe) > PREVIEW else "")
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return (
        value if value is None or isinstance(value, (bool, int, float)) else "[OMITTED]"
    )


def sanitize(value):
    if (
        isinstance(value, dict)
        and "tool" in value
        and value["tool"] not in POLICY["tools"]
    ):
        value = {
            k: v
            for k, v in value.items()
            if k
            in {
                "tool",
                "event",
                "request_id",
                "execution_id",
                "timestamp_unix",
                "duration_ms",
                "status",
            }
        }
        value["reason"] = "unreviewed tool payload suppressed"
        if value.get("status") not in {None, "ok", "error", "timeout", "cancelled"}:
            value["status"] = "unknown"
    safe = _sanitize(value)
    if isinstance(safe, dict):
        protected = {
            "event",
            "tool",
            "request_id",
            "execution_id",
            "timestamp_unix",
            "status",
        }
        while len(json.dumps(safe, ensure_ascii=True)) > 16384:
            candidates = [
                k for k in safe if k not in protected and safe[k] != "[BOUNDED FIELD]"
            ]
            if not candidates:
                break
            key = max(
                candidates, key=lambda k: len(json.dumps(safe[k], ensure_ascii=True))
            )
            safe[key] = "[BOUNDED FIELD]"
            safe["truncated"] = True
    return safe


def sensitive_path(path):
    return bool(
        re.search(
            r"(?i)(^|[/\\])(?:\.env(?:\..*)?|\.ssh|\.aws|\.kube|credentials[^/\\]*|.*(?:private|secret|token).*|agent-state\.json|state\.json|id_rsa|id_ed25519)(?:$|[/\\])|\.(?:pem|key|p12|pfx)$",
            str(path or ""),
        )
    )


def context(msg):
    args = msg.get("arguments", {})
    env = args.get("env", {})
    if isinstance(env, dict):
        register_secrets(env.values())
    argv = args.get("argv", [])
    for flag, value in zip(argv, argv[1:]):
        if str(flag).lower() in {
            "--password",
            "--token",
            "--secret",
            "--api-key",
            "--user",
            "--cookie",
        }:
            register_secrets([value])
        elif (
            str(flag).lower() in {"-u", "-b"}
            and argv
            and Path(str(argv[0])).name == "curl"
        ):
            register_secrets([value])
    data = {
        "tool": msg.get("tool"),
        "request_id": msg.get("request_id", msg.get("execution_id")),
        "execution_id": msg.get("execution_id"),
    }
    source = msg.get("activity", {}).get("source")
    if source:
        data["source"] = source
    return data


def request(msg):
    data = context(msg)
    args = msg.get("arguments", {})
    safe_args = sanitize(args)
    for key in (
        "tool",
        "request_id",
        "execution_id",
        "source",
        "event",
        "timestamp_unix",
    ):
        safe_args.pop(key, None)
    if data["tool"] == "keyboard.type" or data["tool"].startswith(
        ("clipboard.", "transfer.")
    ):
        safe_args = {
            k: v
            for k, v in safe_args.items()
            if k
            in {
                "path",
                "source_path",
                "destination_path",
                "source",
                "destination",
                "src",
                "dst",
                "length",
                "offset",
                "encoding",
            }
        }
    data.update(safe_args)
    data.setdefault("timeout_ms", msg.get("timeout_ms"))
    if data["tool"] in {"shell.exec", "process.start"}:
        if data.get("cwd") is None:
            data["cwd"] = os.getcwd()
    if data["tool"] == "fs.write":
        raw = str(args.get("data", ""))
        data["bytes"] = (
            len(raw.encode())
            if args.get("encoding") != "base64"
            else (len(raw) * 3 // 4 - len(raw) + len(raw.rstrip("=")))
        )
    if data["tool"] == "fs.patch":
        data["patch_count"] = len(args.get("patches", []))
    return data


def result(msg, outcome, duration_ms, streams=None):
    data = context(msg)
    data.update(sanitize(outcome))
    data.update(sanitize(outcome.get("result") or {}))
    data["duration_ms"] = duration_ms
    args = msg.get("arguments", {})
    tool = msg.get("tool", "")
    if tool.startswith("fs.") and "path" in args:
        data.setdefault("path", args["path"])
    if tool == "fs.read":
        raw = outcome.get("result") or {}
        data["bytes_returned"] = raw.get("bytes", 0)
        if (
            raw.get("encoding", args.get("encoding")) != "base64"
            and not sensitive_path(args.get("path"))
            and "\x00" not in raw.get("data", "")
            and "\ufffd" not in raw.get("data", "")
        ):
            data["preview"] = raw.get("data", "")
    if tool in {"fs.write", "fs.patch"} and outcome.get("status") == "ok":
        data["changed"] = tool == "fs.write" or data.get("replacements", 0) > 0
    if tool == "keyboard.type" or tool.startswith(("clipboard.", "transfer.")):
        for key in ("preview", "stdout", "stderr", "command", "argv", "error"):
            data.pop(key, None)
    elif streams:
        data.update(streams)
    return data


def emit(event, data):
    safe = sanitize({**data, "event": event, "timestamp_unix": time.time()})
    print(PREFIX + json.dumps(safe, ensure_ascii=True, allow_nan=False), flush=True)


def render(message, as_json=False, errors=False):
    if not message.startswith(PREFIX):
        return None
    try:
        event = sanitize(json.loads(message[len(PREFIX) :]))
    except (ValueError, TypeError):
        return None
    if not isinstance(event, dict) or event.get("event") not in {
        "REQUEST",
        "RESULT",
        "CONNECTION",
    }:
        return None
    if (
        errors
        and event.get("status") in {None, "ok", "connected"}
        and event.get("exit_code") in {None, 0}
        and not event.get("resource_warning")
    ):
        return None
    if as_json:
        return json.dumps(event, ensure_ascii=True)
    try:
        stamp = time.strftime("%H:%M:%S", time.gmtime(event.get("timestamp_unix") or 0))
    except (TypeError, ValueError, OverflowError):
        return None
    return (
        stamp
        + " UTC "
        + event["event"]
        + "\n"
        + json.dumps(event, indent=2, ensure_ascii=True)
    )


def watch(args):
    if sys.platform != "linux":
        raise ValueError("Local activity is currently supported on Linux")
    service = args.service or "commandcore-agent.service"
    if not re.fullmatch(r"commandcore-agent[\w.-]*\.service", service):
        raise ValueError("Invalid CommandCore service name")
    command = [
        "journalctl",
        "--user",
        "--unit",
        service,
        "--no-pager",
        "--output=json",
        "--lines",
        str(max(1, min(args.last if args.last is not None else 20, 5000))),
    ]
    if args.last is None:
        command.append("--follow")
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as proc:
        try:
            for line in proc.stdout:
                try:
                    display = render(
                        json.loads(line).get("MESSAGE", ""), args.json, args.errors
                    )
                except (ValueError, TypeError):
                    continue
                if display:
                    print(display, flush=True)
            return proc.wait()
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()
