"""Safe, request-local shell execution receipts for the MCP Apps UI.

Never use the account activity feed or untrusted output to recover commands.
Unknown credential formats cannot be reliably classified; when in doubt,
the caller must avoid sending sensitive arguments through ordinary tools.
"""

import re

SHELL_UI_URI = "ui://commandcore/shell-compact-v25-20261112.html"

_SHELL_CARD_SENSITIVE_FILE = re.compile(
    r"(?i)(?:^|[/\s'\"=])(?:\.env(?:\.[A-Za-z0-9_-]+)?|"
    r"id_rsa|id_ed25519|credentials(?:\.json)?|"
    r"private[_-]?key(?:\.[A-Za-z0-9]+)?)(?=$|[\s/'\";\)])"
)
_SHELL_CARD_SENSITIVE_COMMAND = re.compile(
    r"(?i)(?:^|[;&|\n]\s*)(?:env|printenv|set|export\s+-p)\b"
    r"|(?:\b(?:curl|wget)\b[^\n]{0,160}(?:-H|--header)\s+)"
    r"|(?:\b(?:ssh-add|gpg|pass|secret-tool)\b)"
    r"|(?:\b(?:source|cat|head|tail|less|more)\b\s+[^\n]{0,120}"
    r"(?:\.env|/\.ssh/|credential|private[_-]?key))"
)
_SHELL_CARD_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>[A-Za-z_][A-Za-z0-9_-]*)['\"]?\s*[:=]\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s;,'\"]+)"
)
_SHELL_CARD_SENSITIVE_KEY_NAME = re.compile(
    r"(?i)(API[_-]?KEY|ACCESS[_-]?KEY|TOKEN|PASS(?:WORD|WD)?|"
    r"SECRET|CREDENTIAL|AUTHORIZATION|COOKIE|PRIVATE[_-]?KEY)"
)
_SHELL_CARD_SECRET_FLAG = re.compile(
    r"(?i)(?P<flag>--(?:api[-_]?key|access[-_]?token|token|"
    r"password|passwd|secret|client-secret))(?P<sep>\s+|=)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s;]+)"
)
_SHELL_CARD_SECRET_PREFIX = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_-]{15,}|ghp_[A-Za-z0-9_]{15,}|"
    r"github_pat_[A-Za-z0-9_]{15,}|xox[baprs]-[A-Za-z0-9_-]{15,})\b"
)
_SHELL_CARD_BEARER = re.compile(r"(?i)\bBearer\s+[^\s'\"]+")
_SHELL_CARD_SECRET_EXPANSION = re.compile(
    r"(?i)\$\{?(?:[A-Za-z_][A-Za-z0-9_]*"
    r"(?:KEY|TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL|COOKIE)"
    r"[A-Za-z0-9_]*)\}?"
)


def _cc_mask_terminal_secrets(text: str) -> tuple[str, bool]:
    """Best-effort mask credential syntax. Unknown secrets cannot be guaranteed."""
    masked = text
    masked, a = _SHELL_CARD_BEARER.subn("Bearer [REDACTED]", masked)
    masked, b = _SHELL_CARD_SECRET_FLAG.subn(
        lambda m: m.group("flag") + m.group("sep") + "[REDACTED]", masked
    )
    masked, c = _SHELL_CARD_SECRET_ASSIGNMENT.subn(
        lambda m: (
            m.group("key") + "=[REDACTED]"
            if _SHELL_CARD_SENSITIVE_KEY_NAME.search(m.group("key"))
            else m.group(0)
        ),
        masked,
    )
    masked, d = _SHELL_CARD_SECRET_PREFIX.subn("[REDACTED]", masked)
    return masked, bool(a or b or c or d)


def _cc_safe_shell_display(args):
    """Bounded UI-only preview; display normal commands without leaking known keys."""
    if not isinstance(args, dict) or args.get("env"):
        return {"command": "", "visibility": "withheld"}
    command = args.get("command")
    if not isinstance(command, str) or not 1 <= len(command) <= 5000:
        return {"command": "", "visibility": "withheld"}
    if any(ord(ch) < 32 and ch not in ("\n", "\t") for ch in command):
        return {"command": "", "visibility": "withheld"}
    if (
        ("-----BEGIN " in command and "PRIVATE KEY-----" in command)
        or _SHELL_CARD_SENSITIVE_FILE.search(command)
        or _SHELL_CARD_SENSITIVE_COMMAND.search(command)
        or _SHELL_CARD_SECRET_EXPANSION.search(command)
    ):
        return {"command": "", "visibility": "withheld"}
    safe, redacted = _cc_mask_terminal_secrets(command)
    if re.search(r"(?i)\b(?:authorization|set-cookie)\s*:", safe):
        return {"command": "", "visibility": "withheld"}
    if re.search(
        r"(?i)\b(?:curl|wget)\b[^\n]{0,150}\s+--data(?:-raw|-binary)?\b", safe
    ):
        return {"command": "", "visibility": "withheld"}
    return {"command": safe[:3000], "visibility": "redacted" if redacted else "visible"}


def _cc_terminal_display(value, limit):
    if not isinstance(value, str):
        return "", False
    text = "".join(
        ch for ch in value if ch in "\t\n" or 32 <= ord(ch) < 127 or ord(ch) > 159
    )
    clipped = len(text) > limit
    text = text[:limit]
    if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
        return "[sensitive output withheld]", True
    text, _had_secret = _cc_mask_terminal_secrets(text)
    return text, clipped


def build_shell_card(args, payload):
    """Return only a bounded UI-safe snapshot of this request's own result."""
    preview = _cc_safe_shell_display(args)
    visibility = preview["visibility"]
    operation = payload.get("_ui_operation")
    operation = operation if isinstance(operation, dict) else {}
    operation_id = operation.get("operation_id") or payload.get("execution_id")
    if not isinstance(operation_id, str) or not re.fullmatch(
        r"[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}",
        operation_id,
    ):
        # Do not synthesize a cross-call or account-wide operation id.
        operation_id = ""
    stdout, out_truncated = (
        _cc_terminal_display(payload.get("stdout"), 4096)
        if visibility == "visible"
        else ("", False)
    )
    stderr, err_truncated = (
        _cc_terminal_display(payload.get("stderr"), 2048)
        if visibility == "visible"
        else ("", False)
    )
    status = str(payload.get("command_status") or payload.get("status") or "returned")
    exit_code = payload.get("exit_code")
    if isinstance(exit_code, int) and exit_code != 0:
        status = "failed"
    elif status == "ok":
        status = "completed"
    return {
        "operation_id": operation_id,
        "command": preview["command"],
        "command_visibility": visibility,
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "device": str(operation.get("device") or "")[:70],
        "exit_code": exit_code,
        "duration_ms": operation.get("duration_ms"),
        "truncated": out_truncated
        or err_truncated
        or bool((payload.get("output_capture") or {}).get("truncated")),
    }
