"""Safe, request-local shell execution receipts for the MCP Apps UI.

Never use the account activity feed or untrusted output to recover commands.
Unknown credential formats cannot be reliably classified; when in doubt,
the caller must avoid sending sensitive arguments through ordinary tools.
"""

import re

SHELL_UI_URI = "ui://commandcore/shell-compact-v26-20261113.html"

_SHELL_CARD_SENSITIVE_FILE = re.compile(
    r"(?i)(?:^|[/\s'\"=])(?:\.env(?:\.[A-Za-z0-9_-]+)?|"
    r"id_rsa|id_ed25519|credentials(?:\.json)?|"
    r"private[_-]?key(?:\.[A-Za-z0-9]+)?)(?=$|[\s/'\";\)])"
)
_SHELL_CARD_SENSITIVE_COMMAND = re.compile(
    # Bare "set"/"env"/"printenv" prints environment or shell variables.
    # "set -e", "set -euo pipefail" and "env node build" do not.
    r"(?im)(?:^|[;&|\n])\s*(?:env|printenv|set)\s*(?=$|[;&|\n])"
    r"|(?:^|[;&|\n])\s*export\s+-p\b"
    r"|(?:\b(?:ssh-add|gpg|pass|secret-tool)\b)"
    r"|(?:\b(?:source|cat|head|tail|less|more|sed|grep|awk)\b"
    r"\s+[^\n]{0,120}(?:\.env|/\.ssh/|credential|private[_-]?key))"
)
_SHELL_CARD_AUTH_HEADER = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]{0,160}(?:-H|--header)\s+"
    r"['\"]?(?:(?:proxy-)?authorization|cookie|x-api-key)\s*:"
)
_SHELL_CARD_SAFE_HEREDOC_WRITE = re.compile(
    r"(?s)^\s*cat\s*>\s*['\"]?"
    r"(?P<path>/home/[^ \n'\"<>]*?/projects/[^\s'\"<>]+"
    r"\.(?:html|css|js|jsx|ts|tsx|md|txt|py))['\"]?"
    r"\s*<<\s*'(?P<marker>[A-Za-z][A-Za-z0-9_]*)'\s*\n"
    r"(?P<body>.*?)\n(?P=marker)\s*$"
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
    """Mask recognized secret forms; do not count unchanged assignments."""
    masked = text
    masked, bearer_hits = _SHELL_CARD_BEARER.subn("Bearer [REDACTED]", masked)
    masked, flag_hits = _SHELL_CARD_SECRET_FLAG.subn(
        lambda m: m.group("flag") + m.group("sep") + "[REDACTED]", masked
    )
    assignment_redacted = False

    def replace_assignment(match):
        nonlocal assignment_redacted
        if not _SHELL_CARD_SENSITIVE_KEY_NAME.search(match.group("key")):
            return match.group(0)
        assignment_redacted = True
        return match.group("key") + "=[REDACTED]"

    masked = _SHELL_CARD_SECRET_ASSIGNMENT.sub(replace_assignment, masked)
    masked, prefix_hits = _SHELL_CARD_SECRET_PREFIX.subn("[REDACTED]", masked)
    return masked, bool(bearer_hits or flag_hits or assignment_redacted or prefix_hits)


def _cc_safe_shell_display(args):
    """Provide a bounded command preview, never claiming text size is a secret."""
    if not isinstance(args, dict):
        return {"command": "", "visibility": "withheld", "reason": "no_arguments"}
    command = args.get("command")
    if not isinstance(command, str) or not command:
        return {"command": "", "visibility": "withheld", "reason": "no_command"}
    if args.get("env"):
        return {
            "command": "",
            "visibility": "withheld",
            "reason": "environment_overrides",
        }
    if any(ord(ch) < 32 and ch not in ("\n", "\t") for ch in command):
        return {"command": "", "visibility": "withheld", "reason": "control_characters"}
    if "-----BEGIN " in command and "PRIVATE KEY-----" in command:
        return {
            "command": "",
            "visibility": "withheld",
            "reason": "private_key_material",
        }
    # xtrace can reveal values in subsequent shell output.
    if re.search(r"(?m)(?:^|[;&|\n])\s*set\s+-[^\n]*x\b", command):
        return {"command": "", "visibility": "withheld", "reason": "shell_tracing"}
    if _SHELL_CARD_AUTH_HEADER.search(command):
        # We do not try to interpret arbitrary HTTP headers as harmless.
        return {
            "command": "",
            "visibility": "withheld",
            "reason": "authorization_header",
        }
    if _SHELL_CARD_SECRET_EXPANSION.search(command):
        return {"command": "", "visibility": "withheld", "reason": "secret_variable"}
    # A quoted heredoc written directly to an ordinary project source file
    # does not execute its body. References to ".env" in its documentation
    # therefore do not imply a credential-file read.
    safe_source_write = bool(_SHELL_CARD_SAFE_HEREDOC_WRITE.fullmatch(command))
    if _SHELL_CARD_SENSITIVE_FILE.search(command) and not safe_source_write:
        return {
            "command": "",
            "visibility": "withheld",
            "reason": "protected_file_reference",
        }
    if _SHELL_CARD_SENSITIVE_COMMAND.search(command):
        return {
            "command": "",
            "visibility": "withheld",
            "reason": "environment_or_protected_command",
        }
    if re.search(
        r"(?i)\b(?:curl|wget)\b[^\n]{0,150}\s+--data(?:-raw|-binary)?\b",
        command,
    ):
        return {
            "command": "",
            "visibility": "withheld",
            "reason": "unreviewed_http_payload",
        }
    # A large generated script is not evidence of credentials. Display a
    # bounded, redacted excerpt; suppress stdout because the omitted body was
    # not completely displayed or reviewed.
    if len(command) > 5000:
        safe, _ = _cc_mask_terminal_secrets(command[:2400])
        return {
            "command": safe + "\n… [preview shortened; full script not displayed]",
            "visibility": "shortened",
            "reason": "command_preview_limit",
        }
    safe, redacted = _cc_mask_terminal_secrets(command)
    if redacted:
        return {
            "command": safe[:3000],
            "visibility": "redacted",
            "reason": "credential_masked",
        }
    if len(safe) > 3000:
        return {
            "command": safe[:2600] + "\n… [preview shortened]",
            "visibility": "shortened",
            "reason": "command_preview_limit",
        }
    return {"command": safe, "visibility": "visible", "reason": "none"}


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
        "preview_reason": preview["reason"],
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
