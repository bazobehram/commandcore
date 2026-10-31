"""Errors shared by the optional Browser gateway and CDP transport."""

class BrowserError(Exception):
    pass


class BrowserManualStepRequired(BrowserError):
    """The action was blocked before dispatch; private human control is required."""


def check_url(raw: str, allow_hosts: tuple[str, ...]) -> str:
    """Validate caller-supplied *initial* navigation. Not a network firewall."""
    if not allow_hosts:
        raise BrowserError("browser host allowlist is empty")
    if not isinstance(raw, str) or len(raw) > 2048:
        raise BrowserError("invalid URL")
    try:
        u = urlsplit(raw)
        host = (u.hostname or "").rstrip(".").lower()
        port = u.port
    except ValueError as exc:
        raise BrowserError("invalid URL") from exc
    if u.scheme != "https" or not host or port not in (None, 443):
        raise BrowserError("only HTTPS on port 443 is allowed")
    if u.username is not None or u.password is not None:
        raise BrowserError("credentials in URLs are forbidden")
    try:
        ipaddress.ip_address(host)
        raise BrowserError("IP literals are forbidden")
    except ValueError:
        pass
    if not _public_dns_name(host):
        raise BrowserError("only public DNS destinations are allowed")
    if allow_hosts != ("*",) and not any(
        host == allowed
        or (
            allowed.startswith("*.")
            and host.endswith(allowed[1:])
            and host != allowed[2:]
        )
        for allowed in allow_hosts
    ):
        raise BrowserError("host is not in the browser allowlist")
    return raw
