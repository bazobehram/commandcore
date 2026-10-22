from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("COMMANDCORE_HOST", "0.0.0.0")
    port: int = int(os.getenv("COMMANDCORE_PORT", "8787"))
    db_path: str = os.getenv("COMMANDCORE_DB", "./commandcore.sqlite3")
    api_token: str = os.getenv("COMMANDCORE_API_TOKEN", "")
    public_bootstrap_enabled: bool = _bool(
        "COMMANDCORE_PUBLIC_BOOTSTRAP_ENABLED", False
    )
    recovery_enabled: bool = _bool("COMMANDCORE_RECOVERY_ENABLED", False)
    panel_session_secret: str = os.getenv("COMMANDCORE_PANEL_SESSION_SECRET", "")
    oauth_algorithms: tuple[str, ...] = tuple(
        x.strip()
        for x in os.getenv("COMMANDCORE_OAUTH_ALGORITHMS", "RS256,ES256,EdDSA").split(
            ","
        )
        if x.strip()
    )
    bootstrap_subject: str = os.getenv(
        "COMMANDCORE_BOOTSTRAP_SUBJECT", "bootstrap-admin"
    )
    public_base_url: str = os.getenv(
        "COMMANDCORE_PUBLIC_BASE_URL", "http://127.0.0.1:8787"
    )
    mcp_base_url: str = os.getenv(
        "COMMANDCORE_MCP_BASE_URL", "http://127.0.0.1:8787/mcp"
    )
    agent_base_url: str = os.getenv(
        "COMMANDCORE_AGENT_BASE_URL", "ws://127.0.0.1:8787/agent"
    )
    enrollment_ttl_seconds: int = int(
        os.getenv("COMMANDCORE_ENROLLMENT_TTL_SECONDS", "600")
    )
    selection_ttl_seconds: int = int(
        os.getenv("COMMANDCORE_SELECTION_TTL_SECONDS", "86400")
    )
    heartbeat_timeout_seconds: int = int(
        os.getenv("COMMANDCORE_HEARTBEAT_TIMEOUT_SECONDS", "45")
    )
    max_job_output_bytes: int = int(
        os.getenv("COMMANDCORE_MAX_JOB_OUTPUT_BYTES", "1048576")
    )
    max_transfer_bytes: int = int(
        os.getenv("COMMANDCORE_MAX_TRANSFER_BYTES", "10485760")
    )
    auto_approve_enrollment: bool = _bool("COMMANDCORE_AUTO_APPROVE_ENROLLMENT", False)
    panel_session_ttl_seconds: int = int(
        os.getenv("COMMANDCORE_PANEL_SESSION_TTL_SECONDS", "28800")
    )
    panel_cookie_name: str = os.getenv(
        "COMMANDCORE_PANEL_COOKIE_NAME", "commandcore_session"
    )
    panel_cookie_secure: bool = _bool(
        "COMMANDCORE_PANEL_COOKIE_SECURE",
        os.getenv("COMMANDCORE_PUBLIC_BASE_URL", "http://127.0.0.1:8787").startswith(
            "https://"
        ),
    )
    oauth_enabled: bool = _bool("COMMANDCORE_OAUTH_ENABLED", False)
    panel_oauth_client_id: str = os.getenv(
        "COMMANDCORE_PANEL_OAUTH_CLIENT_ID", ""
    ).strip()
    oauth_issuer: str = os.getenv("COMMANDCORE_OAUTH_ISSUER", "").strip()
    oauth_audience: str = os.getenv("COMMANDCORE_OAUTH_AUDIENCE", "").strip()
    oauth_jwks_url: str = os.getenv("COMMANDCORE_OAUTH_JWKS_URL", "").strip()
    oauth_authorization_servers: tuple[str, ...] = tuple(
        x.strip()
        for x in os.getenv("COMMANDCORE_OAUTH_AUTHORIZATION_SERVERS", "").split(",")
        if x.strip()
    )
    recommended_agent_version: str = os.getenv(
        "COMMANDCORE_RECOMMENDED_AGENT_VERSION", "0.9.0-rc7"
    )
    agent_update_manifest_url: str = os.getenv(
        "COMMANDCORE_AGENT_UPDATE_MANIFEST_URL", ""
    ).strip()

    browser_enabled: bool = _bool("COMMANDCORE_BROWSER_ENABLED", False)
    browser_steel_url: str = os.getenv(
        "COMMANDCORE_BROWSER_STEEL_URL", "http://steel:3000"
    ).strip()
    browser_cdp_url: str = os.getenv(
        "COMMANDCORE_BROWSER_CDP_URL", "ws://steel:3000"
    ).strip()
    browser_egress_proxy_url: str = os.getenv(
        "COMMANDCORE_BROWSER_EGRESS_PROXY_URL", "http://browser-boundary:8080"
    ).strip()
    browser_attestation_path: str = os.getenv(
        "COMMANDCORE_BROWSER_ATTESTATION_PATH", ""
    ).strip()
    browser_attestation_key: str = os.getenv("COMMANDCORE_BROWSER_ATTESTATION_KEY", "")
    # Production option: verification-only Ed25519 public key. The signing
    # seed must stay in the separate Docker-privileged operator service.
    browser_attestation_public_key: str = os.getenv(
        "COMMANDCORE_BROWSER_ATTESTATION_PUBLIC_KEY", ""
    ).strip()
    browser_worker_manifest: str = os.getenv(
        "COMMANDCORE_BROWSER_WORKER_MANIFEST", ""
    ).strip()
    browser_worker_binding_path: str = os.getenv(
        "COMMANDCORE_BROWSER_WORKER_BINDING_PATH", ""
    ).strip()
    browser_worker_id: str = os.getenv("COMMANDCORE_BROWSER_WORKER_ID", "").strip()
    browser_worker_binding_key: str = os.getenv(
        "COMMANDCORE_BROWSER_WORKER_BINDING_KEY", ""
    )
    browser_allow_hosts: tuple[str, ...] = tuple(
        host.strip().lower()
        for host in os.getenv("COMMANDCORE_BROWSER_ALLOW_HOSTS", "").split(",")
        if host.strip()
    )

    def validate(self) -> None:
        if self.browser_enabled and self.oauth_enabled:
            if (
                not self.browser_worker_manifest
                or not self.browser_attestation_path
                or not (
                    self.browser_attestation_public_key
                    or len(self.browser_attestation_key) >= 32
                )
            ):
                raise RuntimeError(
                    "OAuth Browser requires a pre-provisioned multi-worker"
                    " manifest and short-lived physical attestation"
                )
            if self.browser_attestation_public_key and self.browser_attestation_key:
                raise RuntimeError(
                    "Choose Ed25519 PUBLIC verification OR legacy HMAC key"
                )
            if self.browser_attestation_public_key:
                from .browser_worker_attestation_ed25519 import _decode_key

                _decode_key(self.browser_attestation_public_key)
            if len(self.browser_worker_binding_key) < 32 or (
                not self.browser_worker_manifest
                and (not self.browser_worker_binding_path or not self.browser_worker_id)
            ):
                raise RuntimeError(
                    "OAuth Browser requires a pre-provisioned persistent worker"
                    " manifest or binding path, stable worker ID and binding key"
                )
            if self.browser_worker_manifest and (
                self.browser_worker_binding_path or self.browser_worker_id
            ):
                raise RuntimeError(
                    "Use worker manifest OR single worker settings, not both"
                )
        if self.browser_enabled and not self.browser_allow_hosts:
            raise RuntimeError(
                "Browser enabled but COMMANDCORE_BROWSER_ALLOW_HOSTS is empty"
            )
        if self.browser_enabled and (
            not self.browser_steel_url.startswith("http://")
            or not self.browser_cdp_url.startswith("ws://")
            or not self.browser_egress_proxy_url.startswith("http://")
        ):
            raise RuntimeError("Browser backend and egress proxy must use private URLs")
        if len(self.api_token) < 32:
            raise RuntimeError(
                "COMMANDCORE_API_TOKEN is required and must be at least 32 characters"
            )
        if self.panel_session_secret and len(self.panel_session_secret) < 32:
            raise RuntimeError(
                "Panel signing secret must contain at least 32 characters"
            )
        if self.panel_session_secret and self.panel_session_secret == self.api_token:
            raise RuntimeError(
                "Panel signing secret must differ from the bootstrap token"
            )
        if not self.public_bootstrap_enabled and not self.panel_session_secret:
            raise RuntimeError(
                "Hardened authentication requires a separate panel signing secret"
            )
        if not self.oauth_algorithms or any(
            a not in {"RS256", "ES256", "EdDSA"} for a in self.oauth_algorithms
        ):
            raise RuntimeError("Invalid OAuth asymmetric algorithm allowlist")

        if self.panel_session_ttl_seconds < 300:
            raise RuntimeError(
                "COMMANDCORE_PANEL_SESSION_TTL_SECONDS must be at least 300"
            )
        if self.oauth_enabled:
            missing = [
                name
                for name, value in {
                    "COMMANDCORE_OAUTH_ISSUER": self.oauth_issuer,
                    "COMMANDCORE_OAUTH_AUDIENCE": self.oauth_audience,
                    "COMMANDCORE_OAUTH_JWKS_URL": self.oauth_jwks_url,
                }.items()
                if not value
            ]
            if missing:
                raise RuntimeError("OAuth enabled but missing: " + ", ".join(missing))

    @property
    def session_secret(self) -> str:
        return self.panel_session_secret or self.api_token
