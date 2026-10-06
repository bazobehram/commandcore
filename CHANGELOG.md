# Changelog

All notable public CommandCore changes are recorded here.

The project is preparing its first clean public release from the 0.9
release-candidate family. Earlier private engineering milestones are summarized
rather than reproducing environment-specific deployment history.

## Unreleased

### Changed

- Prepared the repository for public free-software development under
  AGPL-3.0-or-later.
- Removed private deployment branding and environment-specific artifacts from the
  public source tree.
- Added contributor governance, DCO sign-off, pull-request policy, CODEOWNERS,
  issue forms, dependency automation, and public-repository policy checks.
- Reworked public documentation around generic self-hosting and provider-neutral
  OAuth/OIDC.
- Added factual CommandCore/Desktop Commander selection guidance.
- Updated client guides to separate protocol compatibility from live acceptance.

## 0.9.0-rc7 - 2026-10-05

### Added

- Native Linux Rust Agent for x86_64 and ARM64 release-candidate operation.
- Agent-initiated enrollment with locally generated Ed25519 identity.
- Outbound authenticated WebSocket transport with reconnect and heartbeat.
- MCP device discovery/selection and multi-device routing.
- Filesystem, shell, process, system, transfer, and Git capabilities.
- OAuth-protected MCP resource server with per-account device grants.
- READ_ONLY, STANDARD, and explicit local FULL_CONTROL permission model.
- Privilege-separated Linux helper for privileged operations.
- Managed long-running jobs with bounded output and reconnect-aware supervision.
- Device key rotation.
- Signed Agent manifests, versioned installation, health validation, and rollback.
- Fleet/canary rollout primitives.
- Operator panel, enrollment review, audit/activity views, and grant management.
- Signed Linux installer lifecycle for supported candidate architectures.
- Experimental desktop capability surface with runtime capability detection.

### Security

- Effective authority is the intersection of OAuth scope, explicit device grant,
  server profile, and device-local ceiling.
- Enrollment does not implicitly grant operation access.
- The network-facing Agent remains unprivileged by default.
- Release-signing private keys are outside the control-plane trust boundary.
- Sensitive operation/audit fields are redacted.
- Public source and history secret scanning are CI gates.
- Dependency auditing and committed application SBOMs are part of release
  engineering.

### Known limits

- Windows remains a preview rather than a stable supported release.
- macOS Agent support is planned.
- Interactive desktop control is experimental.
- Browser automation is not implemented.
- A public 1.0 compatibility promise has not yet been declared.

## Engineering lineage

The current architecture evolved through earlier private milestones that added,
in order: the first MCP-to-Agent vertical slice, operator hardening, Linux
privilege separation, OAuth/device grants, key rotation and signed updates,
health-gated rollback, fleet rollout, and the native Rust Agent.

Those milestones are intentionally not published as operational release notes
because they contained environment-specific evidence and were not public
releases.
