# Validation status

This document summarizes project-level evidence without embedding private
deployment details. Exact release evidence belongs with the signed release
artifacts and CI run.

## Automated gates

The release-candidate family includes automated checks for:

- Python compile/import and unit/integration tests;
- MCP initialize/discovery and core tool round trips;
- READ_ONLY denial behavior;
- OAuth/JWKS validation and authorization failures;
- device enrollment, reconnect, revocation, and key rotation;
- panel/API behavior;
- signed update staging, activation, health validation, and rollback;
- fleet canary/ring state transitions;
- Linux privilege-separated FULL_CONTROL fixtures;
- Rust fmt, strict Clippy, unit tests, locked release build;
- native Rust Agent black-box parity;
- source/history secret scanning;
- Python and Rust dependency audits;
- locked server container build.

## Real-runtime evidence

The project has separately exercised:

- a real remote MCP client through OAuth to a deployed CommandCore server;
- real Linux x86_64 installation and systemd lifecycle;
- native Linux ARM64 Agent core/reconnect behavior;
- revocation denial;
- server/transport reconnect;
- privilege-separated Linux helper behavior in isolated acceptance;
- failed-update rollback in controlled environments.

Client and platform guides distinguish this evidence from capabilities that remain
experimental.

## Not implied

A passing fixture does not by itself establish:

- support for every Linux distribution;
- Windows FULL_CONTROL;
- interactive desktop support;
- browser automation;
- compatibility with every OAuth provider or MCP client;
- safety of enabling privileged tools on unrelated production workloads.

See PLATFORM_SUPPORT.md and the release checklist before changing support claims.
