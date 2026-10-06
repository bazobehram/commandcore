# Native Rust Agent

The native Rust Agent is the preferred long-term device runtime for supported
platforms. The Python Agent remains a useful reference implementation and
controlled fallback.

## Goals

- single native executable for normal Agent operation;
- local Ed25519 device identity;
- outbound authenticated WebSocket transport;
- reconnect and heartbeat;
- filesystem, shell, process, system, transfer, and Git parity;
- bounded streaming/output behavior;
- managed process continuity across transport/server reconnect;
- device-key rotation;
- signed release verification and health markers;
- optional delegation to a separate local privileged helper.

## Linux status

Linux x86_64 and ARM64 are the primary native targets. Release claims require:

- cargo fmt;
- strict Clippy;
- cargo test --locked;
- cargo build --locked --release;
- black-box MCP core parity;
- reconnect;
- enrollment/revocation;
- signed install/update/rollback;
- FULL_CONTROL helper parity in an isolated environment when enabled.

## Windows status

Windows native work is a preview. Do not claim stable support until the complete
real-runtime install, logon/reboot, reconnect, core operation, update, rollback,
uninstall, and privileged-helper gates pass.

## Privilege model

The network Agent should not run as root/Administrator. Privileged work belongs
behind a separate local helper with explicit local installation, authenticated
IPC, and a device-local permission ceiling.

## Compatibility

The Agent Protocol is independent of MCP. Wire changes must be versioned,
documented in DEVICE_PROTOCOL.md, and covered by cross-language tests when
canonicalization or signatures change.
