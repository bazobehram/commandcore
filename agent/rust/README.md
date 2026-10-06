# Rust Agent

Status: **SUPPORTED CANDIDATE / NATIVE NETWORK AND CORE PATH VALIDATED**.

The Rust implementation is the preferred long-term CommandCore Agent for supported
platforms. The Python Agent remains the reference implementation and controlled
fallback.

Implemented and covered by repository validation:

- one-time enrollment and local Ed25519 identity generation;
- Agent Protocol v1 challenge signing and authenticated outbound WebSocket;
- reconnect with bounded backoff and heartbeat capability advertisement;
- `job.request`, streaming `job.output`, `job.result`, cancellation, and
  disconnect handling;
- READ_ONLY / STANDARD filesystem, shell, process, system, transfer, and Git
  capabilities;
- bounded managed-process output and metadata retained across transport/server
  reconnects;
- FULL_CONTROL delegation through the authenticated privilege-separated Linux
  helper while keeping the network Agent unprivileged;
- crash-safe Agent state and device-key rotation recovery;
- signed release verification, health markers, activation, and rollback support;
- deterministic Agent Protocol v1 cryptographic vectors shared with the Python
  reference implementation.

The release gates include Rust formatting, strict Clippy, locked tests, a locked
release build, native black-box core parity, enrollment/reconnect, and isolated
FULL_CONTROL helper parity. Platform support is still evidence-based: a successful
compile alone does not make a platform stable.

Linux x86_64 and ARM64 are the primary native targets. Windows native support
remains preview until its complete real-runtime installation, reconnect,
update/rollback, uninstall, and privileged-helper acceptance matrix passes.

The Linux installer keeps versioned releases and health-gated rollback behavior.
A candidate binary must pass the release gates before it is promoted as a
known-good runtime.

See [Native Agent](../../docs/NATIVE_AGENT.md),
[Platform support](../../docs/PLATFORM_SUPPORT.md), and
[Agent architecture](../../docs/AGENT_ARCHITECTURE.md).
