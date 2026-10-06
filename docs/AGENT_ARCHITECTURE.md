# Agent architecture

CommandCore separates the internet-facing Agent from optional local privileged
execution.

## Network Agent

The Agent is intentionally unprivileged by default. It owns:

- outbound WSS;
- local Ed25519 device identity;
- enrollment and authenticated reconnect;
- heartbeat/capability advertisement;
- READ_ONLY/STANDARD execution;
- managed process supervision;
- local activity/audit metadata;
- signed-release health reporting.

It exposes no inbound command port.

## Permission boundary

~~~text
CommandCore Agent (unprivileged)
        |
        | authenticated local IPC
        v
optional privileged helper
~~~

The helper is a separate local trust boundary. It validates the device-local
policy and never allows the control plane to raise a device above its local
ceiling.

FULL_CONTROL must be explicitly enabled on the device.

## Native Rust Agent

The native Rust implementation is the preferred Agent for supported Linux binary
releases. It covers enrollment, authenticated WSS, reconnect/heartbeat, managed
jobs, core executors, key rotation, health markers, release verification, and
delegation to the existing helper when locally enabled.

The Python Agent remains a reference implementation and controlled fallback.

## Managed jobs

Long-running jobs are represented by CommandCore process handles rather than by a
single MCP request lifetime.

The native Agent retains bounded output and job metadata so a server or transport
reconnect does not automatically destroy the job.

Host reboot is a different boundary and ordinary jobs are not promised to resume
after reboot.

## Runtime health

After authenticated connection and server acknowledgement, an Agent can publish a
credential-free health marker containing the active version and connected state.

The updater uses a fresh marker written after activation to decide whether the
candidate is healthy. A failed candidate restores the prior known-good release.

## Updates

Agent release trust is local. A remote server may request an update operation only
when the device has already pinned the required release trust.

Signature, artifact hash/size, version, and configured origin are verified before
activation.

## Protocol separation

The Agent Protocol is independent of MCP:

~~~text
AI client <-> MCP <-> CommandCore server <-> Agent Protocol <-> device
~~~

This allows new MCP clients without changing device identity or transport, and
allows Agent implementations without making each device a local MCP server.

See DEVICE_PROTOCOL.md and MCP_CONTRACT.md.
