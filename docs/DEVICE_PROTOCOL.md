# Device protocol

Version: `1`

The Agent protocol is CommandCore-owned and independent of MCP. v0.5+ adds identity-lifecycle messages additively without changing protocol version 1.

## Connection

1. Agent opens outbound WebSocket to `/agent`.
2. Authorization header supplies device ID + device token.
3. Server validates approved/non-revoked device and token hash.
4. Server sends a fresh challenge nonce.
5. Agent signs `commandcore-agent-auth-v1\n<device_id>\n<nonce>` with its local Ed25519 private key.
6. Server verifies the stored public key and protocol version.
7. Agent advertises Agent version + capabilities + local permission maximum.
8. Server acknowledges with current key generation and a connection-scoped key-rotation nonce.

## Core messages

- `challenge`
- `hello`
- `hello.ack`
- `heartbeat`
- `job.request`
- `job.output`
- `job.result`
- `job.cancel`

Heartbeat may carry updated capabilities, allowing local helper/authority changes to take effect without reconnect.

## Device-key rotation

Additive v1 messages:

- `device.key.rotate.prepare`
- `device.key.rotate.prepared`
- `device.key.rotate.confirm`
- `device.key.rotate.ack`
- `device.key.rotate.error`

Prepare proof is signed by **both** the active key and newly generated key over:

```text
commandcore-key-rotation-prepare-v1
<device_id>
<connection_rotation_nonce>
<new_public_key_b64>
```

The server stores the new public key only as pending. Confirmation is signed by the pending new key over:

```text
commandcore-key-rotation-confirm-v1
<device_id>
<rotation_id>
```

Only then does the server atomically promote the pending key, retain previous-public-key audit metadata and increment `key_generation`. Pending rotations expire.

## Job semantics

Each request has a unique execution ID. Output/results are accepted only from the device to which that job was routed. Disconnect does not automatically replay arbitrary jobs because duplicate side effects may be unsafe.

## Versioning

Protocol version is independent of server/Agent package version. Incompatible protocol versions are rejected rather than silently executed. Additive message types/capabilities may evolve within a compatible protocol revision; breaking wire changes require a new protocol version.

## v0.6+ cross-language conformance vectors

`packages/protocol/agent-protocol-v1-vectors.json` freezes exact Agent Protocol v1 authentication and key-rotation signing inputs/outputs for future implementations. The embedded private seeds are explicitly test-only deterministic fixtures. Production keys continue to be generated locally per device and never committed.
