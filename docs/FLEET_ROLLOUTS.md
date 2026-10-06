# Fleet rollouts

Status: **implemented for Linux Agents that advertise `agent_update` and locally configured release trust**.

CommandCore fleet rollout is deliberately separate from release signing. The
control plane may select an already-signed release manifest and coordinate a
rollout, but it cannot create a trusted release signature or replace the
root-owned signing key/origin policy on a device.

## Trust boundary

A device is eligible only when all of these are true:

- server permission profile is `FULL_CONTROL`;
- device-local maximum profile is `FULL_CONTROL`;
- `agent_update=true` is advertised;
- `agent_update_trust_configured=true` is advertised;
- the manifest URL is HTTPS;
- the manifest origin is allowed by the device-local root-owned policy;
- the manifest/artifact verifies against the device-local trusted Ed25519 release key.

The control plane never sends a release public key to `agent.update.stage`.

## State machine

```text
planned
  |
  v
running ring 0 (canary)
  |
  +-- pending -> staging -> staged -> activating
  |                              |
  |                              +-- authenticated reconnect + committed local rollout
  |                                      -> committed
  |
  +-- failure -> paused (default stop_on_failure=true)
                 |
                 +-- operator resume / skip / cancel

all devices in ring satisfied
  -> next ring
  -> ...
  -> completed
```

Activation normally disconnects the network Agent because systemd restarts it.
That disconnect is not treated as success or failure. The authoritative commit
signal is the new Agent reconnecting with the target `agent_version` while its
local rollout state advertises `committed`.

## Why `advance` is one step at a time

`POST /api/fleet-rollouts/{id}/advance` performs at most one durable remote
action. This keeps rollout state observable and crash-recoverable and avoids a
hidden long-running loop inside the web process. An operator, automation, or a
future dedicated controller can call `advance` repeatedly.

## API

```text
GET    /api/fleet-rollouts
POST   /api/fleet-rollouts
GET    /api/fleet-rollouts/{id}
POST   /api/fleet-rollouts/{id}/advance
POST   /api/fleet-rollouts/{id}/resume
POST   /api/fleet-rollouts/{id}/devices/{device_id}/skip
DELETE /api/fleet-rollouts/{id}
```

Example create payload:

```json
{
  "target_version": "0.9.0-rc7",
  "manifest_url": "https://updates.example.org/commandcore/manifest.json",
  "device_ids": ["device-a", "device-b", "device-c"],
  "canary_count": 1,
  "ring_size": 2,
  "stop_on_failure": true
}
```

## Per-device MCP tools

Fleet orchestration is built on the same device tools available to authorized
MCP clients:

```text
agent.update.status      READ_ONLY
agent.update.stage       FULL_CONTROL
agent.update.activate    FULL_CONTROL
agent.update.rollback    FULL_CONTROL
```

`stage`, `activate`, and `rollback` are critical-risk audited operations.

## Local Linux policy

The trusted release key and manifest origin are local administration settings,
not fleet-plan input. Example installation:

```bash
sudo ./agent/install-linux.sh \
  --max-profile FULL_CONTROL \
  --update-public-key-b64 '<ED25519_PUBLIC_KEY_BASE64>' \
  --update-manifest-origin 'https://updates.example.org'
```

The resulting `/etc/commandcore/agent-policy.json` is root-owned.

## Current limits

- The coordinator is operator-driven; there is no autonomous background rollout daemon yet.
- Devices that do not advertise the current update capability/trust state are ineligible for fleet rollout.
- Windows update/helper support remains a preview; macOS updater/helper support is not available.

## Recovery behavior

Fleet state is designed to survive ordinary control-plane/transport interruptions:

- a `staging` row older than the recovery timeout is returned to `pending`; signed staging is idempotent;
- if the Agent goes offline between the server's status check and stage dispatch, the device returns to `pending`/waiting rather than being marked as a bad release;
- if activation dispatch races with disconnect, the staged artifact is preserved for retry;
- if activation was delivered and restart begins, the device stays `activating` until authenticated reconnect/advertised local rollout state resolves it;
- transport send failure is converted into a durable `agent_disconnected` job result instead of leaving a database job permanently `running`.
