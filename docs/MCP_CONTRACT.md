# MCP contract

Status: **implemented in the 0.9 release-candidate family**  
Primary protocol revision: `2026-07-28`.

## Stateless model

MCP transport/session identity is not authoritative selected-device state. `devices.select` returns an expiring `selection_id` bound to authenticated subject + immutable device ID. Explicit `device_id` wins where supported. Every privileged action re-resolves/audits the immutable device.

## Authentication

CommandCore supports:

1. **Bootstrap bearer** — private/admin recovery path.
2. **OAuth 2.1 resource-server mode** — multi-user/client path with external issuer/JWKS.

OAuth validation covers signature, issuer, audience, `exp`, `iat`, `sub`; `client_id`/`azp` becomes audited client identity. MCP `clientInfo` is informational only.

Scopes:

```text
commandcore:read
commandcore:standard
commandcore:full
commandcore:admin
```

`commandcore:admin` controls management APIs but does not independently grant machine FULL_CONTROL.

## Device authorization

Effective execution authority is:

```text
caller execution scope
∩ device subject grant
∩ server-selected profile
∩ device-local maximum/helper availability
```

Grant revoke is rechecked even for existing selection handles.

## Tool families

Current families include device discovery/selection, filesystem, shell/process, system/metrics/power, transfer, Linux services/packages, Git, Docker and Agent lifecycle.

Agent lifecycle tools:

```text
agent.update.status     READ_ONLY
agent.update.stage      FULL_CONTROL
agent.update.activate   FULL_CONTROL
agent.update.rollback   FULL_CONTROL
```

These tools do not permit callers to supply release trust anchors; signing key and allowed manifest origin are root-owned device policy.

Fleet rollout itself is an operator/admin API/panel concept, not hidden MCP session state. Generic MCP clients continue to use the same per-device lifecycle tools.

## Compatibility and validation

A limited initialize-era compatibility path exists for older clients. Current release gates include generic MCP→Agent `hostname`, OAuth/JWKS, scope/grant intersection, READ_ONLY/STANDARD/FULL_CONTROL, Git, key rotation, signed single-device rollout and fleet rollout state-machine smoke.

Every deployment should validate the final HTTPS endpoint with an independent MCP client/Inspector in addition to project fixtures.
