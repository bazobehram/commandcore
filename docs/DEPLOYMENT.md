# Deployment

This guide describes the production shape of a CommandCore deployment. It does
not prescribe a particular cloud, reverse proxy, DNS provider, or OAuth vendor.

## Components

- CommandCore server
- SQLite persistence
- HTTPS/WSS reverse proxy
- external OAuth/OIDC provider for user-facing remote MCP access
- one or more outbound CommandCore Agents
- optional privileged helper on explicitly trusted Linux devices

## Server deployment

Run the server behind a reverse proxy and expose one canonical HTTPS origin:

~~~text
https://commandcore.example.com
~~~

Recommended public paths:

~~~text
/        operator UI
/mcp     remote MCP
/agent   Agent WebSocket
~~~

Keep the internal application listener private.

## Configuration

Start from .env.example and replace every placeholder. Generate new credentials
for each deployment. Never reuse example, test, or repository credentials.

Production configuration should explicitly define:

- public base URL;
- Agent WebSocket URL;
- bootstrap/recovery credential policy;
- OAuth issuer;
- OAuth audience/resource;
- JWKS URL or discovery metadata;
- allowed token algorithms;
- database path;
- trusted release/update configuration when remote updates are enabled.

## Reverse proxy requirements

The proxy must support:

- TLS 1.2 or newer;
- HTTP streaming required by the MCP transport;
- WebSocket upgrade for /agent;
- realistic idle timeouts for long-lived Agent connections;
- forwarding of the original HTTPS scheme/host where the application validates
  external URLs.

Test reconnect behavior after proxy and server restarts.

## Agents

Install Agents under a normal operating-system account by default. Enrollment
creates a device identity; operator approval and an account grant are separate
steps.

Start with READ_ONLY or STANDARD. FULL_CONTROL requires explicit local
configuration and should never be enabled merely to simplify onboarding.

## Database migration

Server startup applies numbered migrations. Before upgrading:

1. create a verified SQLite backup;
2. record the currently deployed application version;
3. retain the previous application artifact/image;
4. apply the upgrade;
5. run health and MCP acceptance;
6. roll back the application if acceptance fails.

Database downgrade migrations are not assumed to exist.

## Release and update trust

Agent release manifests and artifacts are signed. The release private key must
not live on the internet-facing control plane or Agent.

A device may participate in remote update/fleet rollout only after local policy
pins the trusted release public key and allowed manifest origin.

## Production acceptance

Before calling a deployment production-ready, verify:

- HTTPS certificate and hostname validation;
- OAuth issuer/audience/JWKS validation;
- MCP initialize and tools discovery;
- explicit device grant behavior;
- Agent enrollment, outbound WSS, heartbeat, and reconnect;
- server restart reconnect;
- reverse-proxy restart reconnect;
- safe filesystem/system operation on a non-critical device;
- STANDARD shell only when intended;
- revocation denial;
- database backup and restore;
- audit records;
- signed upgrade and rollback when release updates are enabled.

FULL_CONTROL, desktop input, package management, reboot, and shutdown require
separate explicit acceptance.
