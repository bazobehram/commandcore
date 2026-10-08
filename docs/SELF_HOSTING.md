# Self-hosting

CommandCore is designed to be self-hosted. The server can run from source or in
a container, while enrolled devices connect outbound over authenticated WSS.

## Minimal architecture

~~~text
MCP clients
    |
 HTTPS + OAuth
    v
reverse proxy
    |
    v
CommandCore server ---- SQLite
    ^
    |
 outbound WSS
    |
CommandCore agents
~~~

The server should normally listen only on an internal interface. A reverse proxy
terminates public TLS and forwards HTTPS/WSS to CommandCore.

## Development start

~~~bash
cp .env.example .env
./scripts/generate-secret.sh   # generate COMMANDCORE_API_TOKEN
./scripts/generate-secret.sh   # generate a different COMMANDCORE_PANEL_SESSION_SECRET
# Put both secrets and the deployment URLs into .env.
# Bootstrap and recovery stay disabled by default.

docker compose up -d --build
~~~

The example Compose file binds the server to localhost by default. Do not expose
the internal application port directly to the internet.

`/healthz` confirms that the server started; it does not confirm operator login,
OAuth, device enrollment, or agent release distribution. The default template has
OAuth and bootstrap disabled, so configure a deliberate login path before
expecting to use the panel. For local HTTP evaluation, use loopback deployment
URLs and set `COMMANDCORE_PANEL_COOKIE_SECURE=false` only for that local HTTP
environment. Keep secure cookies enabled for HTTPS deployments.

The server does not automatically manage its host. Install and enroll an agent on
that host if desired, or enroll agents on other computers. A Linux server can be
used with a Windows agent, but Windows remains preview. See
[Installation](INSTALLATION.md) and [installation readiness](INSTALLATION_READINESS.md).

## Public URL

Use one canonical deployment origin, for example:

~~~text
https://commandcore.example.com
~~~

Typical resources:

~~~text
https://commandcore.example.com/
https://commandcore.example.com/mcp
wss://commandcore.example.com/agent
~~~

The example domain is documentation only. CommandCore must not hard-code the
operator's real domain.

## Authentication

The example configuration keeps public bootstrap and recovery disabled. For a
controlled first-time bootstrap, set a strong unique API token and deliberately
enable public bootstrap only for the onboarding window. Disable it again before
normal remote operation. Keep recovery disabled except during an explicit recovery
procedure.

For production remote MCP access, configure a standards-based OAuth/OIDC provider.
CommandCore validates the issuer, audience/resource, signature, expiry, and
required scopes, then applies independent device grants and local/server
permission ceilings.

Provider-specific setup belongs in deployment documentation rather than core
authorization logic. See OAUTH_MCP.md.

## Persistence

The server stores operational state in SQLite, including:

- device public identity and lifecycle state;
- account-to-device grants;
- permission profiles;
- selections;
- audit metadata;
- rollout state.

Back up the database using SQLite's online backup mechanism or a controlled
quiesced copy. Test restore procedures periodically.

Device private keys stay on devices and are not stored in the control-plane
database.

## Network requirements

Required:

- client -> reverse proxy over HTTPS;
- agent -> reverse proxy/server over outbound HTTPS/WSS;
- server -> configured OAuth/JWKS endpoints as required by the identity provider.

Not required:

- inbound command ports on enrolled devices;
- inbound SSH to enrolled devices;
- public exposure of the internal CommandCore application port.

## TLS

Production deployments must use valid TLS. Do not disable certificate or hostname
verification to work around configuration problems.

## FULL_CONTROL

FULL_CONTROL is an explicit local opt-in. On Linux, the network-facing agent stays
unprivileged and delegates allowed privileged work to a separate authenticated
local helper.

Do not run the internet-facing agent as root for convenience.

## Backups and recovery

Back up configuration templates and the SQLite database, but keep runtime secrets
and private signing keys out of source control.

Release-signing private keys should be offline or isolated from the internet-facing
server. If a device identity is lost, prefer revocation and re-enrollment over
copying unknown private state between machines.
