# OAuth and MCP integration

CommandCore is an OAuth-protected MCP resource server. It intentionally does not
implement a custom authorization server.

Use an established OAuth 2.0/OIDC provider and configure CommandCore to verify
tokens according to that provider's published metadata.

## Validation requirements

For every bearer access token, CommandCore validates:

- signature;
- permitted algorithm;
- issuer;
- audience/resource;
- expiry and not-before when present;
- required CommandCore scopes.

Only after token validation does CommandCore evaluate account-to-device grants,
server permission profile, and device-local ceiling.

## Scopes

CommandCore defines these application scopes:

~~~text
commandcore:read
commandcore:standard
commandcore:full
commandcore:admin
~~~

offline_access is provider/client-specific and does not itself grant CommandCore
device authority.

Use least privilege. A client that only needs inspection should not receive
STANDARD or FULL_CONTROL.

## Effective authority

~~~text
effective authority =
    OAuth scope
    AND explicit account-to-device grant
    AND server permission profile
    AND device-local permission ceiling
~~~

A valid OAuth token without a device grant cannot operate that device.

## Discovery and PKCE

Public interactive clients should use Authorization Code with PKCE S256 when
supported by the provider. Exact registration details vary by MCP client and
provider.

Keep client-specific setup under docs/clients/. Do not weaken the server model to
accommodate one vendor-specific shortcut.

## Protected resource metadata

Internet-facing deployments should publish correct protected-resource metadata
for the MCP endpoint so clients can discover the authorization server and scopes.

Example resource:

~~~text
https://commandcore.example.com/mcp
~~~

The configured audience/resource must match the token issued by the provider.

## Browser/operator panel

The operator panel should use a public Code+PKCE client where possible. Tokens
remain server-side or in appropriately protected session handling; do not expose
refresh tokens to browser JavaScript.

Use same-site/HttpOnly cookies, state validation, and exact callback URLs.

### Operator configuration checklist

Register the panel as a public Authorization Code + PKCE client with the exact
redirect URI `https://commandcore.example.com/auth/callback`. Replace the example
origin throughout. Configure the identity provider to issue asymmetric-signed JWT
access tokens for your MCP resource and the required CommandCore scopes; opaque
access tokens are not this server's validation path.

| Server setting | Value to obtain/configure |
|---|---|
| `COMMANDCORE_OAUTH_ENABLED` | `true` after configuring the provider |
| `COMMANDCORE_PUBLIC_BASE_URL` | Canonical HTTPS origin |
| `COMMANDCORE_MCP_BASE_URL` | Canonical resource URL ending in `/mcp` |
| `COMMANDCORE_AGENT_BASE_URL` | Canonical WSS URL ending in `/agent` |
| `COMMANDCORE_PANEL_OAUTH_CLIENT_ID` | Registered public panel client ID |
| `COMMANDCORE_OAUTH_ISSUER` | Exact issuer claim, including a trailing slash if used |
| `COMMANDCORE_OAUTH_AUDIENCE` | Audience/resource the provider puts in the access token |
| `COMMANDCORE_OAUTH_JWKS_URL` | Provider's published asymmetric signing-key URL |
| `COMMANDCORE_OAUTH_AUTHORIZATION_SERVERS` | Provider authorization-server origin(s) |
| `COMMANDCORE_OAUTH_ALGORITHMS` | Matching supported asymmetric algorithm allowlist |

**Current panel compatibility limit:** the browser login implementation builds
`<issuer>/authorize` and `<issuer>/oauth/token` directly. It does not discover
arbitrary authorization/token endpoint paths from OIDC metadata. The provider
must support those paths and the panel's Code+PKCE/resource request, or the panel
flow needs a separately reviewed implementation change. Do not assume every
standards-compliant OIDC provider works with the panel merely because its JWTs
can be validated by the MCP resource server.

Use [the client guides](README.md#client-integration) for the separate MCP client's
registration requirements; the panel's callback is not that client's callback.
After login, verify scopes and explicit device grants with a real request. Keep
public bootstrap and recovery disabled for normal remote operation. A passing
`/healthz` check does not validate any of these provider settings.

## auth.whoami

auth.whoami may expose only verified identity context needed for diagnostics:

- subject;
- issuer;
- scopes;
- effective device grants.

It must never return access tokens, refresh tokens, cookies, authorization
headers, client secrets, private keys, or raw credentials.

## Provider-neutral acceptance

For any OAuth/OIDC provider:

1. verify discovery/issuer metadata;
2. obtain a least-privileged access token through the real client flow;
3. confirm auth.whoami;
4. confirm the intended device grant;
5. verify wrong issuer is rejected;
6. verify wrong audience/resource is rejected;
7. verify expired/not-yet-valid tokens are rejected;
8. verify missing scope is rejected;
9. revoke the device grant and confirm access denial;
10. test refresh behavior separately if the client requires long-lived sessions.

Provider pricing, product tiers, and client UI behavior change over time and
should not be encoded as CommandCore security assumptions.
