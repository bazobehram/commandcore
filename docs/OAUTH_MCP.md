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
