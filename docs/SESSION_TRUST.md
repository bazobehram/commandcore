# Host conversation metadata: unresolved release gate

`openai/session` is supplied in MCP request metadata and is used to correlate
activity with a conversation. The server validates the OAuth issuer, subject,
client and scope and rechecks device grants, but it does not independently
verify that the caller is the ChatGPT host or that the metadata value belongs to
the current conversation. HMAC-hashing that value does not authenticate its
origin. OpenAI describes it as a client-provided identifier for correlation:
https://developers.openai.com/plugins/reference.

A local MCP test reproduces the gap: with the same valid issuer, subject, client,
STANDARD scope and device grant, a caller that knows a different conversation's
session value can submit that value and retrieve its timeline events. This does
not establish cross-subject access, show how the identifier could be obtained,
or demonstrate behavior of an actual ChatGPT client. Tests using different
session values only demonstrate separation when callers supply different values.
Viewer references are issuer/subject/client-bound, but can be issued based on
the same unauthenticated session metadata. Isolated checks also show that the
same principal and copied session value can see a conversation-filtered
Activity event and pass the Browser conversation gate; the latter check does
not start or operate a Browser worker.

This is a **release blocker** for any claim that conversation metadata is an
authenticated isolation boundary. Browser and Activity require end-to-end
assessment with the actual host and Browser worker.

Before release, review a design that either authenticates host-to-server
conversation context through an independently verifiable binding, or explicitly
limits the security claim to an approved threat model and demonstrates that the
actual host and network prevent untrusted callers from asserting that context.
An OAuth client ID, a trusted-looking header, a hash of the session value, or a
proxy reachable by arbitrary callers is not sufficient by itself. Verify the
chosen design with real ChatGPT, same-subject adversarial requests, other-subject
requests, revoked grants, viewer replay and reconnect behavior. Preserve Shell,
Browser and existing operation-card compatibility; do not silently disable them
as a substitute for the requested acceptance. Document the residual threat and
obtain independent security review before production deployment.

`tests/test_host_session_trust.py` is a strict expected failure for the known
spoof case. A passing test suite containing that expected failure is not a
security acceptance; remove the marker only when the intended protection is
implemented and the regression passes.
