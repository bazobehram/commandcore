# Public Browser relay proof operator

Source-only operator component. This is not a deployment authorization.

The operator periodically inspects active workers from the locked private
lifecycle registry, verifies the Steel/boundary topology and the exact relay
container and sockets, and atomically signs Ed25519 v2 evidence. Stopped and
stopping workers are omitted. Duplicate identities, unexpected network members,
missing relay evidence, inspection failures and excessive inspection age deny
the whole snapshot. An observed failure replaces the previous proof with an
empty signed snapshot. A stalled or unavailable signer is bounded by the
existing proof expiration. The signing key must remain operator-only.

The CLI requires a protected signing-key file, private state directory,
attestation destination and proof group. Its refresh interval is 1–3 seconds.
The inspection budget is half the proof lifetime; the timestamp is taken before
inspection. The initial all-or-nothing failure policy intentionally favors
isolation over availability.

Tests use synthetic Docker inspection records and real Ed25519 signatures.
This does not install a service, publish API-readable owner ledgers, authorize
worker access, or verify real Netti Docker topology. Complete those steps and
two independent OAuth-account acceptance before public activation.
