# Security model

Status: **0.9 release-candidate security baseline**.

CommandCore intentionally provides powerful remote administration. Security is based on authenticated identities, explicit authority, device-local ceilings, privilege separation, lifecycle integrity, controlled rollout and audit—not shell blacklists.

## Northbound identity

### Bootstrap/admin path

- A strong `COMMANDCORE_API_TOKEN` is mandatory at startup.
- The web panel exchanges it for a finite-lifetime signed HttpOnly, SameSite=Strict session cookie.
- This is private-deployment bootstrap/recovery, not the multi-user identity model.

### OAuth resource-server path

When enabled, CommandCore validates externally issued OAuth/OIDC JWT access tokens against configured issuer, audience and JWKS. It validates signature, issuer, audience, expiry, issued-at and subject. `client_id`/`azp`, when present, becomes audited client identity.

Scopes:

- `commandcore:read`
- `commandcore:standard`
- `commandcore:full`
- `commandcore:admin`

`commandcore:admin` is management authority, **not automatic machine FULL_CONTROL**. Machine execution still requires execution scope plus device grant/profile/local authority.

## Device access and policy intersection

A valid token alone does not grant every machine. A subject must own the device or receive a per-device grant with a maximum profile.

Final execution permission is the minimum of:

1. caller execution scope;
2. per-device subject grant;
3. server-selected device profile;
4. root-owned device-local maximum and helper availability.

## Device identity

- one-time enrollment tokens expire, are single-use and are stored only as hashes server-side;
- Ed25519 identity is generated locally and private key never leaves the device;
- device token is stored server-side only as a hash;
- every connection requires token + fresh challenge signature;
- revocation disconnects/denies future access;
- two-phase old+new-key proven rotation uses monotonic key generation;
- interrupted/expired rotations recover without re-enrollment;
- Agent state writes are atomic and POSIX mode-restricted.

## Linux privilege separation

The network Agent runs unprivileged. FULL_CONTROL delegates over local Unix IPC to `commandcore-helper`, which runs as root.

Helper checks:

- local Unix socket only, no network listener;
- `SO_PEERCRED` peer UID;
- HMAC authentication;
- timestamp freshness;
- nonce replay window;
- root-owned local maximum policy;
- requested profile must be FULL_CONTROL.

## Update and fleet trust

Remote Agent replacement is a root/supply-chain boundary.

A device is eligible for remote signed update only when its **root-owned local policy** contains both:

1. the trusted Ed25519 release public key; and
2. one or more allowed HTTPS manifest origins.

The control plane cannot provide or replace either trust anchor. `agent.update.stage` verifies the signed manifest, origin, size and SHA-256; privileged activation independently re-verifies the signed manifest and staged artifact before changing the version pointer. Fresh authenticated health commits the candidate; failure rolls back.

Fleet rollout adds canary/ring orchestration only. It does not weaken the device-local release trust boundary. Offline devices wait rather than being marked failed, failures pause by default, and every rollout transition is durable/auditable.

## Tool classification

- READ_ONLY: inspection and Git read operations.
- STANDARD: filesystem mutation, shell/process, upload and `git.run` as the Agent user.
- FULL_CONTROL: root-helper path, services, packages, power, Docker and Agent update mutation.

Docker daemon access is FULL_CONTROL because conventional Docker socket access is effectively host-root authority.

## Filesystem integrity

`fs.patch` uses an unpredictable same-directory temporary file, fsync + atomic replace, preserves mode and refuses symlinks by default. `follow_symlinks=true` must be explicit. This reduces predictable-temp/symlink attacks; it is not a chroot or complete `openat2` sandbox.

## Audit

Audit records include authenticated user, client ID, resolved device, tool, redacted argument summary, execution ID, result, duration, exit code and risk class. Fleet management actions and rollout events are also persisted. Secret-bearing inputs, raw file payloads and environment values are not blindly logged.

## Residual risks

- FULL_CONTROL is intentionally root-equivalent; prompt injection in an authorized high-privilege AI session can become a root action.
- The native Rust Agent reduces the device runtime dependency surface on supported Linux candidates, but implementation choice does not replace OS isolation or least privilege.
- Some filesystem races remain outside hardened operations; helper APIs are not fully fd-relative/openat2-based.
- The external OAuth authorization server is part of the authentication trust boundary.
- Fleet rollout is operator-driven; automatic scheduling/ring controllers and signed fleet policy are not implemented.
- Hardware-backed device keys/attestation are not implemented.
- Browser automation is not implemented. Interactive desktop control is experimental and requires a dedicated prompt-injection/data-exfiltration boundary before stable support.
