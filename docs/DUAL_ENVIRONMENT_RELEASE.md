# CommandCore dual-environment release contract

The public service at `https://commandcore.app` (Netti) and the private service at `https://commandcore.synovaq.org` (homeserver) are **two isolated deployments of one product**, not independent product forks.

## Invariants

- Source of truth: the public `commandcore` repository. A change is not released by modifying only one server or copying a manually customized frontend.
- The UI, backend, agent protocol, and customer-facing fixes must be released from the **same reviewed commit and immutable artifact digest** to both environments, with explicit compatible feature flags. Planned staging differences are documented.
- Distinct Auth0 tenants, clients, OAuth issuers, databases, device identities, enrollment keys, secrets, storage, backup sets, TLS/tunnel configuration, and security policy. **Never replicate user data or credentials between installations.**
- Environment-specific public landing pages, branding copy, infrastructure and domain-routing configuration may differ, but the authenticated workspace experience should not.
- `/workspace/` is the canonical authenticated UI path on both domains. The public legacy `/app/` path must redirect to `/workspace/`.

## Release train (target; NOT currently automated)

1. CI/security/release-candidate checks pass on a reviewed commit, including browser, Linux, Windows and permission-boundary tests.
2. Create and attest one immutable release image/build and frontend asset manifest. Pin exact digests, never a floating `latest` tag.
3. Publish an environment-specific release plan (image digest, frontend manifest, config schema diff, migrations, approval, rollback and health gates) without secrets.
4. Perform a read-only topology and database backup check on both environments. Confirm migration safety and per-environment rollback readiness.
5. Use a protected production approval and least-privileged executor **per target**; no arbitrary public-PR code on self-hosted deployment executors.
6. Apply the same release digest to the two environments in a controlled sequence with health checks at each stage; rollback the affected target immediately on failure. A healthy deployment of only one target is a **parity exception**, not a completed dual release.
7. Verify backend compatibility, authentication, enrollment, authorization boundaries, and `/workspace/` assets on both domains before marking the release fully promoted.
8. Record deployed commit/digest and timestamps for both. Restore parity promptly after any emergency hotfix.

## Current monitoring

`scripts/check_dual_workspace_parity.py` is a **read-only UI asset check**. It compares current JavaScript, CSS and brand SVG from both public endpoints and fails if artifacts drift. `.github/workflows/dual-workspace-parity.yml` runs it on a GitHub-hosted runner daily and on manual dispatch. It does **not** deploy, handle secrets, validate token scopes, or prove backend parity. GitHub workflow failures require human investigation and approved release action.

## Blocking prerequisites

`bazobehram/commandcore-deploy` explicitly has **no production deployment executor or approval workflow**. Do not enable unattended parallel deployments until its security preconditions are met: approved exact Compose topology, dedicated restricted executors, protected environments, artifact attestations, staged migration/rollback, audited operations, and cross-environment acceptance tests. Manual private overlays and server-only fixes must be ported upstream to the shared source or listed as reviewed environment-specific deltas.
