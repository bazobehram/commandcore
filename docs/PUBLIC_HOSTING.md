# Public and private CommandCore hosting

CommandCore can run two independent deployments from the same source code and vetted immutable release image. One installation is the public product at `https://commandcore.app`; the other can be an operator-owned private instance with its own hostname.

Never reuse database volumes, session secrets, Agent keys, device grants, audit logs or production OAuth clients between instances.

Public onboarding requires a dedicated OAuth resource/audience and callback `https://commandcore.app/auth/callback`. A working landing page, Angular bundle or healthy container is **not** sufficient evidence that customer sign-in, device enrollment and MCP access are ready.

## Release gates

1. Build and test immutable artifacts in GitHub-hosted CI.
2. Verify correct production OAuth discovery, independent audience and client, denied anonymous access, multi-user device isolation and Agent heartbeat.
3. Update public canary first and check rollback.
4. Back up the operator-owned private database, reconcile its live overlays into the approved source, then update that installation with the same vetted image digest.
5. Verify both separately; stop and roll back code on failure. Schema downgrades are not assumed possible.

Do not execute public pull-request code with private server credentials or privileged runner permissions.
