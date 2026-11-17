# CommandCore documentation

Start with the guides for your role. This repository contains both **current
product documentation** and **dated engineering evidence**. Historical review
notes are not installation instructions or evidence of current release status.

## New users and self-hosters

1. [README and product walkthrough](../README.md) — what CommandCore does, real
   ChatGPT/Browser examples, architecture, and a safe quick start
2. [Installation](INSTALLATION.md) — server versus Agent, enrollment, upgrades,
   and uninstall
3. [Agent-assisted installation](AGENT_ASSISTED_INSTALL.md) — hand a constrained,
   security-aware deployment task to an AI coding/operations agent
4. [Self-hosting](SELF_HOSTING.md) and [deployment](DEPLOYMENT.md) — production-style
   HTTPS/WSS, authentication, and server operations
5. [Platform support](PLATFORM_SUPPORT.md) — supported, preview, and experimental
   capabilities; do not interpret compilation as real-platform acceptance
6. [Managed Browser](BROWSER.md) — optional, operator-provisioned Browser and
   its security/isolation requirements

The **signed Agent download feed is not enabled by default**. A healthy server
does not imply an installed Agent or authorized MCP client. Check the
[installation readiness review](INSTALLATION_READINESS.md) for historical pitfalls,
then verify the current release/deployment before following any dated findings.

## AI client setup

- [Generic MCP client](clients/GENERIC_MCP.md)
- [ChatGPT](clients/CHATGPT.md)
- [Claude](clients/CLAUDE.md)
- [Gemini](clients/GEMINI.md)
- [Codex](clients/CODEX.md)
- [OAuth and MCP](OAUTH_MCP.md)

Client-product acceptance is distinct from protocol compatibility. Keep grants
least-privileged, and never assume FULL_CONTROL is required by default.

## Contributors and forking

- [Contributing and DCO sign-off](../CONTRIBUTING.md) — before your first PR
- [Development and test commands](DEVELOPMENT.md)
- [Agent instructions](../AGENTS.md) — operational boundaries for repository-aware
  AI coding agents
- [GitHub issue forms](../.github/ISSUE_TEMPLATE) and
  [pull request template](../.github/PULL_REQUEST_TEMPLATE.md)
- [Project roadmap](ROADMAP.md), [versioning](VERSIONING.md), and
  [release process](RELEASE.md)
- [Frontend transition](FRONTEND_TRANSITION.md) and [compatibility](COMPATIBILITY.md)
- [Branding](BRANDING.md) and [licensing](LICENSING.md)

Security reports **must not** be placed in public issues. Read
[SECURITY.md](../SECURITY.md) and use the private reporting route described there.

## Architecture, policy, and operation

- [System architecture](ARCHITECTURE.md) and [Agent architecture](AGENT_ARCHITECTURE.md)
- [MCP contract](MCP_CONTRACT.md) and [device protocol](DEVICE_PROTOCOL.md)
- [Device enrollment](DEVICE_ENROLLMENT.md) and [permissions](PERMISSIONS.md)
- [Security model](SECURITY_MODEL.md), [threat model](THREAT_MODEL.md), and
  [Browser security review](BROWSER_SECURITY_REVIEW.md)
- [Operator guide](OPERATOR_GUIDE.md) and [observability](OBSERVABILITY.md)
- [Agent updates](AGENT_UPDATE.md), [fleet rollouts](FLEET_ROLLOUTS.md),
  and [managed job semantics](JOB_SEMANTICS.md)
- [Release signing](RELEASE_SIGNING.md), [Linux installer verification](VERIFY_LINUX_INSTALLER.md),
  and [release downloads](RELEASE_DOWNLOADS.md)
- [Local activity](LOCAL_ACTIVITY.md) and [dependency licensing](DEPENDENCY_LICENSES.md)

## Historical reviews, release evidence, and drafts

The following documents are retained for traceability, not as current release
promises or recommended first steps:

- [Public repository readiness — October 2026](PUBLICATION_READINESS.md):
  **pre-publication snapshot**, written before this public repository existed
- [Public release checklist](PUBLIC_RELEASE_CHECKLIST.md): includes one-time
  initial publication tasks; apply recurring release gates to each new release
- [Installation readiness — October 2026](INSTALLATION_READINESS.md):
  historical findings; revalidate availability and supported features
- [Validation evidence](VALIDATION_RESULTS.md), [GitHub setup](GITHUB_SETUP.md),
  and [public MCP edge preflight](PUBLIC_MCP_EDGE_PREFLIGHT.md):
  evidence and configuration tasks must be reconciled with current CI
- [Operator legal review draft](LEGAL_OPERATOR_REVIEW_DRAFT.md):
  **unapproved, not a privacy policy or terms of service**
- [Private-only instance owner option](PRIVATE_INSTANCE_OWNER.md):
  optional guidance, **not** a public/multi-user deployment setting

If a dated note contradicts a current feature guide or the running release,
prefer current source and CI evidence; open a documentation issue to reconcile it.
