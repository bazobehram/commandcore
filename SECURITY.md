# Security policy

CommandCore is a privileged remote-control system. A STANDARD agent can execute
commands with the authority of its operating-system account. FULL_CONTROL can
delegate selected operations to a separate local privileged helper.

Treat every exposed control path as security-sensitive.

## Supported versions

Until a stable 1.0 release exists, security fixes target the latest public
release-candidate line. Older snapshots are development history and may not
receive fixes.

## Report vulnerabilities privately

Do **not** open a public issue for:

- authentication or authorization bypass;
- device identity or enrollment bypass;
- privilege escalation;
- signature/update verification bypass;
- remote code execution outside the intended authorization model;
- credential, private-key, token, or sensitive-data exposure;
- a reliable denial-of-service against the control plane or enrolled agents.

Use GitHub Private Vulnerability Reporting when it is enabled for the repository.
If that feature is unavailable, contact a maintainer through a private channel
before disclosing exploit details publicly.

Include:

- affected version or commit;
- impact and required attacker capabilities;
- minimal reproduction;
- expected versus actual authorization boundary;
- suggested mitigation if known.

Never include real credentials or private device identity material.

## Security expectations

The effective authority of a remote action is bounded by all of:

~~~text
OAuth scope
AND account-to-device grant
AND server permission profile
AND device-local permission ceiling
~~~

Enrollment does not itself grant operational access.

Agents generate and retain device private keys locally. Internet-facing agents
should run without root/Administrator authority. Linux FULL_CONTROL uses an
explicitly configured local helper with authenticated IPC.

Read:

- docs/SECURITY_MODEL.md
- docs/THREAT_MODEL.md
- docs/PERMISSIONS.md
- docs/DEVICE_ENROLLMENT.md
- docs/RELEASE_SIGNING.md

## Safe testing

Test only systems you own or have explicit permission to test. Do not probe public
CommandCore deployments, third-party agents, or unrelated infrastructure.

Privileged helper, destructive filesystem, package-management, reboot, shutdown,
and update/rollback tests belong in disposable environments unless the operator
has explicitly authorized the target.

There is no public bug-bounty program unless separately announced.

## Coordinated disclosure

Maintainers will assess severity, reproduce the issue, prepare a fix, and
coordinate a reasonable disclosure timeline with the reporter. Public disclosure
should wait until affected users have a practical mitigation or patched release
when possible.
