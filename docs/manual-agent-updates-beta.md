# CommandCore Public Beta — onboarding and manual Agent updates

## User experience

The **Add device** panel offers Linux and Windows choices. The browser OS is
only a suggestion; it is not necessarily the target computer. If detection
fails, the user must choose. Linux offers the signed one-command installer
only when its published endpoint is reachable. Windows offers its PowerShell
installer only when the published script contains production release pins,
not unresolved template placeholders. An unavailable Windows package is
reported honestly instead of providing a broken command.

The user approves the device enrollment using the verification code. The
device-local permission ceiling remains independent from the panel grant.
Windows defaults to STANDARD until a verified local Full Control capability
exists.

## Version notification

For each device, show the **installed** and **recommended** Agent versions.
The recommended version is configured by
`COMMANDCORE_RECOMMENDED_AGENT_VERSION`; the signed update feed is configured
by `COMMANDCORE_AGENT_UPDATE_MANIFEST_URL`. Publishing a release requires
coordinating both values with the actual **signed artifact** and supported
OS/architecture matrix; changing the recommended version alone cannot make
an update safe or installable.

A newer recommended version yields **Update available**, but a clickable
update action requires every prerequisite below:

- A connected, owned device and the operator's Full Control OAuth scope.
- FULL_CONTROL for the device's server, account grant, and local ceiling.
- The Agent's explicit `agent_update` capability.
- The Agent's `agent_update_trust_configured=true` capability.
- A configured HTTPS signed-release manifest feed.
- A strictly newer, parseable Agent release.

The server does not trust a manifest URL provided by a browser click.
It takes the target and URL from operator-controlled server settings.

## Manual Update button

The operator explicitly clicks **Update Agent** and then **Confirm update**.
The server creates one durable, audited single-device rollout. The existing
signed Agent update mechanism stages and activates the candidate, verifies
reconnection, and attempts rollback if the candidate fails. The browser
displays the rollout's current status and does not start any operation
without this confirmation.

The update applies to the **Agent only**, never to the privileged root helper
or the Control Plane. A new helper release or changed privilege scope needs
its own audited, locally authorized upgrade procedure.

## Deliberately out of scope for Public Beta

- Automatic or scheduled updates.
- Forced updates.
- Updating a disconnected device.
- Unattended privileged-helper upgrades.
- Fleet-wide background rollout orchestrators.
- Claiming that an unpublished Windows installer is production-ready.

## Release acceptance

1. Linux initial install, second install, and permission gating pass on a
   disposable device; repeat installs preserve the identity and helper.
2. Windows package is independently signed, trusted-pinned, published, and
   verified on a Windows machine before Windows Copy becomes enabled.
3. Normal read-only or insufficiently trusted devices never receive an
   actionable update button.
4. Single-device Agent update stage, restart/reconnect, commit, and failure
   rollback are tested with an actual newer signed release.
5. Private and public deployments have separate identities, data, and release controls.
