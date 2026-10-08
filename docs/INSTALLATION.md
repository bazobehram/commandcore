# Installation

CommandCore separates server deployment from device Agent installation.

The server and agent may run on the same Linux machine or on different machines.
Each managed computer needs its own enrolled agent; starting the server does not
automatically install one. See [installation readiness](INSTALLATION_READINESS.md)
for supported platforms and remaining release work.

## Linux Agent

A deployment can expose a signed installer at:

~~~bash
curl -fsSL https://commandcore.example.com/install/linux | sh -s -- --server https://commandcore.example.com
~~~

Replace the example host with the CommandCore deployment.

This command requires an operator-published signed feed and a generated installer
with a pinned verification key. Default Compose does not publish either endpoint;
404 means the feed has not been published, not that installation should bypass
verification. Follow [release-feed setup](RELEASE_DOWNLOADS.md#publish-a-deployment-feed).
Pass `--server` even when downloading from your own server.

The current native Linux installer requires x86_64 or ARM64, glibc 2.36 or newer,
curl 8.4 or newer, Python 3, and OpenSSL with Ed25519 support. The default service
workflow also needs a working systemd user manager. Check these prerequisites
before choosing a distribution; Linux support does not cover every distribution.

The installer is designed to run as the normal user and to:

- verify the signed release manifest;
- select the correct OS/architecture artifact;
- verify exact artifact hash and size;
- install versioned binaries under the user's data directory;
- preserve device identity across upgrades;
- configure a systemd user service;
- enable boot persistence where supported;
- verify fresh connected health after activation;
- roll back automatically when activation fails.

The default installation does not grant FULL_CONTROL.

## Enrollment

After installation, the Agent creates or reuses its local device identity and
starts enrollment.

The operator should:

1. open the enrollment URL;
2. sign in;
3. compare the verification code shown on the device;
4. review device name, platform, architecture, and requested local ceiling;
5. approve or reject;
6. explicitly choose whether the account receives an initial device grant.

Enrollment and operational authorization are separate.

## Upgrade

~~~bash
curl -fsSL https://commandcore.example.com/install/linux | sh -s -- --server https://commandcore.example.com --upgrade
~~~

Upgrade requires a valid existing managed installation and preserves identity.
The previous version remains available for rollback until the new version passes
fresh-health validation.

## Uninstall

~~~bash
curl -fsSL https://commandcore.example.com/install/uninstall-linux | sh
~~~

Uninstall should remove only files/services owned by the managed installation.
Identity may be retained by design so accidental reinstall does not silently
create a different device. Revoke the device from the server when permanent
removal is intended.

## Default Linux paths

Typical user installation paths are under:

~~~text
~/.local/share/commandcore-agent
~/.config/commandcore
~/.local/bin/commandcore-agent
~/.config/systemd/user/commandcore-agent.service
~~~

Exact paths are recorded in managed installation metadata.

## FULL_CONTROL

The public normal-user installer does not implicitly enable privileged access.

FULL_CONTROL requires an explicit local privileged-helper installation and a
device-local policy ceiling. See PERMISSIONS.md and SECURITY_MODEL.md.

## Windows

Windows installation remains a preview. Candidate scripts and native code may be
present, but do not treat them as a stable supported installer until the platform
matrix records full real-runtime install/reboot/reconnect/update/rollback
acceptance.

## Source/development installation

Developers can install directly from the repository:

~~~bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt -e . -e ./agent
~~~

This is not the same trust path as the signed end-user Agent installer.

### Source agent evaluation (Linux)

When no signed feed is available, a technical operator can run the Python reference
agent from a reviewed checkout. Requires Python 3.11 or newer and an already
configured server with a working operator login. Run as the normal device user:

~~~bash
python3 -m venv .venv-agent
. .venv-agent/bin/activate
python -m pip install ./agent
commandcore-agent enroll https://commandcore.example.com --name my-linux-pc
commandcore-agent run
~~~

Open the review URL printed by enrollment, sign in, compare the verification code,
and approve the device. Explicitly select an initial account grant if that account
should operate the device. Enrollment alone is not a grant. Replace the host and
device name with your own values.

This foreground evaluation does not create a service, enable boot persistence,
or configure signed updates. Keep the terminal open while evaluating. Preserve
the device identity; do not overwrite it to troubleshoot authentication. Use
`commandcore-agent status` to inspect the enrolled configuration. For a managed
installation, complete the signed feed and platform lifecycle acceptance first.
