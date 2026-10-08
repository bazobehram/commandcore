# Release download and transport policy

CommandCore distributes Agents through signed manifests and immutable artifacts.
A deployment may host its own release feed.

## Publish a deployment feed

The default server does not ship agent binaries or a signed manifest. Its
distribution routes return 404 until `COMMANDCORE_DISTRIBUTION_DIR` is configured
and the requested files exist. A healthy container alone does not provide an
end-user installer.

First build, accept, and sign a release following [RELEASE.md](RELEASE.md) and
[RELEASE_SIGNING.md](RELEASE_SIGNING.md). Use artifact URLs on your intended HTTPS
origin, retain the source commit/provenance, and verify signatures and artifact
hashes independently. Keep the signing private key outside the server.

With an already signed manifest and its independently trusted public key, generate
the Linux installer in the release environment:

~~~bash
python scripts/package_installers.py ./manifest.json \
  --public-key "$COMMANDCORE_RELEASE_PUBLIC_KEY_B64" \
  --manifest-url https://commandcore.example.com/releases/agent/manifest.json \
  --linux-only --output ./published-feed
~~~

`--linux-only` avoids advertising the Windows preview as an accepted release. The
current packager expects a Linux x86_64 executable entry even for a multi-architecture
feed. Installer packaging does not itself perform platform acceptance or publish
the agent binaries.

The directory served by CommandCore should contain real accepted files, for example:

~~~text
published-feed/
  linux.sh                         generated pinned installer
  uninstall-linux.sh               reviewed install/uninstall-linux.sh
  manifest.json                    current signed manifest
  <version>/
    manifest.json                  retained signed manifest
    linux.sh                       immutable reviewed installer, when published
    commandcore-agent-linux-x86_64  exact binary named by the signed manifest
    commandcore-agent-linux-arm64   only if built, signed, and accepted
~~~

Copy the artifacts to the paths declared in the signed manifest. Preserve
immutable version paths. If installer verification uses `installers.linux`, the
final signed manifest must describe the actual generated script's URL, hash, and
size; the packager does not add that metadata for you.

For the default Docker Compose deployment, add an operator-owned override file:

~~~yaml
services:
  commandcore:
    environment:
      COMMANDCORE_DISTRIBUTION_DIR: /opt/commandcore-feed
    volumes:
      - ./published-feed:/opt/commandcore-feed:ro
~~~

The existing container user (UID 10001) needs read/traverse access to this public
feed. Mount only published files, never a signing-key directory. Recreate the
service with the override, then confirm these endpoints return 200:

~~~bash
curl -fsS https://commandcore.example.com/install/linux -o /dev/null
curl -fsS https://commandcore.example.com/releases/agent/manifest.json -o /dev/null
~~~

These checks establish availability, not signature validity. Follow
[installer verification](VERIFY_LINUX_INSTALLER.md) before execution and pass
`--server https://commandcore.example.com` explicitly. The installer template's
default server remains an example hostname even when the script is downloaded
from another host.

## Canonical deployment paths

~~~text
/install/linux
/install/uninstall-linux
/releases/agent/manifest.json
/releases/agent/<version>/<artifact>
~~~

The public host is deployment-specific, for example:

~~~text
https://commandcore.example.com
~~~

## Selection

The installer selects an artifact using operating system, architecture, and
signed manifest metadata. Device identity must not determine which executable is
downloaded.

Unsupported platform/architecture combinations fail closed before activation.

## Trust

The installer:

1. obtains the manifest over verified HTTPS;
2. verifies the Ed25519 signature using a pinned release public key;
3. validates product/schema/version metadata;
4. downloads the selected immutable artifact;
5. verifies exact size and SHA-256;
6. installs into a versioned location;
7. switches the active release only after verification;
8. requires fresh connected health;
9. restores the previous release when activation/health fails.

The release private key never belongs on the server or Agent.

## Bounded network behavior

Downloads use bounded connect and transfer deadlines, clean partial files after
failure, and preserve certificate/hostname validation.

Do not implement raw-IP TLS bypass, disabled certificate verification, or
unbounded retry loops as connectivity workarounds.

## Rollback

An upgrade preserves the prior versioned executable and installation metadata.
A failed candidate restores the previous active target and service definition.

Downgrade is denied by default except through an explicit local recovery path.

## Activity

Local diagnostics are available through the Agent status/activity commands when
supported:

~~~bash
commandcore-agent status
commandcore-agent activity
commandcore-agent activity --last 30
commandcore-agent activity --errors
~~~

Activity output must follow the project's redaction policy and must not expose
bearer tokens, refresh tokens, private keys, or unredacted secrets.

## Release evidence

Every public release should retain:

- source commit;
- CI result;
- signed manifest;
- artifact hashes;
- SBOM;
- dependency/vulnerability audit result;
- platform acceptance matrix;
- installer/update/rollback acceptance result;
- provenance/signing record.
