# Release download and transport policy

CommandCore distributes Agents through signed manifests and immutable artifacts.
A deployment may host its own release feed.

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
