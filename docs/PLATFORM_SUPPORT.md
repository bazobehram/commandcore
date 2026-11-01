# Platform support

Support claims require runtime acceptance, not compilation alone.

Windows at-logon task **registration** is covered by disposable CI. Actual
interactive login/reboot acceptance requires the separately gated
[disposable Windows desktop VM harness](WINDOWS_INTERACTIVE_VM_ACCEPTANCE.md).
The offline harness tests only a harmless task action, **not** real Agent
startup, enrollment, reconnect or upgrade. Windows remains Preview.

Disposable Windows signed-installer CI additionally verifies negative safety paths:
normal-user repeat installation and attempted `-Upgrade` without the existing
identity/interactive task are rejected, with the signed release binary,
manifest, activation metadata and install marker unchanged. This is **not** an
upgrade success/rollback test; those remain unverified until an isolated
end-to-end Windows installation and interactive Task Scheduler lifecycle pass.

The same disposable Windows native-installer CI fixture also fetches a locally
served manifest whose Ed25519 signature no longer matches its contents and a
modified verifier binary whose SHA-256 no longer matches the packaged pin.
Both must be rejected before creating any Agent installation or identity state;
these tests cover **integrity fail-closed behavior**, not a successful version
upgrade or post-activation rollback.

| Platform / component | Status | Evidence / limits |
|---|---|---|
| Linux Python Agent | Supported reference | Core filesystem/shell/process/system/transfer/Git, reconnect, helper, update regression |
| Linux x86_64 Rust Agent | Supported candidate | fmt/Clippy/tests/release build, core parity, reconnect, signed lifecycle |
| Linux ARM64 Rust Agent | Supported candidate | Native runtime/core/reconnect acceptance plus signed artifact validation |
| Linux signed user installer | Supported candidate | Integrity verification, enrollment, systemd lifecycle, rollback acceptance |
| Windows Python Agent | Preview | Enrollment and core runtime work exists; complete release lifecycle remains gated |
| Windows Rust Agent/helper | Preview / incomplete | Do not advertise FULL_CONTROL until real privileged-helper acceptance passes |
| macOS Agent | Planned | No supported release |
| Interactive desktop control | Experimental | Requires a real interactive user session; disabled by default |
| Managed Browser | Linux deployment candidate | Provisioned isolated workers; public research and private human control; see [Browser guide](BROWSER.md) |

## Capability advertisement

The Agent must advertise what the actual running environment can do. A headless
or service session must not claim screen, mouse, keyboard, or clipboard control.

Feature flags do not convert an experimental capability into a supported release
claim.

## Release rule

A platform moves to Supported only after:

- clean installation;
- restart/reboot lifecycle where relevant;
- reconnect after server/transport interruption;
- core operation matrix;
- revocation;
- update and rollback when distributed through the signed installer;
- security-boundary tests;
- documented uninstall/recovery;
- CI plus at least one real runtime acceptance environment.
