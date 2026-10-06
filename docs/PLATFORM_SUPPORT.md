# Platform support

Support claims require runtime acceptance, not compilation alone.

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
| Browser automation | Not implemented | No supported backend |

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
