# Threat model

Status: **0.9 release-candidate baseline**.

| Threat | Current mitigation | Remaining work |
|---|---|---|
| Stolen bootstrap credential | strong required secret, TLS expected, ownership checks, audit, expiring HttpOnly panel session | rotate secret; prefer OAuth for multi-user access |
| Stolen enrollment token | short expiry, single-use atomic consume, approval, cancel | optional stronger enrollment ceremony |
| Stolen device token | insufficient alone; Ed25519 challenge also required | automated token rotation policy |
| Stolen old device key | two-phase Ed25519 rotation, key generation, revocation | hardware-backed keys/attestation |
| Rotation interrupted | pending local key persisted atomically; old/new convergence; stale pending cleanup | broader fault-injection matrix |
| Compromised control plane | device-local authority ceiling prevents privilege elevation; release key + update origin remain local root-owned trust anchors | signed job envelopes/attestation if threat model expands |
| Compromised STANDARD Agent | dedicated OS user; helper denies unless local FULL_CONTROL | native Agent hardening/sandboxing |
| Compromised FULL_CONTROL Agent | helper is intentionally root-capable when locally enabled | optional per-operation local approvals |
| Malicious MCP client | auth, scopes, grants, profiles, local ceiling, audit | richer approval/policy workflows |
| Prompt injection | least privilege, grants/scopes, dangerous annotations, power confirmation, audit | source-aware risk policy / local confirmations |
| Shell injection | structured tools use argv/typed args; raw shell is deliberately arbitrary | optional shell approval; never rely only on blacklists |
| Package/service option injection | option-like inputs rejected; argv execution | manager/platform-specific validation expansion |
| Path traversal | no fake sandbox claim; OS identity/permissions authoritative | optional allowed roots; fd-relative/openat2 primitives |
| Symlink/temp-file attacks | atomic `fs.patch`, random same-dir temp, symlink refusal by default | harden all helper filesystem primitives similarly |
| Agent auth replay | fresh random signed connection challenge | hardware attestation if required |
| Helper request replay | HMAC + timestamp + nonce cache | persistent replay journal if restart-window threat matters |
| Cross-device result spoofing | execution ID bound to routed device connection | signed per-job envelopes if needed |
| Agent disconnect during job | routed job becomes disconnected; Agent kills process group where applicable | resumable safe job classes only |
| Dispatch/offline race | transport failure becomes durable `agent_disconnected`; fleet stage remains retryable | broader chaos testing |
| Server restart during fleet stage | stale `staging` recovers to signed/idempotent retry after timeout | dedicated controller lease/worker for very large fleets |
| Server restart with running job | stale jobs marked interrupted | durable safe-job reconciliation |
| Secret/log leakage | redaction, bounded output, separate detailed output policy | structured secret classifiers/retention controls |
| Root helper remote exposure | Unix socket only, peer UID + HMAC, no network listener | SELinux/AppArmor profiles |
| Helper disappears | capability drop + authority downgrade | operator alerting improvements |
| Lost/stolen machine | server revoke + live disconnect | local credential wipe/MDM integration |
| Malicious update manifest | Ed25519 signature + root-owned trusted release key | HSM/release ceremony |
| Manifest-origin SSRF/egress abuse | root-owned allowed HTTPS manifest origins; control plane cannot choose arbitrary host | optional IP/DNS pinning policy |
| Tampered update artifact | HTTPS + signed metadata + SHA-256 + size; privileged re-verification | artifact transparency/provenance |
| Bad signed candidate | fresh authenticated health gate + automatic rollback | multi-signal health policies |
| Fleet-wide bad release | canary/rings, durable one-step advance, stop-on-failure default, operator skip/resume/cancel | automated blast-radius budgets and schedules |
| Supply-chain compromise | clean public source, CI, signed releases, no vendored Desktop Commander | maintain complete lock/SBOM/vulnerability scan/artifact provenance |
| Browser/desktop automation risk | browser not implemented; desktop experimental and capability-gated | dedicated policy/acceptance boundary before stable support |

## Trust statement

On a machine deliberately configured locally for FULL_CONTROL, the owner authorizes CommandCore to perform root administration. The goal is not to cripple legitimate root actions; it is to make that authority explicit, locally enabled, authenticated, revocable, lifecycle-safe and auditable.
