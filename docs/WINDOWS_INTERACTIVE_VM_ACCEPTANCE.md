# M3: isolated interactive Windows VM task-lifecycle acceptance

**Status:** Operator-run acceptance harness, not evidence that CommandCore Windows Agent
logon, enrollment, reboot, rollback or general Windows support already works.
See [platform support](PLATFORM_SUPPORT.md) and [release issue #156](https://github.com/bazobehram/commandcore/issues/156).

## Why a separate VM?

GitHub Windows Actions can verify signed installation under a disposable
standard-user credential and registration of an at-logon Scheduled Task.
They **cannot claim a real interactive logon** simply by executing
Start-Process -Credential. Attempting to launch the task that way in #168
failed closed (worker_task_launch). Do not fix this by changing the task to
run elevated, using a saved account password, or altering production devices.

## Safe environment

Use a newly provisioned **disposable Windows 11 x86_64 desktop VM**, with a
local **non-administrator** test account signed into its desktop. The harness
requires Windows 11 build 22000+, workstation product type, native x64 CPU and
64-bit PowerShell, a known virtual-machine manufacturer/model, a non-admin
interactive token and a nonzero GUI session. It rejects Windows 10, Windows
Server, ARM64 guests (including x64-emulated PowerShell), GitHub CI, Session 0,
and pre-existing tasks. It requires explicit consent. Do not execute it on a
personal Windows PC or a production Windows host.

Microsoft currently provides a 90-day Windows 11 Enterprise evaluation ISO:
[Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise).
Choose an **x64** image, not Arm64. Verify the exact ISO SHA-256 against
[Microsoft's published evaluation hashes](https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file)
for the **specific build, locale and edition** before installation. Do not
assume the hash of a different ISO release or locale is interchangeable.
Microsoft's license and any evaluation/activation conditions still apply.
Use a separately provisioned test VM host; **do not** allocate memory, disk
or CPU for this VM on homeserver, Netti or the personal Windows PC.

The offline `windows_interactive_vm_platform_probe.ps1` matrix contains 11
negative cases covering Windows 10, Server, ARM64, 32-bit execution, physical
hardware and invalid metadata. It runs on CI without touching Task Scheduler.
Passing the platform gate is a safeguard, not hypervisor attestation: model
and manufacturer strings can be forged, so the test operator must independently
confirm the disposable guest's provenance.

The harness uses an offline, harmless PowerShell action. It does not install,
start or enroll a real CommandCore Agent; it does not contact any CommandCore
server or request FULL_CONTROL. The task and state live only in the test
account; no secrets or credentials are embedded.

Keep all included scripts together in the same `scripts/` directory,
including `windows_interactive_vm_logon_acceptance.ps1`,
`windows_interactive_logon_action.ps1`, `windows_interactive_vm_task_shape.ps1`,
`windows_interactive_vm_platform_validation.ps1`, and
`windows_interactive_vm_proof_validation.ps1`. Cleanup and verification are scoped to
the Scheduler root (`\\`), the authenticated Windows token's user identity,
the exact limited/interactive principal, one at-logon trigger, and the exact
PowerShell action arguments. They never rely on an inherited `USERNAME`
environment variable to authorize another user's task.

CI runs the separate, **non-mutating** `windows_interactive_vm_task_shape_probe.ps1`
negative matrix for tampered/foreign tasks. It also runs
`windows_interactive_vm_proof_probe.ps1` against the pure
`windows_interactive_vm_proof_validation.ps1` verifier. The latter tests
unexpected user/logon SIDs, mismatched nonces, administrator or Session 0
evidence, malformed/stale/future timestamps, failed Scheduler execution,
and reboot evidence, without logging any real identities. Keep both proof scripts and the platform-validation script plus
`windows_interactive_vm_platform_probe.ps1` alongside the harness.

**Evidence limitation:** task state and proof files belong to the disposable
local test user, so this is reproducible operator-run acceptance, **not**
tamper-proof remote attestation. Even a PASS on a real interactive VM proves
only the harmless action ran at logon; it does not prove actual CommandCore
Agent enrollment, authenticated reconnect, or a connected signed upgrade.
Neither this CI matrix nor the harness is permitted to contact production.

## Portable, offline acceptance bundle

To avoid requiring Git or Python inside a clean Windows evaluation VM, use
the GitHub Actions
[Windows M3 disposable VM acceptance bundle](../.github/workflows/windows-vm-acceptance-bundle.yml)
workflow. It publishes an artifact automatically **only when its workflow,
packager, offline harness or runbook changes are merged into `main`**; an
operator may also trigger `workflow_dispatch` manually for a reviewed `main`
commit. Check that the run completed successfully, was started from the
intended `main` SHA, and did not originate from an untrusted fork. Download
its `windows-m3-disposable-vm-acceptance` artifact within its 14-day retention
window, and copy the contained ZIP to the **isolated disposable VM only**. This archive has **only** source-controlled offline
PowerShell acceptance scripts, this runbook, `SOURCE_COMMIT.txt`, and
`SHA256SUMS.txt`. It contains **no Agent binary, production URL, installer,
credentials, enrollment keys, or user state**.

Before running scripts, verify the workflow's GitHub repository and commit
against `SOURCE_COMMIT.txt`, and inspect the bundle contents. File hashes
detect accidental changes **within the downloaded bundle**, not substitution
of both files by a malicious publisher. The entire artifact must come from
the trusted repository and its reviewed GitHub Actions run.

Windows 11 includes **Windows PowerShell 5.1** (`powershell.exe`). PowerShell 7
(`pwsh`) is *not* a prerequisite. The following commands use the built-in
PowerShell executable; `-ExecutionPolicy Bypass` applies to that process only
and does not change the system's execution policy.

As the disposable VM's non-administrator desktop user, extract the archive,
open Windows PowerShell in the extracted folder, and verify all file digests:

~~~powershell
Expand-Archive -LiteralPath .\windows-m3-vm-acceptance.zip -DestinationPath .\m3-vm -ErrorAction Stop
Set-Location .\m3-vm
foreach ($line in Get-Content -LiteralPath .\SHA256SUMS.txt) {
    if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9_./-]+)$') { throw 'Invalid manifest line' }
    $expected = $Matches[1]
    $filename = $Matches[2]
    if (!(Test-Path -LiteralPath $filename -PathType Leaf)) { throw 'Missing acceptance script' }
    if ((Get-FileHash -LiteralPath $filename -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) {
        throw 'Offline acceptance file checksum mismatch'
    }
}
'PASS: offline acceptance bundle file hashes match'
~~~

These checks do **not** prove a live logon or signed Agent connectivity.
They only ensure the operator has the reviewed offline acceptance scripts.

From the extracted bundle or checked-out source as the same standard user:

### 1. Prepare

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_interactive_vm_logon_acceptance.ps1 -Mode Prepare -ConfirmDisposableVM
~~~

Expected: PASS: limited interactive at-logon task prepared.
It creates an owned CommandCore CI Interactive Logon Acceptance task,
with an **Interactive**, **Limited** principal and an at-logon trigger.
An existing task/fixture is a failure; do not overwrite it.

### 2. Actual user login, then verify

**Sign out and sign back in** as the same VM test user, not
Start-Process -Credential or Start-ScheduledTask.
After the desktop appears:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_interactive_vm_logon_acceptance.ps1 -Mode Verify -ConfirmDisposableVM
~~~

The verifier requires a matching unique nonce, exact user SID, a **different
Windows logon SID from the Prepare token** that also matches the newly signed-in
user, non-admin process and non-zero GUI session, a proof created after
registration, and successful Task Scheduler last execution. Manually starting
the task in the original session therefore cannot pass the logon identity gate.
This verifies that a harmless task executed after a real new login; it does not
test real Agent startup or eliminate the need to follow the no-manual-start rule.

### 3. Optional reboot path

For a *fresh* Prepare cycle, reboot the disposable VM, sign in as the same
test user and run:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_interactive_vm_logon_acceptance.ps1 -Mode Verify -ConfirmDisposableVM -RequireReboot
~~~

This also verifies the OS boot timestamp advanced after registration.
Never reboot a personal machine for this acceptance. An existing proof from
an earlier login is not a substitute for an independent reboot cycle.

### 4. Cleanup (always)

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_interactive_vm_logon_acceptance.ps1 -Mode Cleanup -ConfirmDisposableVM
~~~

Cleanup refuses unrelated tasks and other user identities; it deletes only
the task bearing the known description and the current test user's isolated
fixture. If a test fails, inspect locally and perform Cleanup in the VM.
Destroy the entire test VM after acceptance and retain only redacted PASS/FAIL
evidence; do not upload SIDs, task XML, paths, environment dumps or test account
details.

## Interpret results strictly

| Gate | PASS proves | Still missing |
| --- | --- | --- |
| Windows CI registration | Non-admin can register an Interactive, Limited task | Real login and startup |
| Interactive VM Prepare/Verify | Harmless limited task launched after real login, matching identity | Real CommandCore Agent startup |
| Interactive VM RequireReboot | A later OS boot and the same limited task's proof | Agent reconnect, upgrade, rollback, uninstall |
| Future native Agent acceptance | Actual signed installer and disposable local control plane | Separate production release approval |

This is a reproducible **manual VM acceptance** harness, not a self-executing CI
claim. CI runs only negative safety checks: code parses; the harness refuses
every mode on GitHub-hosted Windows workers without making a task.
