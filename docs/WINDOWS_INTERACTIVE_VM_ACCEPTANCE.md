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
local **non-administrator** test account signed into its desktop. This
harness detects common hypervisors, rejects GitHub CI and Session 0, refuses
administrator tokens and pre-existing tasks, and requires explicit consent.
Do not execute it on a personal Windows PC or a production Windows host.

The harness uses an offline, harmless PowerShell action. It does not install,
start or enroll a real CommandCore Agent; it does not contact any CommandCore
server or request FULL_CONTROL. The task and state live only in the test
account; no secrets or credentials are embedded.

From the checked-out source as the same standard user:

### 1. Prepare

~~~powershell
pwsh -NoProfile -File ./scripts/windows_interactive_vm_logon_acceptance.ps1 -Mode Prepare -ConfirmDisposableVM
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
pwsh -NoProfile -File ./scripts/windows_interactive_vm_logon_acceptance.ps1 -Mode Verify -ConfirmDisposableVM
~~~

The verifier requires a matching unique nonce, exact user SID, non-admin
process and non-zero GUI session, a proof created after registration, and a
successful Task Scheduler last execution. This verifies that a harmless
task **executed after the actual login**; it does not test real Agent startup.

### 3. Optional reboot path

For a *fresh* Prepare cycle, reboot the disposable VM, sign in as the same
test user and run:

~~~powershell
pwsh -NoProfile -File ./scripts/windows_interactive_vm_logon_acceptance.ps1 -Mode Verify -ConfirmDisposableVM -RequireReboot
~~~

This also verifies the OS boot timestamp advanced after registration.
Never reboot a personal machine for this acceptance. An existing proof from
an earlier login is not a substitute for an independent reboot cycle.

### 4. Cleanup (always)

~~~powershell
pwsh -NoProfile -File ./scripts/windows_interactive_vm_logon_acceptance.ps1 -Mode Cleanup -ConfirmDisposableVM
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
