# Optional, offline, disposable interactive Windows VM acceptance harness.
# Modes: Prepare -> human sign-out/sign-in (or reboot) -> Verify -> Cleanup.
# It never installs/enrolls an Agent or touches CommandCore production devices.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify','Cleanup')][string]$Mode,
    [switch]$ConfirmDisposableVM,
    [switch]$RequireReboot
)
$ErrorActionPreference = 'Stop'
$taskName = 'CommandCore CI Interactive Logon Acceptance'
$description = 'CommandCore disposable VM interactive logon proof only'
$root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CommandCore-VM-Acceptance\WindowsLogon'
$statePath = Join-Path $root 'state.json'
$proofPath = Join-Path $root 'proof.json'
$actionPath = Join-Path $root 'task-action.ps1'

function Deny([string]$code) {
    Write-Output ('BLOCKED: ' + $code)
    exit 2
}
function Get-OwnedTask {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (!$task) { return $null }
    if ($task.Description -ne $description) { Deny 'unrelated_task_name' }
    if ([string]$task.Principal.UserId -notin @($identity.Name, $identity.User.Value, $env:USERNAME, ($env:COMPUTERNAME + '\' + $env:USERNAME), ('.\' + $env:USERNAME))) {
        Deny 'task_principal_mismatch'
    }
    if ([string]$task.Principal.LogonType -ne 'Interactive' -or [string]$task.Principal.RunLevel -ne 'Limited') {
        Deny 'unsafe_task_principal'
    }
    return $task
}

# CI cannot supply the interactive logon requirement; fail before all mutations.
if ($env:CI -eq 'true' -or $env:GITHUB_ACTIONS -eq 'true') { Deny 'not_interactive_ci' }
if (!$ConfirmDisposableVM.IsPresent) { Deny 'explicit_disposable_vm_consent_required' }
if ($env:OS -ne 'Windows_NT') { Deny 'windows_only' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Deny 'must_use_standard_user' }
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($sessionId -le 0 -or ![Environment]::UserInteractive) { Deny 'interactive_desktop_required' }
$logonSids = @($identity.Groups | ForEach-Object { $_.Value } | Where-Object { $_ -match '^S-1-5-5-\d+-\d+$' })
if ($logonSids.Count -ne 1) { Deny 'unique_logon_identity_unavailable' }
$currentLogonSid = [string]$logonSids[0]

# Require a virtualized environment as an additional safeguard against running
# this task fixture on the maintainer's own PC. These are not production hosts.
$system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$model = [string]$system.Model + ' ' + [string]$system.Manufacturer
if ($model -notmatch '(?i)virtual.machine|vmware|virtualbox|qemu|kvm|parallels|hyper-v|virtual.platform|bochs|hvm domu') {
    Deny 'virtual_machine_not_detected'
}
Import-Module ScheduledTasks -ErrorAction Stop

if ($Mode -eq 'Prepare') {
    if (Test-Path -LiteralPath $root) { Deny 'fixture_already_exists' }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { Deny 'task_already_exists' }
    $source = Join-Path $PSScriptRoot 'windows_interactive_logon_action.ps1'
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { Deny 'missing_action_source' }
    $createdTask = $false
    try {
        New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $source -Destination $actionPath -ErrorAction Stop
        $now = [DateTimeOffset]::UtcNow.ToString('o')
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        $state = @{
            schema = 1
            nonce = [guid]::NewGuid().ToString('N')
            user_sid = [string]$identity.User.Value
            logon_sid = $currentLogonSid
            prepared_utc = $now
            boot_utc = $boot
        }
        $state | ConvertTo-Json -Compress | Set-Content -LiteralPath $statePath -Encoding UTF8
        $arg = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $actionPath + '" -FixtureRoot "' + $root + '"'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2))
        Register-ScheduledTask -TaskName $taskName -Description $description -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -ErrorAction Stop | Out-Null
        $createdTask = $true
        $saved = Get-OwnedTask
        if (!$saved -or $saved.Triggers.Count -ne 1 -or $saved.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger') {
            throw 'task_shape_rejected'
        }
        Write-Output 'PASS: limited interactive at-logon task prepared in a disposable VM'
        Write-Output 'NEXT: sign out and sign in as the SAME disposable user, then run Verify'
        Write-Output 'ALTERNATIVE: reboot and run Verify -RequireReboot'
        Write-Output 'DO NOT manually start the task; that does not prove at-logon startup'
    } catch {
        if ($createdTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        throw 'Disposable VM preparation failed; owned fixtures were cleaned up'
    }
    exit 0
}

if (!(Test-Path -LiteralPath $statePath -PathType Leaf)) { Deny 'no_owned_fixture' }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.schema -ne 1 -or [string]$state.user_sid -ne [string]$identity.User.Value -or [string]$state.nonce -notmatch '^[a-f0-9]{32}$' -or [string]$state.logon_sid -notmatch '^S-1-5-5-\d+-\d+$') {
    Deny 'fixture_identity_invalid'
}
$task = Get-OwnedTask
if (!$task) { Deny 'owned_task_missing' }
if ($task.Triggers.Count -ne 1 -or $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger') {
    Deny 'not_a_logon_task'
}
if ($Mode -eq 'Cleanup') {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    Write-Output 'PASS: only owned disposable task and fixture removed'
    exit 0
}

if (!(Test-Path -LiteralPath $proofPath -PathType Leaf)) { Deny 'logon_action_not_observed' }
$proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
if ($proof.schema -ne 1 -or $proof.nonce -cne $state.nonce -or $proof.user_sid -ne $state.user_sid -or
    $proof.non_admin -ne $true -or [int]$proof.session_id -le 0 -or
    [string]$proof.logon_sid -ne $currentLogonSid -or [string]$proof.logon_sid -eq [string]$state.logon_sid) { Deny 'proof_invalid' }
$prepared = [DateTimeOffset]::Parse([string]$state.prepared_utc)
$started = [DateTimeOffset]::Parse([string]$proof.started_utc)
if ($started -le $prepared.AddSeconds(2) -or $started -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) {
    Deny 'proof_timestamp_invalid'
}
$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
if ($taskInfo.LastTaskResult -ne 0 -or [DateTimeOffset]$taskInfo.LastRunTime -le $prepared) {
    Deny 'scheduler_task_execution_unconfirmed'
}
$bootNow = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
if ($RequireReboot -and $bootNow -le [DateTimeOffset]::Parse([string]$state.boot_utc).UtcDateTime) {
    Deny 'reboot_not_observed'
}
Write-Output 'PASS: disposable interactive Windows logon task executed as intended non-admin user'
if ($RequireReboot) { Write-Output 'PASS: OS reboot observed after task preparation' }
Write-Output 'NOT_TESTED: actual CommandCore Agent enrollment, reconnect, upgrade, rollback'
Write-Output 'NEXT: run Cleanup to remove the owned fixture'
