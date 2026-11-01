# CI-only Windows logon-task registration; never runs a task or enrolls a device.
# A credential-launched standard user must be able to register its own task.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'result\worker.result.json'
$taskName = $null
$created = $false
$stage = 'identity'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Expected standard-user token.'
    }
    $stage = 'task_modules'
    Import-Module ScheduledTasks -ErrorAction Stop
    $accountName = $identity.Name
    $shortName = $accountName.Substring($accountName.LastIndexOf('\') + 1)
    if ($shortName -notmatch '^cc[a-f0-9]{10}$') { throw 'Not a disposable CI user.' }
    $taskName = 'CommandCore CI Install ' + $shortName
    $description = 'Disposable CommandCore CI logon task probe'
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'Refusing a pre-existing task.'
    }
    # This is the real at-logon task configuration used by the user installer,
    # not an elevated task, password-bearing batch task or one-time trigger.
    $probe = Join-Path $FixtureRoot 'installers\task-action.ps1'
    if (!(Test-Path -LiteralPath $probe -PathType Leaf)) { throw 'Missing disposable task action.' }
    $taskArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $probe + '" -FixtureRoot "' + $FixtureRoot + '"'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $accountName
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $accountName -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    $stage = 'task_register'
    Register-ScheduledTask -TaskName $taskName -Description $description -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -ErrorAction Stop | Out-Null
    $created = $true
    $stage = 'task_verify'
    $saved = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($saved.Description -ne $description -or
        [string]$saved.Principal.LogonType -ne 'Interactive' -or
        [string]$saved.Principal.RunLevel -ne 'Limited' -or
        $saved.Triggers.Count -ne 1 -or
        $saved.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger') {
        throw 'Registered task is not a limited interactive logon task.'
    }
    $stage = 'task_identity'
    # A disposable local account can be rendered as SID, HOST\user,
    # .\user, or short local user. Avoid slow network account translation.
    $allowedIdentities = @(
        [string]$identity.User.Value,
        [string]$identity.Name,
        [string]($env:COMPUTERNAME + '\' + $shortName),
        [string]('.\' + $shortName),
        [string]$shortName
    )
    $principalMatch = $allowedIdentities -icontains [string]$saved.Principal.UserId
    $triggerMatch = $allowedIdentities -icontains [string]$saved.Triggers[0].UserId
    if (!$principalMatch -or !$triggerMatch) {
        if (!$principalMatch -and !$triggerMatch) { $identityPart = 'both' }
        elseif (!$principalMatch) { $identityPart = 'principal' }
        else { $identityPart = 'trigger' }
        throw 'Task user identity differs from the standard user.'
    }
    # A manual Start-ScheduledTask probe is separate from at-logon/reboot acceptance.
    # Task Scheduler must execute the harmless action using the disposable user.
    $stage = 'task_launch'
    $taskMarker = Join-Path $FixtureRoot 'result\task-executed.marker'
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline -and !(Test-Path -LiteralPath $taskMarker -PathType Leaf)) {
        Start-Sleep -Milliseconds 250
    }
    if (!(Test-Path -LiteralPath $taskMarker -PathType Leaf)) { throw 'Disposable task action did not execute.' }
    if ((Get-Content -LiteralPath $taskMarker -Raw).Trim() -ne 'commandcore-ci-disposable-task-executed') {
        throw 'Unexpected disposable task result.'
    }
    $stage = 'task_launch_verify'
    # Do not claim interactive logon or reboot, which require separate acceptance.
    # Defer PASS until the owned task has been removed successfully.
 } catch {
    $hint = 'other'
    $errorName = [string]$_.FullyQualifiedErrorId
    $message = [string]$_.Exception.Message
    if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { $hint = 'missing_command' }
    elseif ($message -match '(?i)access.denied|permission|unauthorized') { $hint = 'access_denied' }
    elseif ($message -match '(?i)logon|logon.type|account') { $hint = 'logon_policy' }
    elseif ($message -match '(?i)registered.task|limited interactive|user identity') { $hint = 'task_shape' }
    elseif ($message -match '(?i)task action|task result|task execute') { $hint = 'task_launch' }
    elseif ($errorName -match '(?i)parameter|argument') { $hint = 'invalid_argument' }
    @{status='FAIL'; non_admin=$false; task_probe=$false; stage=$stage; hint=$hint; identity_part=$identityPart} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
} finally {
    if ($created -and $taskName) {
        try {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        } catch {
            # Runner-side driver will clean an owned fixture before user deletion.
            exit 1
        }
    }
}

@{status='PASS'; non_admin=$true; task_probe=$true; task_launch=$true} |
    ConvertTo-Json -Compress |
    Set-Content -LiteralPath $report -Encoding UTF8
