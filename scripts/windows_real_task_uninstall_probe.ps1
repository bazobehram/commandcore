# Disposable Windows CI: real Task Scheduler registration and real uninstaller.
# Does NOT log on, reboot, start the task, or enroll/connect an Agent.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$Uninstaller,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:OS -ne 'Windows_NT' -or
    $Origin -notmatch '^https://localhost:[0-9]{2,5}$') {
    throw 'Disposable Windows CI and localhost HTTPS required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$user = $identity.Name.Substring($identity.Name.LastIndexOf('\') + 1)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $user -notmatch '^cc[a-f0-9]{10}$') {
    throw 'Disposable non-administrator Windows account required.'
}
$name = 'CommandCore Agent'
$description = 'Managed by CommandCore user installer'
$root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
$state = Join-Path $env:LOCALAPPDATA 'CommandCore\State\agent.json'
$launcher = Join-Path $root 'run-agent.ps1'
$marker = Join-Path $root '.commandcore-install'
$sentinel = '{"ci_disposable_identity":true}'
$allowed = @($identity.Name, $identity.User.Value, $user,
    ($env:COMPUTERNAME + '\' + $user), ('.\' + $user))
if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $state) -or
    (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) {
    throw 'Unexpected pre-existing Agent, identity, or Scheduled Task.'
}
$installStarted = $false
$registerAttempted = $false
$phase = 'preconditions'
function Test-OwnedFixtureTask($task) {
    if (!$task) { return $false }
    $triggers = @($task.Triggers)
    $actions = @($task.Actions)
    return (
        $task.Description -eq $description -and
        [string]$task.Principal.UserId -in $allowed -and
        [string]$task.Principal.LogonType -eq 'Interactive' -and
        [string]$task.Principal.RunLevel -eq 'Limited' -and
        $triggers.Count -eq 1 -and
        $triggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and
        [string]$triggers[0].UserId -in $allowed -and
        $actions.Count -eq 1 -and
        [string]$actions[0].Execute -match '(?i)(^|\\)powershell\.exe$' -and
        ([string]$actions[0].Arguments).Contains('"' + $launcher + '"')
    )
}
try {
    # Module load must also be covered by bounded CI phase diagnostics.
    Import-Module ScheduledTasks -ErrorAction Stop
    $phase = 'signed_reinstall'
    $installStarted = $true
    & $Installer -Server $Origin -NoEnroll -NoTask | Out-Null
    if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
        (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'commandcore-agent') {
        throw 'Signed install marker missing.'
    }
    # Harmless non-executable fixture; the task is never started.
    Set-Content -LiteralPath $launcher -Value '# disposable CI launcher' -NoNewline
    Set-Content -LiteralPath $state -Value $sentinel -NoNewline
    $stateHash = (Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $launcher + '"'
    )
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    $phase = 'task_register'
    $registerAttempted = $true
    Register-ScheduledTask -TaskName $name -Description $description -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -ErrorAction Stop | Out-Null
    $phase = 'task_verify'
    $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
    if (!(Test-OwnedFixtureTask $task) -or [string]$task.State -eq 'Running') {
        throw 'Unexpected disposable Scheduled Task ownership or state.'
    }
    # The real product uninstaller must unregister this Ready task, not start it.
    $phase = 'uninstall'
    & $Uninstaller | Out-Null
    $phase = 'verify_cleanup'
    if ((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $root) -or
        !(Test-Path -LiteralPath $state -PathType Leaf) -or
        (Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash -cne $stateHash) {
        throw 'Real Scheduled Task uninstall or identity preservation failed.'
    }
    @{status='PASS'; real_task_registered=$true; real_task_removed=$true;
      signed_files_removed=$true; disposable_identity_preserved=$true;
      gui_logon_tested=$false} | ConvertTo-Json -Compress
} catch {
    # The worker publishes only this allowlisted phase; never print a raw
    # PowerShell exception, local path, test credential, or release details.
    throw ('CI_REAL_TASK_PHASE_' + $phase)
} finally {
    # On failure, clean only the exact fixture we just attempted to register.
    if ($registerAttempted) {
        $left = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($left) {
            if (!(Test-OwnedFixtureTask $left)) {
                throw 'Refusing unsafe test task cleanup; manual disposable runner teardown required.'
            }
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
        }
    }
    if ($installStarted -and
        (Test-Path -LiteralPath $marker -PathType Leaf) -and
        (Get-Content -LiteralPath $marker -Raw).Trim() -eq 'commandcore-agent') {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $state -PathType Leaf) {
        if ((Get-Content -LiteralPath $state -Raw) -ceq $sentinel) {
            Remove-Item -LiteralPath $state -Force -ErrorAction Stop
        }
    }
}
