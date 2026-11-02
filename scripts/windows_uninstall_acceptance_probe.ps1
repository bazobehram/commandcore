# CI-only negative Windows uninstaller ownership and real filesystem cleanup.
# Task Scheduler cmdlets are mocked in-process; no real user task is touched.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Uninstaller)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:OS -ne 'Windows_NT') {
    throw 'Disposable Windows CI runner required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.Name.Split('\')[-1] -notmatch '^cc[a-f0-9]{10}$') {
    throw 'Disposable standard-user test account required.'
}
$root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
$stateDir = Join-Path $env:LOCALAPPDATA 'CommandCore\State'
$statePath = Join-Path $stateDir 'agent.json'
$active = Join-Path $root 'active.json'
$marker = Join-Path $root '.commandcore-install'
$launcher = Join-Path $root 'run-agent.ps1'
if (!(Test-Path -LiteralPath $root -PathType Container) -or
    !(Test-Path -LiteralPath $active -PathType Leaf) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Test-Path -LiteralPath $statePath)) {
    throw 'No disposable, un-enrolled signed installation fixture.'
}
$config = Get-Content -LiteralPath $active -Raw | ConvertFrom-Json
$files = @($active, $marker, $config.binary, (Join-Path (Split-Path -Parent $config.binary) 'manifest.json'), $launcher)
$before = @{}
foreach ($file in $files) {
    $before[$file] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
}
$releaseCount = @(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count
# This file is NOT a valid enrollment secret. It tests that uninstall does not
# silently revoke/delete identity data before explicit user revocation.
$stateFixture = '{"ci_disposable_uninstall_state":true}'
Set-Content -LiteralPath $statePath -Value $stateFixture -NoNewline -ErrorAction Stop
$stateHash = (Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
$global:CommandCoreCiUninstall = @{
    case = 'none'
    task_checked = $false
    stopped = $false
    unregistered = $false
}
$user = $identity.Name
function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiUninstall.task_checked = $true
    $task = [pscustomobject]@{
        State = 'Running'
        Description = 'Managed by CommandCore user installer'
        Principal = [pscustomobject]@{
            UserId = $user
            LogonType = 'Interactive'
            RunLevel = 'Limited'
        }
        Triggers = @([pscustomobject]@{
            UserId = $user
            CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' }
        })
        Actions = @([pscustomobject]@{
            Execute = 'powershell.exe'
            Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $launcher + '"')
        })
    }
    switch ($global:CommandCoreCiUninstall.case) {
        'foreign_description' { $task.Description = 'Unrelated task' }
        'foreign_owner' { $task.Principal.UserId = 'S-1-5-32-544' }
        'elevated_principal' { $task.Principal.RunLevel = 'Highest' }
        'password_logon' { $task.Principal.LogonType = 'Password' }
        'foreign_trigger' { $task.Triggers[0].UserId = 'S-1-5-32-544' }
        'foreign_action' { $task.Actions[0].Arguments = '-NoProfile -File "C:\unrelated.ps1"' }
        'multiple_actions' {
            $task.Actions = @($task.Actions[0], [pscustomobject]@{
                Execute = 'powershell.exe'
                Arguments = '-NoProfile -File "C:\unrelated.ps1"'
            })
        }
    }
    return $task
}
function Stop-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiUninstall.stopped = $true
}
function Unregister-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName,[switch]$Confirm)
    $global:CommandCoreCiUninstall.unregistered = $true
}
$cases = @(
    'foreign_description', 'foreign_owner', 'elevated_principal',
    'password_logon', 'foreign_trigger', 'foreign_action',
    'multiple_actions'
)
try {
    foreach ($case in $cases) {
        $global:CommandCoreCiUninstall.case = $case
        $global:CommandCoreCiUninstall.task_checked = $false
        $global:CommandCoreCiUninstall.stopped = $false
        $global:CommandCoreCiUninstall.unregistered = $false
        $denied = $false
        try {
            & $Uninstaller | Out-Null
        } catch {
            $denied = [string]$_.Exception.Message -ceq 'Refusing an unowned or unexpected scheduled task.'
        }
        if (!$denied -or !$global:CommandCoreCiUninstall.task_checked -or
            $global:CommandCoreCiUninstall.stopped -or $global:CommandCoreCiUninstall.unregistered) {
            throw 'Unowned Windows uninstall task was not rejected before mutation.'
        }
        foreach ($file in $files) {
            if (!(Test-Path -LiteralPath $file -PathType Leaf) -or
                (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne $before[$file]) {
                throw 'Rejected Windows uninstall modified protected Agent files.'
            }
        }
        if (@(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count -ne $releaseCount -or
            (Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash -cne $stateHash) {
            throw 'Rejected Windows uninstall modified release or state.'
        }
    }
    # Positive fixture: a matching limited task is "stopped" and "removed"
    # by scoped test doubles; the real signed installation files are deleted.
    $global:CommandCoreCiUninstall.case = 'owned'
    $global:CommandCoreCiUninstall.task_checked = $false
    $global:CommandCoreCiUninstall.stopped = $false
    $global:CommandCoreCiUninstall.unregistered = $false
    & $Uninstaller | Out-Null
    if (!$global:CommandCoreCiUninstall.task_checked -or
        !$global:CommandCoreCiUninstall.stopped -or
        !$global:CommandCoreCiUninstall.unregistered -or
        (Test-Path -LiteralPath $root) -or
        !(Test-Path -LiteralPath $statePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash -cne $stateHash) {
        throw 'Managed Windows uninstall did not clean files and preserve identity.'
    }
    @{status='PASS'; rejected_cases=$cases.Count; installed_files_removed=$true; identity_preserved=$true;
        managed_task_cleanup_simulated=$true} | ConvertTo-Json -Compress
} finally {
    # The fabricated state must never survive the disposable fixture.
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Remove-Variable -Scope Global -Name CommandCoreCiUninstall -ErrorAction SilentlyContinue
}
