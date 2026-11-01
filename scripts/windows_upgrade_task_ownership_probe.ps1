# CI-only negative ownership matrix on an isolated, disposable non-admin
# Windows profile. All Task Scheduler APIs are scoped test doubles.
# Never register, stop or replace a real Scheduled Task.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $Origin -notmatch '^https://localhost:[0-9]{2,5}$') {
    throw 'Disposable localhost Windows CI fixture required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.Name.Split('\')[-1] -notmatch '^cc[a-f0-9]{10}$') {
    throw 'Disposable standard-user token required.'
}
$root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
$stateRoot = Join-Path $env:LOCALAPPDATA 'CommandCore\State'
$statePath = Join-Path $stateRoot 'agent.json'
$active = Join-Path $root 'active.json'
$marker = Join-Path $root '.commandcore-install'
$launcher = Join-Path $root 'run-agent.ps1'
if (!(Test-Path -LiteralPath $active -PathType Leaf) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $launcher -PathType Leaf) -or
    (Test-Path -LiteralPath $statePath)) {
    throw 'Expected disposable no-enrollment installation fixture.'
}
$config = Get-Content -LiteralPath $active -Raw | ConvertFrom-Json
$manifest = Join-Path (Split-Path -Parent $config.binary) 'manifest.json'
$paths = @($active, $marker, $launcher, $config.binary, $manifest)
$before = @{}
foreach ($path in $paths) {
    $before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
$releaseCount = @(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count
$global:CommandCoreCiOwnerProbe = @{
    mode = 'none'
    looked_up = $false
    exported = $false
    mutated = $false
}
$ciUser = $identity.Name
# Test doubles are only visible to this local PowerShell test process.
function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiOwnerProbe.looked_up = $true
    if ($global:CommandCoreCiOwnerProbe.mode -eq 'missing_task') { return $null }
    $task = [pscustomobject]@{
        Description = 'Managed by CommandCore user installer'
        Principal = [pscustomobject]@{
            UserId = $ciUser
            LogonType = 'Interactive'
            RunLevel = 'Limited'
        }
        Triggers = @([pscustomobject]@{
            UserId = $ciUser
            CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' }
        })
        Actions = @([pscustomobject]@{
            Execute = 'powershell.exe'
            Arguments = ('-NoProfile -NonInteractive -File "' + $launcher + '"')
        })
    }
    switch ($global:CommandCoreCiOwnerProbe.mode) {
        'foreign_description' { $task.Description = 'Unrelated existing task' }
        'foreign_owner' { $task.Principal.UserId = 'S-1-5-32-544' }
        'elevated_principal' { $task.Principal.RunLevel = 'Highest' }
        'password_logon' { $task.Principal.LogonType = 'Password' }
        'foreign_trigger' { $task.Triggers[0].UserId = 'S-1-5-32-544' }
        'foreign_action' { $task.Actions[0].Arguments = '-NoProfile -File "C:\unrelated.ps1"' }
    }
    return $task
}
function Export-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiOwnerProbe.exported = $true
    throw 'A rejected task must never reach task export.'
}
function Stop-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiOwnerProbe.mutated = $true
    throw 'A rejected task must never be stopped.'
}
function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiOwnerProbe.mutated = $true
    throw 'A rejected task must never be registered.'
}
$scenarios = @(
    @{ mode = 'missing_task'; expected = 'Upgrade requires an existing managed interactive logon task.' },
    @{ mode = 'foreign_description'; expected = 'Refusing an unrelated scheduled task.' },
    @{ mode = 'foreign_owner'; expected = 'Refusing to upgrade an unowned or unexpected scheduled task.' },
    @{ mode = 'elevated_principal'; expected = 'Refusing to upgrade an unowned or unexpected scheduled task.' },
    @{ mode = 'password_logon'; expected = 'Refusing to upgrade an unowned or unexpected scheduled task.' },
    @{ mode = 'foreign_trigger'; expected = 'Refusing to upgrade an unowned or unexpected scheduled task.' },
    @{ mode = 'foreign_action'; expected = 'Refusing to upgrade an unowned or unexpected scheduled task.' }
)
try {
    Set-Content -LiteralPath $statePath -Value '{"ci_fixture":true}' -NoNewline -ErrorAction Stop
    foreach ($case in $scenarios) {
        $global:CommandCoreCiOwnerProbe.mode = $case.mode
        $global:CommandCoreCiOwnerProbe.looked_up = $false
        $global:CommandCoreCiOwnerProbe.exported = $false
        $global:CommandCoreCiOwnerProbe.mutated = $false
        $denied = $false
        try {
            & $Installer -Server $Origin -NoEnroll -Upgrade | Out-Null
        } catch {
            $denied = ([string]$_.Exception.Message -ceq [string]$case.expected)
        }
        if (!$denied -or !$global:CommandCoreCiOwnerProbe.looked_up -or
            $global:CommandCoreCiOwnerProbe.exported -or
            $global:CommandCoreCiOwnerProbe.mutated) {
            throw 'Unsafe Windows task-ownership preflight outcome.'
        }
        foreach ($path in $paths) {
            if (!(Test-Path -LiteralPath $path -PathType Leaf) -or
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $before[$path]) {
                throw 'Rejected Windows task changed an installed file.'
            }
        }
        if (@(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count -ne $releaseCount -or
            (Test-Path -LiteralPath (Join-Path $root 'active.new.json')) -or
            !(Test-Path -LiteralPath $statePath -PathType Leaf)) {
            throw 'Rejected Windows task changed activation or identity state.'
        }
    }
    @{status = 'PASS'; scenarios = $scenarios.Count; task_ownership_denied = $true; unchanged = $true} |
        ConvertTo-Json -Compress
} finally {
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Remove-Variable -Scope Global -Name CommandCoreCiOwnerProbe -ErrorAction SilentlyContinue
}
