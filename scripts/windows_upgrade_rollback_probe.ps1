# CI-only transaction test: signed upgrade with a simulated Scheduled Task
# registration failure, on the disposable standard-user installer profile.
# Native signature and filesystem operations are real; Task Scheduler is mocked.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $Origin -notmatch '^https://localhost:[0-9]{2,5}$') {
    throw 'Disposable local CI Windows fixture required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.Name.Split('\')[-1] -notmatch '^cc[a-f0-9]{10}$') {
    throw 'Disposable Windows account required.'
}
$root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
$stateRoot = Join-Path $env:LOCALAPPDATA 'CommandCore\State'
$statePath = Join-Path $stateRoot 'agent.json'
$active = Join-Path $root 'active.json'
if (!(Test-Path -LiteralPath $active -PathType Leaf) -or
    (Test-Path -LiteralPath $statePath)) {
    throw 'Expected no-enrollment signed installation fixture.'
}
$previousHash = (Get-FileHash -LiteralPath $active -Algorithm SHA256).Hash
$previous = Get-Content -LiteralPath $active -Raw | ConvertFrom-Json
$oldRelease = Join-Path $root ('releases\' + $previous.version)
$oldBinaryHash = (Get-FileHash -LiteralPath $previous.binary -Algorithm SHA256).Hash
$oldManifestHash = (Get-FileHash -LiteralPath (Join-Path $oldRelease 'manifest.json') -Algorithm SHA256).Hash
$launcher = Join-Path $root 'run-agent.ps1'
# Fresh CI install uses -NoTask; create an isolated, distinct prior launcher
# to prove the upgrade restores its original bytes, not only the task XML.
Set-Content -LiteralPath $launcher -Value '# disposable prior launcher bytes' -NoNewline -ErrorAction Stop
$priorLauncherHash = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash
$oldXml = '<Task xmlns="urn:commandcore:ci" version="1"/>'
$script:taskWasStopped = $false
$script:taskRestoreObserved = $false
$script:taskRestarted = $false
$script:injectedMutation = $false
# Mock task APIs in this child script only, never in the system. This checks
# installer transaction logic, NOT real Task Scheduler logon or execution.
function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    return [pscustomobject]@{
        Description = 'Managed by CommandCore user installer'
        Principal = [pscustomobject]@{ UserId = $identity.Name; LogonType = 'Interactive'; RunLevel = 'Limited' }
        Triggers = @([pscustomobject]@{
            UserId = $identity.Name
            CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' }
        })
        Actions = @([pscustomobject]@{
            Execute = 'powershell.exe'
            Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $launcher + '"')
        })
    }
}
function Export-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    return $oldXml
}
function Stop-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $script:taskWasStopped = $true
}
function Start-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $script:taskRestarted = $true
}
function New-ScheduledTaskAction { param([string]$Execute,[string]$Argument) return [pscustomobject]@{ Execute=$Execute; Arguments=$Argument } }
function New-ScheduledTaskTrigger { param([switch]$AtLogOn,[string]$User) return [pscustomobject]@{UserId=$User} }
function New-ScheduledTaskPrincipal { param([string]$UserId,[string]$LogonType,[string]$RunLevel) return [pscustomobject]@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel} }
function New-ScheduledTaskSettingsSet { param($ExecutionTimeLimit,[int]$RestartCount,$RestartInterval) return [pscustomobject]@{} }
function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName,[string]$Description,$Action,$Trigger,$Principal,$Settings,[switch]$Force,[string]$Xml)
    if ($PSBoundParameters.ContainsKey('Xml')) {
        if ($Xml -cne $oldXml) { throw 'Unexpected task restoration snapshot.' }
        $script:taskRestoreObserved = $true
        return
    }
    $script:injectedMutation = $true
    throw 'CI injected task registration failure after attempted mutation'
}
$injectedFailure = $false
try {
    # A harmless fake identity file permits preflight but is never an
    # enrolled device credential, token, or actual authentication fixture.
    Set-Content -LiteralPath $statePath -Value '{"ci_fixture":true}' -NoNewline -ErrorAction Stop
    try {
        & $Installer -Server $Origin -ManifestUrl ($Origin + '/releases/agent/manifest-upgrade.json') -NoEnroll -Upgrade | Out-Null
    } catch {
        $injectedFailure = [string]$_.Exception.Message -eq 'CI injected task registration failure after attempted mutation'
    }
    if (!$injectedFailure -or !$script:injectedMutation -or !$script:taskWasStopped -or
        !$script:taskRestoreObserved -or !$script:taskRestarted) {
        throw 'Signed upgrade did not execute expected fail-and-restore transition.'
    }
    if ((Get-FileHash -LiteralPath $active -Algorithm SHA256).Hash -cne $previousHash -or
        (Get-FileHash -LiteralPath $previous.binary -Algorithm SHA256).Hash -cne $oldBinaryHash -or
        (Get-FileHash -LiteralPath (Join-Path $oldRelease 'manifest.json') -Algorithm SHA256).Hash -cne $oldManifestHash -or
        (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash -cne $priorLauncherHash -or
        (Test-Path -LiteralPath (Join-Path $root 'releases\0.9.0-rc2')) -or
        (Test-Path -LiteralPath (Join-Path $root 'active.new.json'))) {
        throw 'Failed signed upgrade did not preserve the old activated release.'
    }
    @{task_restored=$true; activation_unchanged=$true; failed_release_removed=$true; old_task_restarted=$true} |
        ConvertTo-Json -Compress
} finally {
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
}
