# CI-only signed Windows upgrade positive transaction acceptance.
# Installer, Ed25519 verification, ACLs and filesystem are real. Task Scheduler
# and connected Agent health are isolated test doubles: NO interactive login.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $Origin -notmatch '^https://localhost:[0-9]{2,5}$') {
    throw 'Disposable local Windows CI release fixture required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.Name.Split('\')[-1] -notmatch '^cc[a-f0-9]{10}$') {
    throw 'Disposable non-admin test identity required.'
}
$root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
$stateRoot = Join-Path $env:LOCALAPPDATA 'CommandCore\State'
$statePath = Join-Path $stateRoot 'agent.json'
$healthPath = Join-Path $stateRoot 'health.json'
$active = Join-Path $root 'active.json'
$marker = Join-Path $root '.commandcore-install'
$launcher = Join-Path $root 'run-agent.ps1'
if (!(Test-Path -LiteralPath $active -PathType Leaf) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $launcher -PathType Leaf) -or
    (Test-Path -LiteralPath $statePath) -or
    (Test-Path -LiteralPath $healthPath)) {
    throw 'Expected clean disposable no-enroll signed install.'
}
$old = Get-Content -LiteralPath $active -Raw | ConvertFrom-Json
if ($old.version -ne '0.9.0-rc1') { throw 'Expected old signed release.' }
$oldBinary = $old.binary
$oldManifest = Join-Path (Split-Path -Parent $oldBinary) 'manifest.json'
$originalHashes = @{}
foreach ($path in @($oldBinary, $oldManifest, $marker)) {
    $originalHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
$global:CommandCoreCiWindowsUpgrade = @{
    lookup=$false
    exported=$false
    stopped=$false
    registered=$false
    started=$false
    synthetic_health=$false
    task_xml_backout=$false
}
$taskXml = '<Task xmlns="urn:commandcore:ci" version="1"/>'
# Only scoped mock functions: never modify actual Task Scheduler state.
function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiWindowsUpgrade.lookup=$true
    return [pscustomobject]@{
        Description = 'Managed by CommandCore user installer'
        Principal = [pscustomobject]@{
            UserId=$identity.Name
            LogonType='Interactive'
            RunLevel='Limited'
        }
        Triggers = @([pscustomobject]@{
            UserId=$identity.Name
            CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'}
        })
        Actions = @([pscustomobject]@{
            Execute='powershell.exe'
            Arguments=('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$launcher+'"')
        })
    }
}
function Export-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiWindowsUpgrade.exported=$true
    return $taskXml
}
function Stop-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiWindowsUpgrade.stopped=$true
}
function New-ScheduledTaskAction {
    param([string]$Execute,[string]$Argument)
    return [pscustomobject]@{Execute=$Execute;Arguments=$Argument}
}
function New-ScheduledTaskTrigger {
    param([switch]$AtLogOn,[string]$User)
    return [pscustomobject]@{UserId=$User}
}
function New-ScheduledTaskPrincipal {
    param([string]$UserId,[string]$LogonType,[string]$RunLevel)
    return [pscustomobject]@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel}
}
function New-ScheduledTaskSettingsSet {
    param($ExecutionTimeLimit,[int]$RestartCount,$RestartInterval)
    return [pscustomobject]@{}
}
function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName,[string]$Description,$Action,$Trigger,$Principal,$Settings,[switch]$Force,[string]$Xml)
    if ($PSBoundParameters.ContainsKey('Xml')) {
        $global:CommandCoreCiWindowsUpgrade.task_xml_backout=$true
        throw 'No task-XML rollback is expected during successful upgrade.'
    }
    if ($Description -ne 'Managed by CommandCore user installer' -or
        $Principal.UserId -ne $identity.Name -or $Principal.RunLevel -ne 'Limited' -or
        $Principal.LogonType -ne 'Interactive' -or $Action.Execute -ne 'powershell.exe' -or
        !([string]$Action.Arguments).Contains('"' + $launcher + '"')) {
        throw 'Upgrade attempted to register unexpected task.'
    }
    $global:CommandCoreCiWindowsUpgrade.registered=$true
}
function Start-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $global:CommandCoreCiWindowsUpgrade.started=$true
    # Synthetic health only. This proves installer's freshness/version gate,
    # NOT that a real Agent process connected.
    $expectedVersion='0.9.0-rc2'
    $observed=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+2)
    @{connected=$true;version=$expectedVersion;observed_at_unix=$observed} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $healthPath -NoNewline
    $global:CommandCoreCiWindowsUpgrade.synthetic_health=$true
}
try {
    # Deliberately fake identity content. No enrollment tokens or device grants.
    Set-Content -LiteralPath $statePath -Value '{"ci_mock_identity":true}' -NoNewline
    & $Installer -Server $Origin -ManifestUrl ($Origin + '/releases/agent/manifest-upgrade.json') -NoEnroll -Upgrade | Out-Null
    if (!$? -or !$global:CommandCoreCiWindowsUpgrade.lookup -or
        !$global:CommandCoreCiWindowsUpgrade.exported -or
        !$global:CommandCoreCiWindowsUpgrade.stopped -or
        !$global:CommandCoreCiWindowsUpgrade.registered -or
        !$global:CommandCoreCiWindowsUpgrade.started -or
        !$global:CommandCoreCiWindowsUpgrade.synthetic_health -or
        $global:CommandCoreCiWindowsUpgrade.task_xml_backout) {
        throw 'Signed upgrade did not complete expected positive transaction.'
    }
    $new=Get-Content -LiteralPath $active -Raw | ConvertFrom-Json
    $newBinary=Join-Path $root 'releases\0.9.0-rc2\commandcore-agent.exe'
    $newManifest=Join-Path $root 'releases\0.9.0-rc2\manifest.json'
    if ($new.version -ne '0.9.0-rc2' -or
        $new.binary -cne $newBinary -or
        !(Test-Path -LiteralPath $newBinary -PathType Leaf) -or
        !(Test-Path -LiteralPath $newManifest -PathType Leaf) -or
        !(Test-Path -LiteralPath $launcher -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $root 'active.new.json')) -or
        @(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count -ne 2) {
        throw 'Signed newer release was not activated cleanly.'
    }
    foreach ($path in @($oldBinary, $oldManifest, $marker)) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $originalHashes[$path]) {
            throw 'Prior signed Agent or install marker changed during upgrade.'
        }
    }
    & $newBinary --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'New selected signed Agent binary failed runtime check.' }
    @{status='PASS'; simulated_signed_upgrade_success=$true;
      previous_release_preserved=$true; new_release_activated=$true;
      task_replacement_simulated=$true; health_synthetic_only=$true} |
        ConvertTo-Json -Compress
} finally {
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $healthPath -Force -ErrorAction SilentlyContinue
    Remove-Variable -Scope Global -Name CommandCoreCiWindowsUpgrade -ErrorAction SilentlyContinue
}
