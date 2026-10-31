# Runs as the disposable CI non-administrator; never enrolls a real device.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'worker.result.json'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Must run as a standard user.'
    }
    if (!$env:LOCALAPPDATA) { throw 'User profile was not loaded.' }
    $installer = Join-Path $FixtureRoot 'installers\windows.ps1'
    if (!(Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Packaged installer missing.' }
    & $installer -Server $Origin -NoEnroll -NoTask
    if (!$?) { throw 'Signed installer returned an error.' }
    $root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
    $active = Join-Path $root 'active.json'
    if (!(Test-Path -LiteralPath $active -PathType Leaf)) { throw 'Activation metadata missing.' }
    if (!(Test-Path -LiteralPath (Join-Path $root '.commandcore-install') -PathType Leaf)) {
        throw 'Managed installation marker missing.'
    }
    $config = Get-Content -LiteralPath $active -Raw | ConvertFrom-Json
    if ($config.version -ne '0.9.0-rc1') { throw 'Incorrect signed release selected.' }
    if (!(Test-Path -LiteralPath $config.binary -PathType Leaf)) {
        throw 'Native Agent executable missing.'
    }
    & $config.binary --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed native Agent is not runnable.' }
    if (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'CommandCore\State\agent.json')) {
        throw 'Unexpected enrollment during no-enroll test.'
    }
    @{status='PASS'; non_admin=$true; signed_install=$true} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
} catch {
    @{status='FAIL'; non_admin=$false; signed_install=$false} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
}
