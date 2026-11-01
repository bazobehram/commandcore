# Disposable Windows Scheduled Task probe, never enrolls a device or runs an installer.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'result\worker.result.json'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Task is not running as a standard user.'
    }
    $systemModules = Join-Path $PSHOME 'Modules'
    $machineModules = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $env:PSModulePath = $systemModules + ';' + $machineModules
    Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
    Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
    Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
    foreach ($cmd in @('Get-FileHash', 'ConvertFrom-Json', 'Get-Content', 'Set-Acl')) {
        if (!(Get-Command $cmd -ErrorAction SilentlyContinue)) {
            throw 'CI standard-user built-in module unavailable.'
        }
    }
    @{status='PASS'; non_admin=$true; task_probe=$true} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
} catch {
    @{status='FAIL'; non_admin=$false; task_probe=$false; stage='identity'} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
}
