# Disposable CI-only HTTPS transport test under a real standard Windows user.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'result\worker.result.json'
$exitCode = 0
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Privileged CI worker is not acceptable.'
    }
    $curl = Get-Command curl.exe -ErrorAction Stop
    $download = Join-Path $FixtureRoot 'result\transport.txt'
    # Same TLS and proxy behavior as install/windows.ps1. Never use -k or
    # disable certificate verification. No credentials or remote host involved.
    & $curl.Source --disable --globoff --proto '=https' --tlsv1.2 --connect-timeout 8 --max-time 12 --fail --silent --output $download --url ($Origin + '/test.txt')
    $exitCode = [int]$LASTEXITCODE
    if ($exitCode -ne 0) { throw 'CI-only HTTPS transport rejected.' }
    if ((Get-Content -LiteralPath $download -Raw).Trim() -ne 'commandcore-ci-https-ok') {
        throw 'Unexpected HTTPS test response.'
    }
    @{status='PASS'; non_admin=$true; task_probe=$true} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $report -Encoding UTF8
} catch {
    @{status='FAIL'; non_admin=$false; task_probe=$false; stage='https_transport'; curl_exit=$exitCode} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
}
