# Disposable GitHub Windows CI negative and positive timeout-cleanup probe.
# Never runs on personal devices. Creates one random local account, cleans it.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:OS -ne 'Windows_NT') {
    throw 'GitHub Windows CI required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Disposable CI runner must be an administrator.'
}
$scriptPath = Join-Path $PSScriptRoot 'windows_ci_timeout_cleanup.ps1'
$userName = 'cc' + [Guid]::NewGuid().ToString('N').Substring(0,10)
$created = $false
try {
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
        throw 'Unexpected existing disposable CI identity.'
    }
    $secret = ConvertTo-SecureString ('Aa!3' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
    New-LocalUser -Name $userName -Password $secret -AccountNeverExpires -Description 'Unrelated user fixture' -ErrorAction Stop | Out-Null
    $created = $true

    # An account whose marker differs must survive a rejected cleanup.
    & powershell.exe -NoProfile -NonInteractive -File $scriptPath -UserName $userName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -or !(Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
        throw 'Timeout cleanup touched an unrelated account.'
    }

    Set-LocalUser -Name $userName -Description 'Disposable CommandCore CI installer test' -ErrorAction Stop
    & powershell.exe -NoProfile -NonInteractive -File $scriptPath -UserName $userName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
        throw 'Timeout cleanup failed for its exact disposable fixture.'
    }
    Write-Output 'PASS: Windows timeout cleanup denies unrelated accounts and removes owned test identity'
} finally {
    if ($created -and (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
        Remove-LocalUser -Name $userName -ErrorAction Stop
    }
}
