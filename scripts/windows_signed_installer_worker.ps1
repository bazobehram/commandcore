# Runs as the disposable CI non-administrator; never enrolls a real device.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'result\worker.result.json'
$stage = 'identity'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Must run as a standard user.'
    }
    $stage = 'profile'
    # Start-Process -Credential can inherit the privileged runner's environment.
    # Derive this disposable account's actual profile from its authenticated SID,
    # not from inherited USERPROFILE/LOCALAPPDATA/TEMP variables.
    $profileKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $identity.User.Value
    $profile = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
    $profile = [Environment]::ExpandEnvironmentVariables([string]$profile)
    if (!(Test-Path -LiteralPath $profile -PathType Container)) {
        throw 'Disposable standard-user profile was not initialized.'
    }
    $env:USERPROFILE = $profile
    $env:LOCALAPPDATA = Join-Path $profile 'AppData\Local'
    $env:APPDATA = Join-Path $profile 'AppData\Roaming'
    $env:TEMP = Join-Path $env:LOCALAPPDATA 'Temp'
    $env:TMP = $env:TEMP
    if (!(Test-Path -LiteralPath $env:LOCALAPPDATA -PathType Container)) {
        throw 'Disposable standard-user LOCALAPPDATA is missing.'
    }
    New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
    $profileProbe = Join-Path $env:LOCALAPPDATA ('commandcore-ci-' + [Guid]::NewGuid().ToString('N'))
    try {
        Set-Content -LiteralPath $profileProbe -Value 'profile-test' -ErrorAction Stop
    } finally {
        Remove-Item -LiteralPath $profileProbe -Force -ErrorAction SilentlyContinue
    }
    $installer = Join-Path $FixtureRoot 'installers\windows.ps1'
    if (!(Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Packaged installer missing.' }
    $stage = 'installer'
    & $installer -Server $Origin -NoEnroll -NoTask
    if (!$?) { throw 'Signed installer returned an error.' }
    $stage = 'activation'
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
    $stage = 'native'
    & $config.binary --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed native Agent is not runnable.' }
    $stage = 'no_enroll'
    if (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'CommandCore\State\agent.json')) {
        throw 'Unexpected enrollment during no-enroll test.'
    }
    @{status='PASS'; non_admin=$true; signed_install=$true} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
} catch {
    # Never serialize the exception, command arguments, token, URL, or path.
    # Only allowlisted categories are returned to the privileged CI driver.
    $hint = 'other'
    if ($stage -eq 'installer') {
        $message = [string]$_.Exception.Message
        $errorId = [string]$_.FullyQualifiedErrorId
        if ($message -match '(?i)Release download failed|curl_exit|HTTP|SSL|TLS|certificate') {
            $hint = 'download_or_tls'
        } elseif ($message -match '(?i)checksum|integrity|sha256|signature') {
            $hint = 'release_integrity'
        } elseif ($message -match '(?i)manifest|verify-release|artifact|release') {
            $hint = 'release_metadata'
        } elseif ($message -match '(?i)ACL|Set-Acl|Access to the path|access is denied|UnauthorizedAccess') {
            $hint = 'filesystem_acl'
        } elseif ($message -match '(?i)execution policy|not digitally signed|running scripts') {
            $hint = 'powershell_policy'
        } elseif ($message -match '(?i)already exists|existing directory|unrelated') {
            $hint = 'preexisting_installation'
        } elseif ($message -match '(?i)parameter cannot be found|ParameterBinding') {
            $hint = 'parameter_binding'
        } elseif ($message -match '(?i)not recognized|CommandNotFound') {
            $hint = 'missing_command'
        } elseif ($message -match '(?i)Property|strict mode') {
            $hint = 'powershell_strictmode'
        } elseif ($errorId -match 'ParserError') {
            $hint = 'powershell_parse'
        }
    }
    $curlCode = 0
    if ($stage -eq 'installer' -and $message -match 'curl_exit=([0-9]{1,3})') {
        $curlCode = [int]$Matches[1]
    }
    $installerLine = 0
    if ($stage -eq 'installer') {
        $source = [IO.Path]::GetFileName([string]$_.InvocationInfo.ScriptName)
        $number = [int]$_.InvocationInfo.ScriptLineNumber
        if ($source -eq 'windows.ps1' -and $number -gt 0 -and $number -lt 1000) {
            $installerLine = $number
        }
    }
    @{status='FAIL'; non_admin=$false; signed_install=$false; stage=$stage; hint=$hint; installer_line=$installerLine; curl_exit=$curlCode} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
}
