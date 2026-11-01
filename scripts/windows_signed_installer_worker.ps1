# Runs as the disposable CI non-administrator; never enrolls a real device.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'result\worker.result.json'
$stage = 'identity'
$rollbackPhase = 'none'
$rollbackCategory = 'none'
$rollbackErrorId = 'none'
$rollbackSourceLine = 0
$rollbackFlags = 'none'
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
    # A credential-launched CI process can inherit the runner's PSModulePath.
    # Resolve built-in PowerShell modules from trusted machine locations only,
    # rather than the runner account's (potentially inaccessible) user modules.
    $systemModules = Join-Path $PSHOME 'Modules'
    $machineModules = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $env:PSModulePath = $systemModules + ';' + $machineModules
    Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
    Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
    Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
    foreach ($cmd in @('Get-FileHash', 'ConvertFrom-Json', 'Get-Content', 'Set-Acl')) {
        if (!(Get-Command $cmd -ErrorAction SilentlyContinue)) {
            throw 'CI standard-user PowerShell module initialization failed.'
        }
    }
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
    # Exercise the actual packaged signed installer before *any* legitimate
    # installation. Neither an invalid signed manifest nor a corrupted pinned
    # executable may create activation metadata, a marker or enrollment state.
    $root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
    $stateRoot = Join-Path $env:LOCALAPPDATA 'CommandCore\State'
    if (Test-Path -LiteralPath $root -PathType Container) {
        throw 'Disposable Windows fixture unexpectedly contains an Agent.'
    }
    $stage = 'tampered_manifest_denial'
    $badManifestDenied = $false
    try {
        & $installer -Server $Origin -NoEnroll -NoTask -ManifestUrl ($Origin + '/releases/agent/manifest-tampered.json') | Out-Null
    } catch {
        $badManifestDenied = [string]$_.Exception.Message -eq 'Manifest signature/metadata verification failed.'
    }
    if (!$badManifestDenied) { throw 'Tampered signed release manifest was not rejected.' }
    $stage = 'pinned_verifier_denial'
    $badVerifierDenied = $false
    try {
        & $installer -Server $Origin -NoEnroll -NoTask -VerifierUrl ($Origin + '/tampered-verifier.exe') | Out-Null
    } catch {
        $badVerifierDenied = [string]$_.Exception.Message -eq 'Native verifier checksum mismatch; nothing was executed.'
    }
    if (!$badVerifierDenied) { throw 'Tampered pinned verifier was not rejected.' }
    $stage = 'clean_after_tamper_denial'
    $noStateAfterTamper = !(Test-Path -LiteralPath $root) -and !(Test-Path -LiteralPath $stateRoot)
    if (!$noStateAfterTamper) {
        throw 'Rejected signed release input created an Agent installation or state.'
    }
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
    $enrollmentState = Join-Path $env:LOCALAPPDATA 'CommandCore\State\agent.json'
    if (Test-Path -LiteralPath $enrollmentState) {
        throw 'Unexpected enrollment during no-enroll test.'
    }
    # Negative safety acceptance on the exact installed signed release, on the
    # same disposable standard-user profile. An unattended rerun or an upgrade
    # without the required identity/task must fail before any mutation.
    $stage = 'repeat_install_snapshot'
    $releaseDir = Split-Path -Parent $config.binary
    $installedManifest = Join-Path $releaseDir 'manifest.json'
    $markerPath = Join-Path $root '.commandcore-install'
    $activeBefore = (Get-FileHash -LiteralPath $active -Algorithm SHA256).Hash
    $binaryBefore = (Get-FileHash -LiteralPath $config.binary -Algorithm SHA256).Hash
    $manifestBefore = (Get-FileHash -LiteralPath $installedManifest -Algorithm SHA256).Hash
    $markerBefore = (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash
    $releaseCountBefore = @(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count
    $stage = 'repeat_install_denial'
    $repeatDenied = $false
    try {
        & $installer -Server $Origin -NoEnroll -NoTask | Out-Null
    } catch {
        $repeatDenied = ([string]$_.Exception.Message -eq 'Use -Upgrade with the existing identity and interactive logon task.')
    }
    if (!$repeatDenied) { throw 'Repeated signed installation was not safely rejected.' }
    $stage = 'unauthorized_upgrade_denial'
    $upgradeDenied = $false
    try {
        & $installer -Server $Origin -NoEnroll -NoTask -Upgrade | Out-Null
    } catch {
        $upgradeDenied = ([string]$_.Exception.Message -eq 'Use -Upgrade with the existing identity and interactive logon task.')
    }
    if (!$upgradeDenied) { throw 'Upgrade without installed identity and task was not safely rejected.' }
    $stage = 'repeat_install_unchanged'
    if ((Get-FileHash -LiteralPath $active -Algorithm SHA256).Hash -cne $activeBefore -or
        (Get-FileHash -LiteralPath $config.binary -Algorithm SHA256).Hash -cne $binaryBefore -or
        (Get-FileHash -LiteralPath $installedManifest -Algorithm SHA256).Hash -cne $manifestBefore -or
        (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash -cne $markerBefore -or
        @(Get-ChildItem -LiteralPath (Join-Path $root 'releases') -Directory).Count -ne $releaseCountBefore -or
        (Test-Path -LiteralPath (Join-Path $root 'active.new.json')) -or
        (Test-Path -LiteralPath $enrollmentState)) {
        throw 'Rejected repeat or upgrade modified the installed release.'
    }
    $stage = 'upgrade_rollback_simulation'
    $probe = Join-Path $FixtureRoot 'installers\upgrade_rollback_probe.ps1'
    if (!(Test-Path -LiteralPath $probe -PathType Leaf)) { throw 'Missing isolated rollback probe.' }
    $probeResult = & $probe -Installer $installer -Origin $Origin | ConvertFrom-Json
    if ($probeResult.status -eq 'FAIL') {
        if ($probeResult.phase -in @('preconditions', 'signed_upgrade', 'restore', 'hashes')) {
            $rollbackPhase = [string]$probeResult.phase
        }
        if ($probeResult.category -in @('none', 'expected_task_failure', 'release_verification', 'task_preflight', 'rollback', 'missing_property', 'parameter_binding', 'access_denied', 'unexpected_failure')) {
            $rollbackCategory = [string]$probeResult.category
        }
        if ($probeResult.error_id -match '^[A-Za-z0-9_]{1,80}$') {
            $rollbackErrorId = [string]$probeResult.error_id
        }
        if ($probeResult.source_line -is [int] -and $probeResult.source_line -gt 0 -and $probeResult.source_line -lt 500) {
            $rollbackSourceLine = [int]$probeResult.source_line
        }
        $rollbackFlags = [string]([int]($probeResult.looked_up -eq $true)) + [string]([int]($probeResult.exported -eq $true)) +
            [string]([int]($probeResult.injected -eq $true)) + [string]([int]($probeResult.restored -eq $true)) +
            [string]([int]($probeResult.restarted -eq $true))
        throw 'Disposable signed upgrade rollback simulation failed.'
    }
    if ($probeResult.task_restored -ne $true -or $probeResult.activation_unchanged -ne $true -or
        $probeResult.failed_release_removed -ne $true -or $probeResult.old_task_restarted -ne $true) {
        throw 'Failed signed upgrade did not restore activation and task.'
    }
    @{status='PASS'; non_admin=$true; signed_install=$true; tampered_manifest_denied=$true; pinned_verifier_denied=$true; clean_after_tamper_denial=$true; repeat_denied=$true; upgrade_without_identity_denied=$true; unchanged_after_denial=$true; simulated_upgrade_rollback=$true} |
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
    # Report only known command names, never raw exception text.
    $missingCommand = 'unknown'
    if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
        $candidate = [string]$_.Exception.CommandName
        if ($candidate -in @('Get-ScheduledTask', 'Get-Command', 'curl.exe', 'Get-FileHash', 'Get-ReleaseFile', 'Get-ItemProperty', 'Set-Acl', 'New-Item', 'ConvertFrom-Json', 'Get-Content', 'Remove-Item')) {
            $missingCommand = $candidate.Replace('-', '_').Replace('.', '_')
        }
    }
    $failureType = ([string]$_.Exception.GetType().Name)
    if ($failureType -notmatch '^[A-Za-z0-9_]{1,64}$') { $failureType = 'other' }
    $failureId = ([string]$_.FullyQualifiedErrorId).Split(',')[0]
    if ($failureId -notmatch '^[A-Za-z0-9_]{1,64}$') { $failureId = 'other' }
    $stack = [string]$_.ScriptStackTrace
    if ($installerLine -eq 0 -and $stack -match '(?i)windows\.ps1:\s*line\s+([0-9]{1,3})') {
        $installerLine = [int]$Matches[1]
    }
    $failureCommand = 'other'
    if ($stack -match '(?i)Get-ReleaseFile') { $failureCommand = 'GetReleaseFile' }
    elseif ($stack -match '(?i)Set-Acl') { $failureCommand = 'SetAcl' }
    @{status='FAIL'; non_admin=$false; signed_install=$false; stage=$stage; hint=$hint; rollback_phase=$rollbackPhase; rollback_category=$rollbackCategory; rollback_error_id=$rollbackErrorId; rollback_source_line=$rollbackSourceLine; rollback_flags=$rollbackFlags; installer_line=$installerLine; curl_exit=$curlCode; failure_type=$failureType; failure_id=$failureId; failure_command=$failureCommand; missing_command=$missingCommand} |
        ConvertTo-Json -Compress |
        Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
}
