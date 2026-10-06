# Native normal-user installer template. Release packaging pins the verifier
# hash from an independently verified signed manifest. Never execute a download
# before checking that pin. Windows acceptance is still required before release.
[CmdletBinding()]
param(
    [string]$Server = 'https://commandcore.example.com',
    [string]$ManifestUrl = '',
    [string]$ReleasePublicKey = '__COMMANDCORE_RELEASE_PUBLIC_KEY__',
    [string]$VerifierUrl = '__COMMANDCORE_VERIFIER_URL__',
    [string]$VerifierSha256 = '__COMMANDCORE_VERIFIER_SHA256__',
    [switch]$NoEnroll,
    [switch]$NoTask,
    [switch]$Upgrade
)
$ErrorActionPreference = 'Stop'
function Get-ReleaseFile([string]$Url, [string]$Output) {
    $parsed = [Uri]$Url
    if ($parsed.Scheme -ne 'https' -or $parsed.UserInfo -or $parsed.Fragment) { throw 'Release download requires HTTPS without credentials.' }
    $curl = Get-Command curl.exe -ErrorAction Stop
    & $curl.Source --disable --globoff --proto '=https' --tlsv1.2 --happy-eyeballs-timeout-ms 250 --connect-timeout 15 --max-time 60 --max-filesize 134217728 --fail --silent --user-agent CommandCore-release-downloader/1 --output $Output --url $Url
    if ($LASTEXITCODE -ne 0) {
        $stage = switch ($LASTEXITCODE) { 6 {'DNS'} 7 {'TCP'} 22 {'HTTP'} 28 {'deadline'} 35 {'TLS'} 60 {'TLS'} default {'transport'} }
        throw ('Release download failed: stage=' + $stage + ' curl_exit=' + $LASTEXITCODE)
    }
}
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run in a normal user session. Privileged helper setup is separate.'
}
if (!$ReleasePublicKey -or $ReleasePublicKey.StartsWith('__COMMANDCORE_')) { throw 'Use the packaged installer with its pinned release public key.' }
if ($VerifierSha256 -notmatch '^[a-f0-9]{64}$') { throw 'A packaged native verifier hash is required.' }
if (!$ManifestUrl) { $ManifestUrl = $Server.TrimEnd('/') + '/releases/agent/manifest.json' }
foreach ($value in @($Server, $ManifestUrl, $VerifierUrl)) {
    $uri = [Uri]$value
    if (!$uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Fragment) {
        throw 'HTTPS URLs without userinfo/fragments are required.'
    }
}
$arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$arch = switch ($arch) { 'X64' { 'x86_64' } 'Arm64' { 'arm64' } default { throw 'Unsupported architecture.' } }
# Only x86_64 has a build/acceptance path at present; do not silently claim ARM.
if ($arch -ne 'x86_64') { throw 'Windows ARM64 is not yet supported.' }
$root = Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'
$stateRoot = Join-Path $env:LOCALAPPDATA 'CommandCore\State'
$marker = Join-Path $root '.commandcore-install'
$activePath = Join-Path $root 'active.json'
$taskName = 'CommandCore Agent'
$taskDescription = 'Managed by CommandCore user installer'
if ((Test-Path -LiteralPath $root) -and !(Test-Path -LiteralPath $marker -PathType Leaf)) {
    throw 'Refusing an unrelated installation directory.'
}
$oldTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($oldTask -and $oldTask.Description -ne $taskDescription) { throw 'Refusing an unrelated scheduled task.' }
$previous = if (Test-Path -LiteralPath $activePath) { Get-Content -LiteralPath $activePath -Raw } else { $null }
if ($previous -and (!$Upgrade -or $NoTask -or !(Test-Path -LiteralPath (Join-Path $stateRoot 'agent.json')))) {
    throw 'Use -Upgrade with the existing identity and interactive logon task.'
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('commandcore-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$activated = $false
$complete = $false
try {
    $verifier = Join-Path $temp 'release-verifier.exe'
    Get-ReleaseFile $VerifierUrl $verifier
    if ((Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash.ToLowerInvariant() -cne $VerifierSha256) {
        throw 'Native verifier checksum mismatch; nothing was executed.'
    }
    $manifest = Join-Path $temp 'manifest.json'
    Get-ReleaseFile $ManifestUrl $manifest
    $metadataText = & $verifier verify-release $manifest --public-key $ReleasePublicKey --platform windows --architecture $arch
    if ($LASTEXITCODE -ne 0) { throw 'Manifest signature/metadata verification failed.' }
    $metadata = $metadataText | ConvertFrom-Json
    if ($previous) {
        $oldVersion = ($previous | ConvertFrom-Json).version
        & $verifier verify-release $manifest --public-key $ReleasePublicKey --platform windows --architecture $arch --newer-than $oldVersion | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Upgrade must be newer than the installed release.' }
    }
    # The native verifier is this release's Agent executable. Bind selection to
    # the packaged pin, preventing a replayed older signed manifest from choosing
    # a different Agent on a clean machine. Download a newer packaged installer
    # for a newer release; existing identity remains untouched during upgrade.
    if ($metadata.sha256 -cne $VerifierSha256) { throw 'Manifest differs from this packaged release. Download the current installer.' }
    $artifact = $verifier
    & $verifier verify-release $manifest --public-key $ReleasePublicKey --platform windows --architecture $arch --artifact $artifact | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Artifact integrity verification failed.' }
    foreach ($path in @($root, $stateRoot)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($identity.User)
        foreach ($sid in @($identity.User.Value, 'S-1-5-18')) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),
                'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    Set-Content -LiteralPath $marker -Value 'commandcore-agent'
    $release = Join-Path $root ('releases\' + $metadata.version)
    $binary = Join-Path $release 'commandcore-agent.exe'
    if (Test-Path -LiteralPath $release) { throw 'Version already exists; refusing overwrite.' }
    New-Item -ItemType Directory -Path $release | Out-Null
    Copy-Item -LiteralPath $artifact -Destination $binary
    Copy-Item -LiteralPath $manifest -Destination (Join-Path $release 'manifest.json')
    if (!$NoEnroll -and !(Test-Path -LiteralPath (Join-Path $stateRoot 'agent.json'))) {
        & $binary enroll $Server --state (Join-Path $stateRoot 'agent.json') --no-connect
        if ($LASTEXITCODE -ne 0) { throw 'Enrollment did not complete.' }
    }
    $next = Join-Path $root 'active.new.json'
    @{version=$metadata.version; binary=$binary; state=(Join-Path $stateRoot 'agent.json')} | ConvertTo-Json | Set-Content -LiteralPath $next
    if ($oldTask) { Stop-ScheduledTask -TaskName $taskName }
    Move-Item -LiteralPath $next -Destination $activePath -Force
    $activated = $true
    if (!$NoTask) {
        $launcher = Join-Path $root 'run-agent.ps1'
        @'
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'active.json') -Raw | ConvertFrom-Json
$resolved = [IO.Path]::GetFullPath($config.binary)
$allowed = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'releases')) + [IO.Path]::DirectorySeparatorChar
if (!$resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid installed executable path.' }
& $resolved run --state $config.state
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $launcher
        # This applies only to the child PowerShell process executing our owned
        # launcher. Machine/user execution policy is never changed.
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
        if (Test-Path -LiteralPath (Join-Path $stateRoot 'agent.json')) {
            $activationTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            Start-ScheduledTask -TaskName $taskName
            $deadline = (Get-Date).AddSeconds(45)
            $healthy = $false
            while ((Get-Date) -lt $deadline) {
                try {
                    $health = Get-Content -LiteralPath (Join-Path $stateRoot 'health.json') -Raw | ConvertFrom-Json
                    if ($health.connected -eq $true -and $health.version -eq $metadata.version -and $health.observed_at_unix -gt $activationTime) { $healthy = $true; break }
                } catch { }
                Start-Sleep -Milliseconds 500
            }
            if (!$healthy) { throw 'No fresh authenticated connection health.' }
        }
    }
    $complete = $true
    Write-Output ('Installed signed user Agent ' + $metadata.version + '. FULL_CONTROL remains disabled.')
} finally {
    if ($activated -and !$complete -and $previous) {
        if (!$NoTask) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
        Set-Content -LiteralPath $activePath -Value $previous
        if ($oldTask) { Start-ScheduledTask -TaskName $taskName }
        Write-Warning 'Installation failed; restored the previous Agent configuration.'
    }
    $resolvedTemp = [IO.Path]::GetFullPath($temp)
    $allowedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (!$resolvedTemp.StartsWith($allowedTemp, [StringComparison]::OrdinalIgnoreCase) -or !(Split-Path $resolvedTemp -Leaf).StartsWith('commandcore-install-')) { throw 'Unsafe temporary cleanup path.' }
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
}
