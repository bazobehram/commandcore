# Disposable CI-only HTTPS transport test under a real standard Windows user.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $FixtureRoot 'result\worker.result.json'
$exitCode = 0
$backend = 'unknown'
$sourceKind = 'other'
$tlsHint = 'unknown'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Privileged CI worker is not acceptable.'
    }
    $curl = Get-Command curl.exe -ErrorAction Stop
    if ($curl.Source -eq (Join-Path $env:WINDIR 'System32\curl.exe')) {
        $sourceKind = 'system32'
    } elseif ($curl.Source -match '(?i)Git') {
        $sourceKind = 'git'
    }
    $versionLine = [string]((& $curl.Source --version | Select-Object -First 1))
    if ($versionLine -match '(?i)Schannel') { $backend = 'schannel' }
    elseif ($versionLine -match '(?i)OpenSSL') { $backend = 'openssl' }
    $download = Join-Path $FixtureRoot 'result\transport.txt'
    $trace = Join-Path $FixtureRoot 'result\curl-trace.tmp'
    # Verify the real Schannel certificate chain. Capture verbose diagnostics
    # only in a disposable fixture, and emit a fixed, nonsecret failure class.
    try {
        & $curl.Source --disable --globoff --proto '=https' --tlsv1.2 --noproxy 'localhost,127.0.0.1' --connect-timeout 8 --max-time 12 --fail --silent --verbose --stderr $trace --output $download --url ($Origin + '/test.txt')
        $exitCode = [int]$LASTEXITCODE
        if ($exitCode -ne 0 -and (Test-Path -LiteralPath $trace)) {
            $detail = Get-Content -LiteralPath $trace -Raw
            if ($detail -match '(?i)SEC_E_UNTRUSTED_ROOT|CERT_TRUST_IS_UNTRUSTED_ROOT') {
                $tlsHint = 'untrusted_root'
            } elseif ($detail -match '(?i)SEC_E_REVOCATION_OFFLINE|CRYPT_E_REVOCATION_OFFLINE|revocation check') {
                $tlsHint = 'revocation'
            } elseif ($detail -match '(?i)SEC_E_WRONG_PRINCIPAL|hostname mismatch') {
                $tlsHint = 'hostname'
            } elseif ($detail -match '(?i)SEC_E_ALGORITHM_MISMATCH|unsupported certificate') {
                $tlsHint = 'algorithm'
            } elseif ($detail -match '(?i)SEC_E_ILLEGAL_MESSAGE|TLS alert|handshake failure') {
                $tlsHint = 'handshake_alert'
            } elseif ($detail -match '(?i)schannel:') {
                $tlsHint = 'schannel_other'
            }
        }
    } finally {
        Remove-Item -LiteralPath $trace -Force -ErrorAction SilentlyContinue
    }
    if ($exitCode -ne 0) { throw 'CI-only HTTPS transport rejected.' }
    if ((Get-Content -LiteralPath $download -Raw).Trim() -ne 'commandcore-ci-https-ok') {
        throw 'Unexpected HTTPS test response.'
    }
    @{status='PASS'; non_admin=$true; task_probe=$true; curl_backend=$backend; curl_source=$sourceKind; tls_hint=$tlsHint} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $report -Encoding UTF8
} catch {
    @{status='FAIL'; non_admin=$false; task_probe=$false; stage='https_transport'; curl_exit=$exitCode; curl_backend=$backend; curl_source=$sourceKind} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $report -Encoding UTF8
    exit 1
}
