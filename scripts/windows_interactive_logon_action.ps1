# Harmless at-logon task action for a dedicated disposable interactive Windows VM.
# Never starts CommandCore Agent, accesses a server, or requests elevation.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
try {
    $stateFile = Join-Path $FixtureRoot 'state.json'
    $proofFile = Join-Path $FixtureRoot 'proof.json'
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Refusing administrator token'
    }
    if ([string]$identity.User.Value -ne [string]$state.user_sid) {
        throw 'Task identity mismatch'
    }
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($session -le 0) { throw 'Task did not run in an interactive desktop session' }
    $proof = @{
        schema = 1
        nonce = [string]$state.nonce
        user_sid = [string]$identity.User.Value
        started_utc = [DateTimeOffset]::UtcNow.ToString('o')
        session_id = $session
        non_admin = $true
    }
    $tmp = Join-Path $FixtureRoot ('proof.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $proof | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $proofFile -ErrorAction Stop
    exit 0
} catch {
    # No raw errors, usernames, tokens, environment variables, or paths in output.
    exit 1
}
