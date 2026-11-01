# CI-only harmless task action. It must run under the same disposable user.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 12 }
$shortName = $identity.Name.Substring($identity.Name.LastIndexOf('\\') + 1)
if ($shortName -notmatch '^cc[a-f0-9]{10}$') { exit 13 }
$path = Join-Path $FixtureRoot 'result\task-executed.marker'
# Marker contains only a fixed string; no user identifier or secret.
Set-Content -LiteralPath $path -Value 'commandcore-ci-disposable-task-executed' -Encoding ascii -NoNewline
