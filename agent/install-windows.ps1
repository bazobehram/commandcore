param(
  [Parameter(Mandatory=$true)][string]$ServerUrl,
  [Parameter(Mandatory=$true)][string]$AgentUrl,
  [string]$InstallDir="$env:ProgramFiles\CommandCore",
  [string]$NativeAgentBinary="",
  [ValidateSet('READ_ONLY','STANDARD','FULL_CONTROL')][string]$MaxProfile='STANDARD'
)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if ($NativeAgentBinary) {
  Copy-Item $NativeAgentBinary "$InstallDir\commandcore-agent.exe" -Force
} elseif (-not (Test-Path "$InstallDir\commandcore-agent.exe")) {
  throw 'A verified native Windows commandcore-agent.exe is required for service installation.'
}
$policyDir="$env:ProgramData\CommandCore"
New-Item -ItemType Directory -Force -Path $policyDir | Out-Null
@{configured_max_permission_profile=$MaxProfile; server_url=$ServerUrl; agent_url=$AgentUrl} | ConvertTo-Json | Set-Content "$policyDir\policy.json" -Encoding UTF8
$svc='CommandCoreAgent'
if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force -ErrorAction SilentlyContinue; sc.exe delete $svc | Out-Null; Start-Sleep -Seconds 1 }
$bin='"'+$InstallDir+'\commandcore-agent.exe" run --server-url "'+$ServerUrl+'" --agent-url "'+$AgentUrl+'" --state "'+$policyDir+'\agent.json"'
New-Service -Name $svc -BinaryPathName $bin -DisplayName 'CommandCore Agent' -StartupType Automatic | Out-Null
sc.exe failure $svc reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Write-Host "Installed $svc. Enroll interactively before starting the service:"
Write-Host "  & '$InstallDir\commandcore-agent.exe' enroll --server-url '$ServerUrl' --token '<ONE_TIME_TOKEN>' --state '$policyDir\agent.json'"
Write-Host "Then: Start-Service $svc"
