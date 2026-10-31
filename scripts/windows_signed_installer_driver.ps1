# CI-only disposable standard-user execution; requires runner Administrator.
# Never use this script against enrolled user machines or production.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin
)
$ErrorActionPreference = 'Stop'
$taskName = "CommandCore CI Install $UserName"
$account = "$env:COMPUTERNAME\$UserName"
$password = $env:COMMANDCORE_CI_USER_PASSWORD
if (!$password -or $UserName -notmatch '^cc[a-f0-9]{10}$') { throw 'Invalid disposable account fixture.' }
$result = Join-Path $FixtureRoot 'worker.result.json'
$worker = Join-Path $PSScriptRoot 'windows_signed_installer_worker.ps1'
$createdUser = $false
$createdTask = $false
try {
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $UserName -Password $secure -AccountNeverExpires -Description 'Disposable CommandCore CI Agent installer acceptance' | Out-Null
    $createdUser = $true
    # Only an ephemeral CI fixture folder is made writable by the Users group.
    & icacls.exe $FixtureRoot /grant '*S-1-5-32-545:(OI)(CI)M' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant fixture access.' }
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $worker + '" -FixtureRoot "' + $FixtureRoot + '" -Origin "' + $Origin + '"'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(10))
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $account -Password $password -RunLevel Limited -Force | Out-Null
    $createdTask = $true
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(110)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $result -PathType Leaf) {
            $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
            if ($report.status -ne 'PASS' -or $report.non_admin -ne $true -or $report.signed_install -ne $true) {
                throw 'Standard-user signed installer failed its assertions.'
            }
            Write-Output 'PASS: isolated non-admin Windows signed Agent install'
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw 'Standard-user installation did not report success before deadline.'
} finally {
    if ($createdTask) {
        try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($createdUser) {
        Remove-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    }
}
