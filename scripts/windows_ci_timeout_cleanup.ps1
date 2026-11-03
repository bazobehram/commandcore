# Last-resort teardown after an *outer* disposable Windows CI driver timeout.
# Only the newly generated cc<10 hex> account and known owned CI logon task
# may be removed. Never runs on user devices or non-GitHub Windows hosts.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$UserName)
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:OS -ne 'Windows_NT' -or $UserName -cnotmatch '^cc[a-f0-9]{10}$') {
    throw 'CI cleanup refused outside disposable GitHub Windows fixture.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'CI cleanup requires the ephemeral runner administrator.'
}
$description = 'Disposable CommandCore CI installer test'
$user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (!$user) {
    Write-Output 'PASS: disposable CI account already absent'
    exit 0
}
if ([string]$user.Description -cne $description) {
    throw 'CI cleanup refused unrelated user.'
}
$taskName = 'CommandCore CI Install ' + $UserName
$task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    $allowed = @(
        [string]$user.SID.Value, [string]$UserName,
        [string]([Environment]::MachineName + '\' + $UserName),
        [string]('.\' + $UserName)
    )
    $triggers = @($task.Triggers)
    $actions = @($task.Actions)
    if ([string]$task.TaskPath -cne '\' -or
        [string]$task.Description -cne 'Disposable CommandCore CI logon task probe' -or
        [string]$task.Principal.UserId -notin $allowed -or
        [string]$task.Principal.LogonType -cne 'Interactive' -or
        [string]$task.Principal.RunLevel -cne 'Limited' -or
        $triggers.Count -ne 1 -or
        [string]$triggers[0].CimClass.CimClassName -cne 'MSFT_TaskLogonTrigger' -or
        [string]$triggers[0].UserId -notin $allowed -or
        $actions.Count -ne 1 -or
        [string]$actions[0].Execute -notmatch '(?i)(^|\\)powershell\.exe$' -or
        [string]$actions[0].Arguments -cne '-NoProfile -NonInteractive -Command "exit 0"') {
        throw 'CI cleanup refused unrelated or unexpected task.'
    }
    Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
}
Remove-LocalUser -Name $UserName -ErrorAction Stop
if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
    throw 'CI account still present after cleanup.'
}
Write-Output 'PASS: only disposable CI account and owned task cleaned'
