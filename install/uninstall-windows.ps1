# Candidate uninstall: preserve identity for explicit panel revocation.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'CommandCore\Agent'))
$expected = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'CommandCore')) + [IO.Path]::DirectorySeparatorChar
if (!$root.StartsWith($expected, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $root -Leaf) -ne 'Agent') { throw 'Unsafe uninstall path.' }
$item = Get-Item -LiteralPath $root
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a redirected installation directory.' }
$marker = Join-Path $root '.commandcore-install'
if (!(Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'commandcore-agent') { throw 'No managed installation.' }
$taskName = 'CommandCore Agent'
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    # Never stop/remove another program's task simply because its name and
    # description match. The existing task must be the current user's exact
    # limited, interactive CommandCore at-logon launcher.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $allowedUsers = @($identity.Name, $identity.User.Value, $env:USERNAME,
        ($env:COMPUTERNAME + '\' + $env:USERNAME), ('.\' + $env:USERNAME))
    $launcher = Join-Path $root 'run-agent.ps1'
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    if ($task.Description -ne 'Managed by CommandCore user installer' -or
        [string]$task.Principal.UserId -notin $allowedUsers -or
        [string]$task.Principal.LogonType -ne 'Interactive' -or
        [string]$task.Principal.RunLevel -ne 'Limited' -or
        $triggers.Count -ne 1 -or
        $triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger' -or
        [string]$triggers[0].UserId -notin $allowedUsers -or
        $actions.Count -ne 1 -or
        [string]$actions[0].Execute -notmatch '(?i)(^|\\)powershell\.exe$' -or
        !([string]$actions[0].Arguments).Contains('"' + $launcher + '"')) {
        throw 'Refusing an unowned or unexpected scheduled task.'
    }
    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
}
Remove-Item -LiteralPath $root -Recurse -Force
Write-Output 'Removed managed Agent files/task. Device identity is retained under State; revoke it in the panel before discarding it.'
