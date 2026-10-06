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
    if ($task.Description -ne 'Managed by CommandCore user installer') { throw 'Refusing an unrelated task.' }
    Stop-ScheduledTask -TaskName $taskName
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Remove-Item -LiteralPath $root -Recurse -Force
Write-Output 'Removed managed Agent files/task. Device identity is retained under State; revoke it in the panel before discarding it.'
