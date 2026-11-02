# Offline, deterministic negative matrix. Does not access Task Scheduler or a VM.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_interactive_vm_task_shape.ps1')
$account = 'S-1-5-21-1234-5678-9012-1001'
$description = 'CommandCore disposable VM interactive logon proof only'
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\CI\task-action.ps1" -FixtureRoot "C:\CI"'
function New-Candidate {
    return [pscustomobject]@{
        TaskPath = '\'
        Description = $description
        Principal = [pscustomobject]@{
            UserId = $account
            LogonType = 'Interactive'
            RunLevel = 'Limited'
        }
        Triggers = @([pscustomobject]@{
            UserId = $account
            CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' }
        })
        Actions = @([pscustomobject]@{
            Execute = 'powershell.exe'
            Arguments = $arguments
        })
    }
}
function Assert-Shape($task, [string]$expected) {
    $actual = Test-CommandCoreVmTaskShape -Task $task -AllowedUsers @($account) `
        -ExpectedDescription $description -ExpectedArguments $arguments
    if ($actual -cne $expected) {
        throw ('Unexpected offline VM task shape: expected ' + $expected + ', got ' + $actual)
    }
}
Assert-Shape (New-Candidate) 'owned'
# Different inherited caller identities must not widen task authorization.
$previousUser = $env:USERNAME
try {
    $env:USERNAME = 'unrelated_runner_admin'
    Assert-Shape (New-Candidate) 'owned'
} finally {
    $env:USERNAME = $previousUser
}
$task = New-Candidate; $task.TaskPath = '\Other\'; Assert-Shape $task 'unexpected_task_path'
$task = New-Candidate; $task.Description = 'unrelated'; Assert-Shape $task 'unrelated_task_name'
$task = New-Candidate; $task.Principal.UserId = 'S-1-5-32-544'; Assert-Shape $task 'task_principal_mismatch'
$task = New-Candidate; $task.Principal.RunLevel = 'Highest'; Assert-Shape $task 'unsafe_task_principal'
$task = New-Candidate; $task.Principal.LogonType = 'Password'; Assert-Shape $task 'unsafe_task_principal'
$task = New-Candidate; $task.Triggers[0].UserId = 'S-1-5-32-544'; Assert-Shape $task 'unexpected_task_trigger'
$task = New-Candidate; $task.Triggers[0].CimClass.CimClassName = 'MSFT_TaskDailyTrigger'; Assert-Shape $task 'unexpected_task_trigger'
$task = New-Candidate; $task.Triggers += $task.Triggers[0]; Assert-Shape $task 'unexpected_task_trigger'
$task = New-Candidate; $task.Actions[0].Execute = 'cmd.exe'; Assert-Shape $task 'unexpected_task_action'
$task = New-Candidate; $task.Actions[0].Arguments += ' -EncodedCommand AAA'; Assert-Shape $task 'unexpected_task_action'
$task = New-Candidate; $task.Actions[0].Arguments = '-File "C:\unrelated.ps1" ' + $arguments; Assert-Shape $task 'unexpected_task_action'
$task = New-Candidate; $task.Actions += $task.Actions[0]; Assert-Shape $task 'unexpected_task_action'
Write-Output 'PASS: 12 unsafe VM Scheduler task shapes denied; valid ownership and inherited USERNAME check passed'
