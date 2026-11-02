# Pure shape validator for the offline disposable Windows interactive-VM harness.
# No Task Scheduler commands, process execution, secrets, or host mutations.
function Test-CommandCoreVmTaskShape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Task,
        [Parameter(Mandatory)][string[]]$AllowedUsers,
        [Parameter(Mandatory)][string]$ExpectedDescription,
        [Parameter(Mandatory)][string]$ExpectedArguments
    )
    if (!$Task -or [string]$Task.TaskPath -cne '\') { return 'unexpected_task_path' }
    if ([string]$Task.Description -cne $ExpectedDescription) { return 'unrelated_task_name' }
    if ([string]$Task.Principal.UserId -notin $AllowedUsers) { return 'task_principal_mismatch' }
    if ([string]$Task.Principal.LogonType -cne 'Interactive' -or
        [string]$Task.Principal.RunLevel -cne 'Limited') { return 'unsafe_task_principal' }
    $triggers = @($Task.Triggers)
    if ($triggers.Count -ne 1 -or
        [string]$triggers[0].CimClass.CimClassName -cne 'MSFT_TaskLogonTrigger' -or
        [string]$triggers[0].UserId -notin $AllowedUsers) { return 'unexpected_task_trigger' }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or
        [string]$actions[0].Execute -notmatch '(?i)(^|\\)powershell\.exe$' -or
        [string]$actions[0].Arguments -cne $ExpectedArguments) {
        return 'unexpected_task_action'
    }
    return 'owned'
}
