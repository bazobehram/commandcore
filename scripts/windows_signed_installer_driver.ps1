# CI-only disposable standard-user execution; requires runner Administrator.
# Never use this script against enrolled user machines or production.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin,
    [switch]$OnlyAccount,
    [switch]$OnlyTask
)
$ErrorActionPreference = 'Stop'
$taskName = "CommandCore CI Install $UserName"
$account = "$env:COMPUTERNAME\$UserName"
$password = $env:COMMANDCORE_CI_USER_PASSWORD
if (!$password -or $UserName -notmatch '^cc[a-f0-9]{10}$') { throw 'Invalid disposable account fixture.' }
$result = Join-Path $FixtureRoot 'result\worker.result.json'
$worker = Join-Path $FixtureRoot 'installers\worker.ps1'
$createdUser = $false
$createdTask = $false
$stage = 'runner_privileges'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Runner must have rights to create a disposable local test account.'
    }
    $stage = 'localaccounts_module'
    if (!(Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
        throw 'Windows LocalAccounts cmdlets unavailable.'
    }
    $stage = 'create_user'
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $UserName -Password $secure -AccountNeverExpires -Description 'Disposable CommandCore CI installer test' -ErrorAction Stop | Out-Null
    $createdUser = $true
    if ($OnlyAccount) {
        Write-Output 'PASS: disposable Windows account creation and cleanup'
        return
    }
    $stage = 'fixture_acl'
    # Least privilege: read/traverse public installer assets, but write only
    # the result folder. TLS private keys are outside this entire fixture.
    & icacls.exe $FixtureRoot /grant '*S-1-5-32-545:RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant fixture traversal.' }
    & icacls.exe (Join-Path $FixtureRoot 'installers') /grant '*S-1-5-32-545:(OI)(CI)RX' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant installer read access.' }
    & icacls.exe (Join-Path $FixtureRoot 'result') /grant '*S-1-5-32-545:(OI)(CI)M' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant result write access.' }
    $stage = 'register_task'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $worker + '" -FixtureRoot "' + $FixtureRoot + '" -Origin "' + $Origin + '"'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(10))
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $account -Password $password -RunLevel Limited -Force | Out-Null
    $createdTask = $true
    $stage = 'start_task'
    Start-ScheduledTask -TaskName $taskName
    $stage = 'read_worker_report'
    $deadlineSeconds = if ($OnlyTask) { 20 } else { 110 }
    $deadline = (Get-Date).AddSeconds($deadlineSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $result -PathType Leaf) {
            $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
            $accepted = $report.status -eq 'PASS' -and $report.non_admin -eq $true
            if ($OnlyTask) {
                $accepted = $accepted -and $report.task_probe -eq $true
            } else {
                $accepted = $accepted -and $report.signed_install -eq $true
            }
            if (!$accepted) {
                if ($report.stage -in @('identity', 'profile', 'installer', 'activation', 'native', 'no_enroll')) {
                    $stage = 'worker_' + $report.stage
                } else {
                    $stage = 'worker_unknown'
                }
                throw 'Standard-user signed installer failed its assertions.'
            }
            if ($OnlyTask) {
                Write-Output 'PASS: isolated non-admin Windows Scheduled Task probe'
            } else {
                Write-Output 'PASS: isolated non-admin Windows signed Agent install'
            }
            return
        }
        Start-Sleep -Milliseconds 500
    }
    $stage = 'worker_timeout'
    try {
        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        $lastResult = [string]$info.LastTaskResult
        if ($lastResult -match '^-?[0-9]{1,11}$') {
            Write-Output ('CI_TASK_LAST_RESULT:' + $lastResult)
        }
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $taskState = [string]$task.State
        if ($taskState -in @('Running', 'Ready', 'Disabled', 'Queued', 'Unknown')) {
            Write-Output ('CI_TASK_STATE:' + $taskState)
        }
    } catch {
        Write-Output 'CI_TASK_DIAGNOSTIC:unavailable'
    }
    throw 'Standard-user worker did not report success before deadline.'
} catch {
    # The diagnostic code is static and never contains credentials, usernames,
    # filesystem locations or raw PowerShell exception messages.
    Write-Output ('CI_INSTALL_STAGE:' + $stage)
    if ($stage -eq 'create_user') {
        $category = 'other'
        $errorId = [string]$_.FullyQualifiedErrorId
        if ($errorId -match 'Password|Complexity') { $category = 'password_policy' }
        elseif ($errorId -match 'AccessDenied|UnauthorizedAccess|Privilege') { $category = 'privilege' }
        elseif ($errorId -match 'AlreadyExists|AlreadyInUse|Exists') { $category = 'name_collision' }
        elseif ($errorId -match 'ParameterBinding|InvalidArgument') { $category = 'argument' }
        Write-Output ('CI_USER_CREATE_CATEGORY:' + $category)
        $record = $_
        $hresult = [string]$record.Exception.HResult
        if ($hresult -match '^-?[0-9]{1,11}$') {
            Write-Output ('CI_USER_CREATE_HRESULT:' + $hresult)
        }
        $errorName = ([string]$record.FullyQualifiedErrorId).Split(',')[0]
        if ($errorName -match '^[A-Za-z0-9_]{1,60}$') {
            Write-Output ('CI_USER_CREATE_ERROR_ID:' + $errorName)
        }
        $errorType = [string]$record.Exception.GetType().Name
        if ($errorType -match '^[A-Za-z0-9_]{1,60}$') {
            Write-Output ('CI_USER_CREATE_EXCEPTION_TYPE:' + $errorType)
        }
        $detail = [string]$record.Exception.Message
        $hint = 'other'
        if ($detail -match '(?i)password|complexity') { $hint = 'password_policy' }
        elseif ($detail -match '(?i)description|too long|48 characters') { $hint = 'description' }
        elseif ($detail -match '(?i)already exists|already in use') { $hint = 'name_collision' }
        elseif ($detail -match '(?i)denied|permission|privilege') { $hint = 'privilege' }
        elseif ($detail -match '(?i)invalid parameter|incorrect parameter') { $hint = 'invalid_parameter' }
        Write-Output ('CI_USER_CREATE_MESSAGE_HINT:' + $hint)
        $class = [string]$record.CategoryInfo.Category
        if ($class -in @('InvalidArgument', 'InvalidOperation', 'PermissionDenied', 'SecurityError', 'NotSpecified', 'ResourceExists')) {
            Write-Output ('CI_USER_CREATE_ERROR_CLASS:' + $class)
        }
    }
    throw 'Disposable Windows installer acceptance failed (redacted).'
} finally {
    if ($createdTask) {
        try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($createdUser) {
        Remove-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    }
}
