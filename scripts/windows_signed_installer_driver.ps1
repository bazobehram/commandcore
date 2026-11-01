# CI-only disposable standard-user execution; requires runner Administrator.
# Never use this script against enrolled user machines or production.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Origin,
    [switch]$OnlyAccount,
    [switch]$OnlyTask,
    [switch]$OnlyCredential
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
$workerProcess = $null
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
    if ($OnlyTask) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(10))
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $account -Password $password -RunLevel Limited -Force | Out-Null
        $createdTask = $true
        $stage = 'start_task'
        Start-ScheduledTask -TaskName $taskName
    } else {
        # Test the signed installer under a real standard-user logon without
        # coupling this gate to Windows Task Scheduler lifecycle support.
        $stage = 'start_credential_process'
        $credential = [pscredential]::new($account, $secure)
        $workerProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Credential $credential -LoadUserProfile -PassThru -ErrorAction Stop
    }
    $stage = 'read_worker_report'
    $deadlineSeconds = if ($OnlyTask -or $OnlyCredential) { 20 } else { 110 }
    $deadline = (Get-Date).AddSeconds($deadlineSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $result -PathType Leaf) {
            $stage = 'parse_worker_report'
            $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
            $stage = 'evaluate_worker_report'
            $accepted = $report.status -eq 'PASS' -and $report.non_admin -eq $true
            if ($OnlyTask -or $OnlyCredential) {
                $accepted = $accepted -and $report.task_probe -eq $true
            } else {
                $accepted = $accepted -and $report.signed_install -eq $true -and
                    $report.tampered_manifest_denied -eq $true -and $report.pinned_verifier_denied -eq $true -and
                    $report.clean_after_tamper_denial -eq $true -and
                    $report.repeat_denied -eq $true -and $report.upgrade_without_identity_denied -eq $true -and
                    $report.unchanged_after_denial -eq $true
            }
            if (!$accepted) {
                if (!$OnlyTask -and !$OnlyCredential -and $report.status -eq 'PASS') {
                    foreach ($gate in @('tampered_manifest_denied', 'pinned_verifier_denied', 'clean_after_tamper_denial',
                        'repeat_denied', 'upgrade_without_identity_denied', 'unchanged_after_denial')) {
                        if ($report.PSObject.Properties.Name -notcontains $gate -or $report.$gate -ne $true) {
                            Write-Output ('CI_SIGNED_INSTALL_MISSING_GATE:' + $gate)
                        }
                    }
                }
                if ($report.stage -in @('identity', 'profile', 'installer', 'activation', 'native', 'no_enroll', 'https_transport',
                    'tampered_manifest_denial', 'pinned_verifier_denial', 'clean_after_tamper_denial',
                    'repeat_install_snapshot', 'repeat_install_denial', 'unauthorized_upgrade_denial', 'repeat_install_unchanged', 'task_modules', 'task_register', 'task_verify', 'task_identity')) {
                    $stage = 'worker_' + $report.stage
                } else {
                    $stage = 'worker_unknown'
                }
                $allowedHints = @(
                    'other', 'download_or_tls', 'release_integrity',
                    'release_metadata', 'filesystem_acl', 'powershell_policy',
                    'preexisting_installation', 'parameter_binding',
                    'missing_command', 'powershell_strictmode', 'powershell_parse'
                )
                if ($report.stage -in @('task_modules', 'task_register', 'task_verify', 'task_identity') -and
                    $report.hint -in @('missing_command', 'access_denied', 'logon_policy', 'task_shape', 'invalid_argument', 'other')) {
                    Write-Output ('CI_TASK_FAILURE_HINT:' + $report.hint)
                    if ($report.identity_part -in @('both', 'principal', 'trigger')) {
                        Write-Output ('CI_TASK_IDENTITY_PART:' + $report.identity_part)
                    }
                }
                if ($report.hint -in $allowedHints) {
                    Write-Output ('CI_WORKER_FAILURE_HINT:' + $report.hint)
                }
                if ($report.missing_command -in @('Get_ScheduledTask', 'Get_Command', 'curl_exe', 'Get_FileHash', 'Get_ReleaseFile', 'Get_ItemProperty', 'Set_Acl', 'New_Item', 'ConvertFrom_Json', 'Get_Content', 'Remove_Item')) {
                    Write-Output ('CI_INSTALLER_MISSING_COMMAND:' + $report.missing_command)
                }
                if ($report.installer_line -is [int] -and $report.installer_line -gt 0 -and $report.installer_line -lt 1000) {
                    Write-Output ('CI_INSTALLER_SOURCE_LINE:' + $report.installer_line)
                }
                if ($report.curl_exit -is [int] -and $report.curl_exit -gt 0 -and $report.curl_exit -lt 256) {
                    Write-Output ('CI_INSTALLER_CURL_EXIT:' + $report.curl_exit)
                }
                if ($report.stage -eq 'https_transport') {
                    $numeric = [string]$report.curl_exit
                    if ($numeric -match '^[0-9]{1,3}$' -and [int]$numeric -le 255) {
                        Write-Output ('CI_HTTPS_PREFLIGHT_CURL_EXIT:' + $numeric)
                    }
                }
                if ($report.stage -eq 'https_transport') {
                    if ($report.curl_backend -in @('schannel', 'openssl', 'unknown')) {
                        Write-Output ('CI_HTTPS_CURL_BACKEND:' + $report.curl_backend)
                    }
                    if ($report.curl_source -in @('system32', 'git', 'other')) {
                        Write-Output ('CI_HTTPS_CURL_SOURCE:' + $report.curl_source)
                    }
                    if ($report.tls_hint -in @('unknown', 'untrusted_root', 'revocation', 'hostname', 'algorithm', 'handshake_alert', 'schannel_other')) {
                        Write-Output ('CI_HTTPS_TLS_HINT:' + $report.tls_hint)
                    }
                    $tlsHex = [string]$report.tls_hresult
                    if ($tlsHex -match '^0x[0-9a-f]{8}$') {
                        Write-Output ('CI_HTTPS_TLS_HRESULT:' + $tlsHex)
                    }
                    $noRevoke = [string]$report.no_revocation_exit
                    if ($noRevoke -match '^[0-9]{1,3}$' -and [int]$noRevoke -le 255) {
                        Write-Output ('CI_HTTPS_NO_REVOCATION_EXIT:' + $noRevoke)
                    }
                }
                if ($report.failure_type -match '^[A-Za-z0-9_]{1,64}$') {
                    Write-Output ('CI_INSTALLER_FAILURE_TYPE:' + $report.failure_type)
                }
                if ($report.failure_id -match '^[A-Za-z0-9_]{1,64}$') {
                    Write-Output ('CI_INSTALLER_FAILURE_ID:' + $report.failure_id)
                }
                if ($report.failure_command -in @('GetReleaseFile', 'SetAcl', 'other')) {
                    Write-Output ('CI_INSTALLER_FAILURE_COMMAND:' + $report.failure_command)
                }
                throw 'Standard-user signed installer failed its assertions.'
            }
            if ($OnlyTask) {
                Write-Output 'PASS: isolated non-admin Windows Scheduled Task probe'
            } elseif ($OnlyCredential) {
                Write-Output 'PASS: isolated non-admin Windows credential process probe'
            } else {
                Write-Output 'PASS: isolated non-admin Windows signed Agent install'
            }
            return
        }
        if (!$OnlyTask -and $workerProcess -and $workerProcess.HasExited) {
            $stage = 'worker_exited_without_report'
            throw 'Standard-user worker exited without producing a report.'
        }
        Start-Sleep -Milliseconds 500
    }
    $stage = 'worker_timeout'
    if ($OnlyTask) { try {
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
    } }
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
    if ($workerProcess -and !$workerProcess.HasExited) {
        Stop-Process -Id $workerProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($createdTask) {
        try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($OnlyCredential -and !$createdTask) {
        # An interrupted standard-user registration probe may leave an owned
        # task behind. Never touch unrelated tasks with the same name.
        try {
            $fixtureTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($fixtureTask -and $fixtureTask.Description -eq 'Disposable CommandCore CI logon task probe') {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            }
        } catch {
            Write-Output 'CI_TASK_DIAGNOSTIC:cleanup_failed'
            throw 'Disposable task cleanup failed (redacted).'
        }
    }
    if ($createdUser) {
        Remove-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    }
}
