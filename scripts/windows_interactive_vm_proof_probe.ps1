# Offline redacted negative test matrix; no Windows VM, Scheduler or Agent needed.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_interactive_vm_proof_validation.ps1')
$now = [DateTimeOffset]::Parse('2026-11-02T20:00:00Z')
$bootNow = [DateTimeOffset]::Parse('2026-11-02T19:00:30Z')
$uid = 'S-1-5-21-123-456-789-1001'
$previousLogon = 'S-1-5-5-10-20'
$currentLogon = 'S-1-5-5-30-40'
$nonce = '0123456789abcdef0123456789abcdef'
function New-State {
    [pscustomobject]@{
        schema=1;nonce=$nonce;user_sid=$uid;logon_sid=$previousLogon;
        prepared_utc='2026-11-02T19:00:00Z';boot_utc='2026-11-02T18:00:00Z'
    }
}
function New-Proof {
    [pscustomobject]@{
        schema=1;nonce=$nonce;user_sid=$uid;logon_sid=$currentLogon;
        started_utc='2026-11-02T19:01:00Z';non_admin=$true;session_id=2
    }
}
function New-TaskInfo {
    [pscustomobject]@{LastTaskResult=0;LastRunTime=[DateTimeOffset]::Parse('2026-11-02T19:00:55Z')}
}
$script:denied = 0
function Assert-Proof {
    param($State,$Proof,$TaskInfo,[string]$Expected,[bool]$Reboot=$false)
    $result = Test-CommandCoreVmLogonProof -State $State -Proof $Proof -TaskInfo $TaskInfo `
        -CurrentUserSid $uid -CurrentLogonSid $currentLogon -Now $now -BootNow $bootNow -RequireReboot:$Reboot
    if ($result -cne $Expected) {
        throw ('VM proof matrix mismatch: expected ' + $Expected + ', got ' + $result)
    }
    if ($Expected -cne 'valid') { $script:denied++ }
}
Assert-Proof (New-State) (New-Proof) (New-TaskInfo) 'valid'
Assert-Proof (New-State) (New-Proof) (New-TaskInfo) 'valid' $true
$s=New-State; $s.nonce='incorrect'; Assert-Proof $s (New-Proof) (New-TaskInfo) 'proof_invalid'
$s=New-State; $s.user_sid='S-1-5-32-544'; Assert-Proof $s (New-Proof) (New-TaskInfo) 'proof_invalid'
$p=New-Proof; $p.user_sid='S-1-5-32-544'; Assert-Proof (New-State) $p (New-TaskInfo) 'proof_invalid'
$p=New-Proof; $p.non_admin=$false; Assert-Proof (New-State) $p (New-TaskInfo) 'proof_invalid'
$p=New-Proof; $p.session_id=0; Assert-Proof (New-State) $p (New-TaskInfo) 'proof_invalid'
$p=New-Proof; $p.logon_sid=$previousLogon; Assert-Proof (New-State) $p (New-TaskInfo) 'logon_identity_invalid'
$p=New-Proof; $p.logon_sid='S-1-5-5-90-91'; Assert-Proof (New-State) $p (New-TaskInfo) 'logon_identity_invalid'
$p=New-Proof; $p.started_utc='not-a-date'; Assert-Proof (New-State) $p (New-TaskInfo) 'timestamp_invalid'
$p=New-Proof; $p.started_utc='2026-11-02T19:00:01Z'; Assert-Proof (New-State) $p (New-TaskInfo) 'proof_timestamp_invalid'
$p=New-Proof; $p.started_utc='2026-11-02T21:00:00Z'; Assert-Proof (New-State) $p (New-TaskInfo) 'proof_timestamp_invalid'
$t=New-TaskInfo; $t.LastTaskResult=1; Assert-Proof (New-State) (New-Proof) $t 'scheduler_task_execution_unconfirmed'
$t=New-TaskInfo; $t.LastRunTime=[DateTimeOffset]::Parse('2026-11-02T18:59:00Z'); Assert-Proof (New-State) (New-Proof) $t 'scheduler_task_execution_unconfirmed'
$t=New-TaskInfo; $t.LastRunTime=[DateTimeOffset]::Parse('2026-11-02T21:00:00Z'); Assert-Proof (New-State) (New-Proof) $t 'scheduler_task_execution_unconfirmed'
$s=New-State; $s.boot_utc='2026-11-02T19:01:00Z'; Assert-Proof $s (New-Proof) (New-TaskInfo) 'reboot_not_observed' $true
$p=New-Proof; $p.started_utc='2026-11-02T19:00:10Z'; Assert-Proof (New-State) $p (New-TaskInfo) 'reboot_not_observed' $true
Write-Output ('PASS: ' + $script:denied + ' invalid VM logon/reboot proofs denied; two valid cases passed')
