# Pure, deterministic verification of disposable Windows VM logon evidence.
# Never reads from a host, runs commands, enrolls Agents, or reveals a SID/path.
function Test-CommandCoreVmLogonProof {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$Proof,
        [Parameter(Mandatory)]$TaskInfo,
        [Parameter(Mandatory)][string]$CurrentUserSid,
        [Parameter(Mandatory)][string]$CurrentLogonSid,
        [Parameter(Mandatory)][DateTimeOffset]$Now,
        [Parameter(Mandatory)][DateTimeOffset]$BootNow,
        [switch]$RequireReboot
    )
    if ($State.schema -ne 1 -or $Proof.schema -ne 1 -or
        [string]$State.nonce -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$State.user_sid -cne $CurrentUserSid -or
        [string]$Proof.user_sid -cne $CurrentUserSid -or
        [string]$Proof.nonce -cne [string]$State.nonce -or
        $Proof.non_admin -ne $true -or [int]$Proof.session_id -le 0) {
        return 'proof_invalid'
    }
    if ($CurrentLogonSid -notmatch '^S-1-5-5-\d+-\d+$' -or
        [string]$State.logon_sid -notmatch '^S-1-5-5-\d+-\d+$' -or
        [string]$Proof.logon_sid -cne $CurrentLogonSid -or
        [string]$Proof.logon_sid -ceq [string]$State.logon_sid) {
        return 'logon_identity_invalid'
    }
    try {
        $prepared = [DateTimeOffset]::Parse([string]$State.prepared_utc)
        $started = [DateTimeOffset]::Parse([string]$Proof.started_utc)
        $previousBoot = [DateTimeOffset]::Parse([string]$State.boot_utc)
        $lastRun = [DateTimeOffset]$TaskInfo.LastRunTime
    } catch {
        return 'timestamp_invalid'
    }
    if ($prepared -gt $Now -or $started -le $prepared.AddSeconds(2) -or
        $started -gt $Now.AddMinutes(1)) {
        return 'proof_timestamp_invalid'
    }
    if ($TaskInfo.LastTaskResult -ne 0 -or $lastRun -le $prepared -or
        $lastRun -gt $Now.AddMinutes(1)) {
        return 'scheduler_task_execution_unconfirmed'
    }
    if ($RequireReboot -and ($BootNow -le $previousBoot -or $started -lt $BootNow)) {
        return 'reboot_not_observed'
    }
    return 'valid'
}
