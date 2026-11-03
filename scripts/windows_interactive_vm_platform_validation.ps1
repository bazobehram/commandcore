# Pure offline check: only Windows 11 x86_64 desktop VMs can close M3.
# No shell execution, Scheduler mutation, network access, or PII output.
function Test-CommandCoreVmPlatform {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$OperatingSystem,
        [Parameter(Mandatory)][AllowEmptyString()][string]$BuildNumber,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ProductType,
        [Parameter(Mandatory)][AllowEmptyString()][string]$CpuArchitecture,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Manufacturer,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Model,
        [Parameter(Mandatory)][bool]$Native64Bit
    )
    if ($OperatingSystem -cne 'Windows_NT') {
        return 'windows_only'
    }
    $build = 0
    if (![int]::TryParse($BuildNumber, [ref]$build) -or
        $build -lt 22000 -or $build -gt 99999) {
        return 'windows_11_required'
    }
    # Win32_OperatingSystem.ProductType: 1=workstation, 2/3=server.
    if ($ProductType -cne '1') {
        return 'windows_workstation_required'
    }
    # Win32_Processor.Architecture: 9=x64; 12=ARM64, 0=x86.
    if ($CpuArchitecture -cne '9' -or !$Native64Bit) {
        return 'native_x64_required'
    }
    $fingerprint = ($Manufacturer + ' ' + $Model)
    if ($fingerprint -notmatch '(?i)virtual.machine|vmware|virtualbox|qemu|kvm|parallels|hyper-v|virtual.platform|bochs|hvm domu') {
        return 'virtual_machine_not_detected'
    }
    return 'valid'
}
