# Deterministic negative matrix; safe on Windows CI and any offline host.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_interactive_vm_platform_validation.ps1')

function New-Platform {
    return [pscustomobject]@{
        OperatingSystem = 'Windows_NT'
        BuildNumber = '26100'
        ProductType = '1'
        CpuArchitecture = '9'
        Manufacturer = 'Microsoft Corporation'
        Model = 'Virtual Machine'
        Native64Bit = $true
    }
}
$script:denied = 0
function Assert-Platform {
    param($Candidate,[string]$Expected)
    $found = Test-CommandCoreVmPlatform -OperatingSystem $Candidate.OperatingSystem `
        -BuildNumber $Candidate.BuildNumber -ProductType $Candidate.ProductType `
        -CpuArchitecture $Candidate.CpuArchitecture -Manufacturer $Candidate.Manufacturer `
        -Model $Candidate.Model -Native64Bit $Candidate.Native64Bit
    if ($found -cne $Expected) {
        throw ('VM platform matrix expected ' + $Expected + ', found ' + $found)
    }
    if ($Expected -cne 'valid') { $script:denied++ }
}
Assert-Platform (New-Platform) 'valid'
$p=New-Platform; $p.Model='VMware Virtual Platform'; Assert-Platform $p 'valid'
$p=New-Platform; $p.Manufacturer='QEMU'; $p.Model='Standard PC'; Assert-Platform $p 'valid'
$p=New-Platform; $p.OperatingSystem='Linux'; Assert-Platform $p 'windows_only'
$p=New-Platform; $p.BuildNumber='19045'; Assert-Platform $p 'windows_11_required'
$p=New-Platform; $p.BuildNumber='no-build'; Assert-Platform $p 'windows_11_required'
$p=New-Platform; $p.BuildNumber='100000'; Assert-Platform $p 'windows_11_required'
$p=New-Platform; $p.ProductType='3'; Assert-Platform $p 'windows_workstation_required'
$p=New-Platform; $p.ProductType='2'; Assert-Platform $p 'windows_workstation_required'
$p=New-Platform; $p.CpuArchitecture='12'; Assert-Platform $p 'native_x64_required'
$p=New-Platform; $p.CpuArchitecture='0'; Assert-Platform $p 'native_x64_required'
$p=New-Platform; $p.Native64Bit=$false; Assert-Platform $p 'native_x64_required'
$p=New-Platform; $p.Manufacturer='Dell'; $p.Model='Optiplex'; Assert-Platform $p 'virtual_machine_not_detected'
$p=New-Platform; $p.Model=''; Assert-Platform $p 'virtual_machine_not_detected'
Write-Output ('PASS: ' + $script:denied + ' invalid Windows VM platforms denied; three x64 VM cases passed')
