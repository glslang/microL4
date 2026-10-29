<#
.SYNOPSIS
Swaps a new microL4 VHDX into the VM made by New-L4Vm.ps1.

.DESCRIPTION
Turns the VM off if it is running, detaches its disk, copies the new VHDX over
the VM's copy, attaches it again and makes it the first boot device.
Re-attaching, rather than overwriting the file in place, lets Hyper-V grant
the VM's account access to the new file.

.EXAMPLE
.\Set-L4Vhdx.ps1 -VhdxPath .\disk.vhdx
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VhdxPath,
    [string] $VMName = 'l4',
    [string] $DiskPath = (Join-Path $env:USERPROFILE 'microl4\l4.vhdx')
)
$ErrorActionPreference = 'Stop'

$vm = Get-VM -Name $VMName
if ($vm.State -ne 'Off') {
    Stop-VM -Name $VMName -TurnOff -Force
}

Get-VMHardDiskDrive -VMName $VMName | Remove-VMHardDiskDrive
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DiskPath) | Out-Null
Copy-Item -Force -LiteralPath $VhdxPath -Destination $DiskPath
Unblock-File -LiteralPath $DiskPath
$drive = Add-VMHardDiskDrive -VMName $VMName -ControllerType SCSI -Path $DiskPath -Passthru
Set-VMFirmware -VMName $VMName -FirstBootDevice $drive

Write-Host "VM '$VMName' now boots $DiskPath (copied from $VhdxPath)."
