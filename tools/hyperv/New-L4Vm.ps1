<#
.SYNOPSIS
Creates the Hyper-V Generation 2 VM that boots microL4 disk images.

.DESCRIPTION
Run once, from an elevated PowerShell or as a member of Hyper-V Administrators.
The VM gets 512 MB of memory, one vCPU with processor compatibility mode off
(the kernel needs SMEP and SMAP), Secure Boot off (the loader is unsigned),
COM1 on a named pipe, no automatic checkpoints, and a copy of the VHDX as its
first boot device. Swap in later images with Set-L4Vhdx.ps1, or boot and check one
in a single step with Test-L4Vhdx.ps1.

.EXAMPLE
.\New-L4Vm.ps1 -VhdxPath .\disk.vhdx
#>
[CmdletBinding()]
param(
    # The VHDX to start with, for example the CI artifact.
    [Parameter(Mandatory)] [string] $VhdxPath,
    [string] $VMName = 'l4',
    # A virtual switch, for networking from M9. Pass '' for no network adapter.
    [string] $SwitchName = 'Default Switch',
    [string] $PipeName = 'l4-com1',
    # Where the VM's own copy of the disk lives.
    [string] $DiskPath = (Join-Path $env:USERPROFILE 'microl4\l4.vhdx')
)
$ErrorActionPreference = 'Stop'

if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "VM '$VMName' already exists. Use Set-L4Vhdx.ps1 to swap its disk, or remove it with Remove-VM first."
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DiskPath) | Out-Null
Copy-Item -Force -LiteralPath $VhdxPath -Destination $DiskPath
# A downloaded artifact carries the mark of the web, which Hyper-V can refuse.
Unblock-File -LiteralPath $DiskPath

$vmArgs = @{ Name = $VMName; Generation = 2; MemoryStartupBytes = 512MB; VHDPath = $DiskPath }
if ($SwitchName) { $vmArgs.SwitchName = $SwitchName }
New-VM @vmArgs | Out-Null

# Checkpoints would put a differencing disk in front of the VHDX we swap.
Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false -CheckpointType Disabled
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName)
Set-VMComPort -VMName $VMName -Number 1 -Path "\\.\pipe\$PipeName"
# One vCPU, and the host CPU's features as they are: processor compatibility
# mode hides SMEP and SMAP, without which the kernel refuses to boot (M3).
Set-VMProcessor -VMName $VMName -Count 1 -CompatibilityForMigrationEnabled $false

Write-Host "Created VM '$VMName' with disk $DiskPath and COM1 on \\.\pipe\$PipeName."
Write-Host "Boot and check an image with: .\Test-L4Vhdx.ps1 -VhdxPath <disk.vhdx>"
