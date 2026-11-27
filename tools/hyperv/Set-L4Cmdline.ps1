<#
.SYNOPSIS
Rewrites the kernel command line in a microL4 VHDX.

.DESCRIPTION
For an owner whose network already uses the CI images' 192.168.77.0/24:
after New-L4Switch.ps1 -Subnet with another subnet, write the guest's
address into each image the M9 check boots. Mounts the VHDX (Mount-VHD),
gives its EFI system partition a drive letter, prints the \cmdline.txt it
finds there, writes -Cmdline in its place as one ASCII line, as xtask
does, and dismounts the VHDX. The VHDX must not be in use: run this on
the downloaded image, before Test-L4Vhdx.ps1 copies it into the VM.

Test-L4Vhdx.ps1 -Scenario sends a udp_echo: to the net.ip= of the
scenario's cmdline:, so change that line, and the expect: lines that name
the addresses, to match.

The Storage module's cmdlets are used here from memory, and this script
first runs at the M9 check: if it fails, paste its error into the PR.

.EXAMPLE
.\Set-L4Cmdline.ps1 -VhdxPath .\m9-check\net\disk.vhdx -Cmdline 'test=net net.ip=10.77.0.2/24 net.gw=10.77.0.1'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VhdxPath,
    [Parameter(Mandatory)] [string] $Cmdline
)
$ErrorActionPreference = 'Stop'

# The loader reads at most 256 bytes of \cmdline.txt and trims its ends
# (loader/src/main.rs).
if ($Cmdline.Length -gt 256 -or $Cmdline -cnotmatch '^[ -~]*$') {
    throw '-Cmdline must be printable ASCII, at most 256 characters'
}
$path = (Resolve-Path -LiteralPath $VhdxPath).ProviderPath
# A downloaded artifact carries the mark of the web, which can stop a mount.
Unblock-File -LiteralPath $path
Mount-VHD -Path $path
try {
    $number = (Get-VHD -Path $path).DiskNumber
    $esp = @(Get-Partition -DiskNumber $number |
        Where-Object GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}')
    if ($esp.Count -ne 1) { throw "$path has $($esp.Count) EFI system partitions, not 1" }
    if (-not [char]::IsLetter($esp[0].DriveLetter)) {
        $esp[0] | Add-PartitionAccessPath -AssignDriveLetter
    }
    $letter = (Get-Partition -DiskNumber $number -PartitionNumber $esp[0].PartitionNumber).DriveLetter
    if (-not [char]::IsLetter($letter)) { throw "the EFI system partition of $path got no drive letter" }
    $file = "${letter}:\cmdline.txt"
    $old = if (Test-Path -LiteralPath $file) { ([System.IO.File]::ReadAllText($file)).Trim() } else { '(none)' }
    [System.IO.File]::WriteAllText($file, "$Cmdline`n", [System.Text.Encoding]::ASCII)
    Write-Host "\cmdline.txt in ${path}, before: $old"
    Write-Host "\cmdline.txt in ${path}, now:    $Cmdline"
} finally {
    Dismount-VHD -Path $path
}
