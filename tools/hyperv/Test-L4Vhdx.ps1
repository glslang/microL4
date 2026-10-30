<#
.SYNOPSIS
Boots a microL4 VHDX on Hyper-V and checks its COM1 output, like a QEMU
scenario.

.DESCRIPTION
Swaps the VHDX into the VM, starts it, reads COM1 until a marker line or the
timeout, then turns the VM off. It passes when the output contains every
-Expect string in order and ends with -Marker. The default expectations are
those of tests/qemu/hello.scenario, except the hypervisor line, which reads
Hyper-V here, and the Hyper-V detection line, which QEMU cannot print. The
log is written to -LogPath for pasting into the PR.

Exit status 0 means pass, 1 means fail.

.EXAMPLE
.\Test-L4Vhdx.ps1 -VhdxPath $HOME\Downloads\microl4-vhdx\disk.vhdx
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VhdxPath,
    [string] $VMName = 'l4',
    [string] $PipeName = 'l4-com1',
    [int] $TimeoutSeconds = 60,
    [string] $LogPath = ("l4-com1-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date)),
    [string] $Marker = 'TEST PASS',
    [string[]] $Expect = @(
        'loader: microL4 loader',
        'entering kernel',
        'microL4 kernel',
        'cpu: features NX PGE PAT SMEP SMAP XSAVE',
        'memory:',
        'cpu: hypervisor Hyper-V',
        'cmdline: "test=hello"',
        'hyperv: ',
        'apic: IA32_APIC_BASE',
        'timer: periodic at 100 Hz',
        'cpu: CR0',
        'cpu: meltdown:',
        'hello from microL4'
    )
)
$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'Set-L4Vhdx.ps1') -VhdxPath $VhdxPath -VMName $VMName
# Hyper-V drops COM1 output while no client is connected, and the loader's
# first line comes a few seconds into the boot. Start the VM as a job and go
# straight into the reader, whose connect loop waits for the pipe to appear.
$start = Start-VM -Name $VMName -AsJob
try {
    $result = & (Join-Path $PSScriptRoot 'Read-L4Com1.ps1') -PipeName $PipeName -TimeoutSeconds $TimeoutSeconds -LogPath $LogPath
} finally {
    # Surfaces a Start-VM failure, if there was one, then stops the VM.
    Receive-Job -Job $start -Wait -AutoRemoveJob | Out-Null
    Stop-VM -Name $VMName -TurnOff -Force
}

# Every expectation must appear after the previous one.
$missing = $null
$i = 0
foreach ($line in $result.Lines) {
    while ($i -lt $Expect.Count -and $line.Contains($Expect[$i])) { $i++ }
}
if ($i -lt $Expect.Count) { $missing = $Expect[$i] }

Write-Host ''
Write-Host "COM1 log: $LogPath"
if ($result.Marker -eq $Marker -and $null -eq $missing) {
    Write-Host 'PASS'
    exit 0
}
if ($null -ne $missing) {
    Write-Host "FAIL: never printed '$missing'"
} elseif ($null -eq $result.Marker) {
    Write-Host "FAIL: no marker line within $TimeoutSeconds s"
} else {
    Write-Host "FAIL: ended with '$($result.Marker)', expected '$Marker'"
}
exit 1
