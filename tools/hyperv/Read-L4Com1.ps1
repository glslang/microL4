<#
.SYNOPSIS
Copies the microL4 VM's COM1 output to the console until a marker line or a
timeout.

.DESCRIPTION
Hyper-V serves COM1 as a named pipe while the VM runs. This connects to it,
retrying until the pipe exists, strips terminal escape sequences, and stops at
the first line containing one of the -StopOn markers: the same markers the
QEMU scenarios use. It returns an object with the marker found (or $null on a
timeout) and every line read, and writes the lines to -LogPath if given.

.EXAMPLE
Start-VM l4; .\Read-L4Com1.ps1 -LogPath com1.log
#>
[CmdletBinding()]
param(
    [string] $PipeName = 'l4-com1',
    [int] $TimeoutSeconds = 60,
    [string] $LogPath,
    [string[]] $StopOn = @('TEST PASS', 'TEST FAIL', 'KERNEL PANIC', 'LOADER ERROR', 'LOADER PANIC')
)
$ErrorActionPreference = 'Stop'

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$escape = [regex]"$([char]27)\[[0-9;?]*[ -/]*[@-~]|$([char]27)[ -/]*[0-~]"
$lines = [System.Collections.Generic.List[string]]::new()
$marker = $null

$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
try {
    while ($true) {
        try {
            $pipe.Connect(500)
            break
        } catch [System.TimeoutException], [System.IO.IOException] {
            if ((Get-Date) -gt $deadline) {
                throw "COM1 pipe \\.\pipe\$PipeName did not appear within $TimeoutSeconds s. Is the VM running?"
            }
        }
    }

    $reader = [System.IO.StreamReader]::new($pipe, [System.Text.Encoding]::ASCII)
    while ($null -eq $marker) {
        $remaining = $deadline - (Get-Date)
        if ($remaining -le [TimeSpan]::Zero) { break }
        $read = $reader.ReadLineAsync()
        if (-not $read.Wait($remaining)) { break }
        if ($null -eq $read.Result) { break } # the VM stopped
        $line = $escape.Replace($read.Result, '').TrimEnd("`r")
        Write-Host $line
        $lines.Add($line)
        foreach ($m in $StopOn) {
            if ($line.Contains($m)) { $marker = $m; break }
        }
    }
} finally {
    $pipe.Dispose()
}

if ($LogPath) {
    $lines | Set-Content -Encoding ascii -LiteralPath $LogPath
}
[pscustomobject]@{ Marker = $marker; Lines = $lines }
