<#
.SYNOPSIS
Copies the microL4 VM's COM1 output to the console until a marker line or a
timeout.

.DESCRIPTION
Hyper-V serves COM1 as a named pipe while the VM runs. This connects to it,
retrying until the pipe exists, strips terminal escape sequences and other
control characters, as the QEMU harness does, and stops at the first line
containing one of the -StopOn markers: the same markers the QEMU scenarios
use. It returns an object with the marker found (or $null on a timeout) and
every line read, and writes the lines to -LogPath if given.

-OnConnect and -OnLine let Test-L4Vhdx.ps1 -Scenario type into COM1 and
take the screen: -OnConnect runs once the pipe is connected, -OnLine after
each line is read and before the markers are checked. Each gets the pipe,
-OnLine the line first; each returns lines (strings) to log after the line,
which are not checked for markers.

.EXAMPLE
Start-VM l4; .\Read-L4Com1.ps1 -LogPath com1.log
#>
[CmdletBinding()]
param(
    [string] $PipeName = 'l4-com1',
    [int] $TimeoutSeconds = 60,
    [string] $LogPath,
    [string[]] $StopOn = @('TEST PASS', 'TEST FAIL', 'KERNEL PANIC', 'LOADER ERROR', 'LOADER PANIC'),
    # { param($pipe) ... }, once connected.
    [scriptblock] $OnConnect,
    # { param($line, $pipe) ... }, after each line.
    [scriptblock] $OnLine
)
$ErrorActionPreference = 'Stop'

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$escape = [regex]"$([char]27)\[[0-9;?]*[ -/]*[@-~]|$([char]27)[ -/]*[0-~]"
# What is left of the other control characters but tab, as xtask's clean().
$control = [regex]'[\x00-\x08\x0A-\x1F\x7F]'
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
        } catch [System.UnauthorizedAccessException] {
            throw "Access to \\.\pipe\$PipeName was denied. Run PowerShell as Administrator."
        }
    }
    if ($OnConnect) {
        foreach ($note in @(& $OnConnect $pipe)) {
            Write-Host $note
            $lines.Add($note)
        }
    }

    $reader = [System.IO.StreamReader]::new($pipe, [System.Text.Encoding]::ASCII)
    while ($null -eq $marker) {
        $remaining = $deadline - (Get-Date)
        if ($remaining -le [TimeSpan]::Zero) { break }
        $read = $reader.ReadLineAsync()
        if (-not $read.Wait($remaining)) { break }
        if ($null -eq $read.Result) { break } # the VM stopped
        $line = $control.Replace($escape.Replace($read.Result, ''), '')
        Write-Host $line
        $lines.Add($line)
        if ($OnLine) {
            foreach ($note in @(& $OnLine $line $pipe)) {
                Write-Host $note
                $lines.Add($note)
            }
        }
        foreach ($m in $StopOn) {
            if ($line.Contains($m)) { $marker = $m; break }
        }
    }
} finally {
    $pipe.Dispose()
    # Even when a callback failed: the log is what the PR needs.
    if ($LogPath) {
        $lines | Set-Content -Encoding ascii -LiteralPath $LogPath
    }
}
[pscustomobject]@{ Marker = $marker; Lines = $lines }
