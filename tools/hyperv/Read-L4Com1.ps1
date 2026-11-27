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

-OnConnect, -OnLine and -OnIdle let Test-L4Vhdx.ps1 -Scenario type into
COM1 and take the screen: -OnConnect runs once the pipe is connected,
-OnLine after each line is read and before the markers are checked, and
-OnIdle each second that passes with no line. Each gets the pipe, -OnLine
the line first; each returns lines (strings) to log, which are not checked
for markers.

Without -Raw the script reads the pipe a line at a time, so while it
cleans, shows and checks one line, or runs a callback, nothing reads the
pipe. With -Raw <file>, .NET's Stream.CopyToAsync copies the pipe's bytes
into that file as they come, through a 1 MiB buffer, on .NET's own I/O
threads: no work per line, and never waiting on this script. The script
reads the lines back from the file as it grows and handles each as it
would without -Raw, ending them at CR LF, CR or LF as .NET's ReadLine
does. The file keeps every byte as it came, escape sequences and all. At
the M9 check, a line cut with the normal reader but whole with -Raw means
the reader fell behind the pipe.

.EXAMPLE
Start-VM l4; .\Read-L4Com1.ps1 -LogPath com1.log

.EXAMPLE
Start-VM l4; .\Read-L4Com1.ps1 -LogPath com1.log -Raw com1.raw
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
    [scriptblock] $OnLine,
    # { param($pipe) ... }, each second with no line.
    [scriptblock] $OnIdle,
    # A file the pipe's bytes are copied to as they come, off this
    # script's thread; the lines are read back from it.
    [string] $Raw
)
$ErrorActionPreference = 'Stop'

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$escape = [regex]"$([char]27)\[[0-9;?]*[ -/]*[@-~]|$([char]27)[ -/]*[0-~]"
# What is left of the other control characters but tab, as xtask's clean().
$control = [regex]'[\x00-\x08\x0A-\x1F\x7F]'
$lines = [System.Collections.Generic.List[string]]::new()
$marker = $null
# With -Raw: the file the copy writes, the copy, and the file read back.
$rawFile = $null
$copy = $null
$tail = $null

# Cleans one line read from COM1, shows and keeps it, runs -OnLine, and
# returns the first marker it contains, or $null.
function Add-L4Line([string] $Text, $Pipe) {
    $line = $control.Replace($escape.Replace($Text, ''), '')
    Write-Host $line
    $lines.Add($line)
    if ($OnLine) {
        foreach ($note in @(& $OnLine $line $Pipe)) {
            Write-Host $note
            $lines.Add($note)
        }
    }
    foreach ($m in $StopOn) {
        if ($line.Contains($m)) { return $m }
    }
    return $null
}

# Runs -OnIdle, if given, and keeps the lines it returns.
function Invoke-L4Idle($Pipe) {
    if ($OnIdle) {
        foreach ($note in @(& $OnIdle $Pipe)) {
            Write-Host $note
            $lines.Add($note)
        }
    }
}

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
    if ($Raw) {
        # Before -OnConnect, which may wait: the copy starts as soon as the
        # pipe connects. A buffer of 1 byte is none, so each block the copy
        # writes reaches the file at once.
        $rawPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Raw)
        $rawFile = [System.IO.FileStream]::new($rawPath, [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 1)
        $copy = $pipe.CopyToAsync($rawFile, 1MB)
        $tail = [System.IO.FileStream]::new($rawPath, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite, 1)
    }
    if ($OnConnect) {
        foreach ($note in @(& $OnConnect $pipe)) {
            Write-Host $note
            $lines.Add($note)
        }
    }

    if (-not $Raw) {
        $reader = [System.IO.StreamReader]::new($pipe, [System.Text.Encoding]::ASCII)
        $second = [TimeSpan]::FromSeconds(1)
        # The line being read: one read at a time, kept across -OnIdle's waits.
        $read = $null
        while ($null -eq $marker) {
            $remaining = $deadline - (Get-Date)
            if ($remaining -le [TimeSpan]::Zero) { break }
            if ($null -eq $read) { $read = $reader.ReadLineAsync() }
            $wait = if ($OnIdle -and $remaining -gt $second) { $second } else { $remaining }
            if (-not $read.Wait($wait)) {
                Invoke-L4Idle $pipe
                continue
            }
            $text = $read.Result
            $read = $null
            if ($null -eq $text) { break } # the VM stopped
            $marker = Add-L4Line $text $pipe
        }
    } else {
        $buffer = [byte[]]::new(64KB)
        $ends = [char[]] @("`r", "`n")
        # What the file holds past the last whole line.
        $pending = ''
        # When the last line came, for -OnIdle.
        $quiet = Get-Date
        while ($null -eq $marker) {
            # Checked on every pass, so a guest that never stops printing
            # still meets it.
            if ((Get-Date) -gt $deadline) { break }
            # Whether the copy had ended before this read: once the VM stops
            # and the pipe closes, a read that finds nothing new is the end.
            $ended = $copy.IsCompleted
            $n = $tail.Read($buffer, 0, $buffer.Length)
            if ($n -gt 0) {
                $pending += [System.Text.Encoding]::ASCII.GetString($buffer, 0, $n)
            }
            while ($null -eq $marker) {
                $i = $pending.IndexOfAny($ends)
                if ($i -lt 0) { break }
                $cr = $pending[$i] -eq [char] "`r"
                # A CR last may be the start of CR LF: wait for what follows.
                if ($cr -and $i + 1 -eq $pending.Length -and -not $ended) { break }
                $skip = if ($cr -and $i + 1 -lt $pending.Length -and $pending[$i + 1] -eq [char] "`n") { 2 } else { 1 }
                $text = $pending.Substring(0, $i)
                $pending = $pending.Substring($i + $skip)
                $marker = Add-L4Line $text $pipe
                $quiet = Get-Date
            }
            if ($n -gt 0) { continue }
            if ($ended) {
                # The VM stopped; a last line with no end is still a line.
                if ($null -eq $marker -and $pending -ne '') { $marker = Add-L4Line $pending $pipe }
                break
            }
            if (((Get-Date) - $quiet).TotalSeconds -ge 1) {
                Invoke-L4Idle $pipe
                $quiet = Get-Date
            }
            Start-Sleep -Milliseconds 50
        }
    }
} finally {
    $pipe.Dispose()
    if ($copy) {
        # Disposing the pipe ends the copy, or the VM's stop will: wait a
        # little for its last block, but never for long.
        try { [void] $copy.Wait(2000) } catch { }
    }
    if ($tail) { $tail.Dispose() }
    if ($rawFile) { $rawFile.Dispose() }
    # Even when a callback failed: the log is what the PR needs.
    if ($LogPath) {
        $lines | Set-Content -Encoding ascii -LiteralPath $LogPath
    }
}
[pscustomobject]@{ Marker = $marker; Lines = $lines }
