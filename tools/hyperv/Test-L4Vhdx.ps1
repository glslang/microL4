<#
.SYNOPSIS
Boots a microL4 VHDX on Hyper-V and checks its COM1 output, like a QEMU
scenario.

.DESCRIPTION
Swaps the VHDX into the VM, starts it, reads COM1 until a marker line or the
timeout, then turns the VM off. It passes when the output contains every
-Expect string in order and ends with -Marker. The default expectations are
the boot summary's lines that every test image prints, whatever its command
line, so they suit both CI images; pass -Expect for a test's own lines. The
log is written to -LogPath for pasting into the PR.

With -Scenario, a scenario file in the QEMU harness's format (from M8,
tools/hyperv/m8-*.scenario) replaces -Expect: its expect:, next:, send:,
forbid:, screendump: and udp_echo: lines are followed as `cargo xtask
test` follows them, over the named pipe. An expect: must appear after the
one before it, on a later line or further along the same one; a next: must
start the line right after its step's; a send: is typed into COM1 once
every expect: above it has matched, and the expects after it match from
the next line on; no line may contain a forbid: text. At a screendump:,
once the line above it has matched and before any later send:, the VM's
screen is saved through Hyper-V's thumbnail API at 1024x768 as
l4-<name>.png beside the log, with the API's raw RGB 565 bytes as
l4-<name>.rgb565. At a udp_echo: <n> (M9), once the line above it has
matched and before any later step, Send-L4Udp.ps1 pings the guest and
sends it n datagrams to echo, at the address of the net.ip= word in the
scenario's cmdline:; its lines are logged as l4: lines, and a datagram
missing or a bad echo fails the run. The guest prints nothing while the
datagrams go, so no COM1 line waits on the exchange. The scenario's
kernel:, exit:, timeout:, qemu_args: and nic: are QEMU's and are ignored,
and so is cmdline: but for net.ip=: the VHDX carries its own command line.

Unlike `cargo xtask test`, which ends the boot at a next: that fails, the
script records the failure and goes on from the next step that is not a
next:, on the same line, so the run, though failed, reaches the steps
after it and the log is whole: a flood line cut at the M9 check still
leaves uart's line and TEST PASS in the log.

-ConnectAfterSeconds starts the VM and opens the pipe only after that many
seconds, to see whether what uart wrote while no client was on the pipe
arrives once one connects. With -Scenario, the script then follows the
steps from the expect: right above the first send:, whose line may have
been printed with no client on the pipe: it types that send: when its own
expect: line arrives or, if it never does, once no line at all has come
for 10 seconds, and requires the steps after it. It reports how many of
the expect: lines above that send:, from the first that starts
'root: cmdline', arrived, each counted wherever it comes: those are uart's,
while the loader's polled writes give up on a transmitter that does not
drain, so its lines say nothing.

-Raw <file> has Read-L4Com1.ps1 copy COM1's bytes into that file as they
come, off the script's thread, and read the lines back from it, so COM1
never waits on the script's work per line (M9).

Exit status 0 means pass, 1 means fail.

.EXAMPLE
.\Test-L4Vhdx.ps1 -VhdxPath $HOME\Downloads\microl4-vhdx\disk.vhdx

.EXAMPLE
.\Test-L4Vhdx.ps1 -VhdxPath .\m8-check\tui\disk.vhdx -Scenario .\m8-check\m8-tui.scenario -LogPath m8-tui.log

.EXAMPLE
.\Test-L4Vhdx.ps1 -VhdxPath .\m9-com1\release-burst15\disk.vhdx -Scenario .\m9-com1\m9-release-burst15.scenario -LogPath m9-burst15-raw.log -Raw m9-burst15-raw.com1
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
        'hyperv: ',
        'apic: IA32_APIC_BASE',
        'timer: periodic at 100 Hz',
        'cpu: CR0',
        'cpu: meltdown:'
    ),
    # A scenario file, followed in place of -Expect.
    [string] $Scenario,
    # Start the VM, then open COM1's pipe only after this many seconds.
    [int] $ConnectAfterSeconds = 0,
    # A file COM1's bytes are copied to as they come (Read-L4Com1.ps1 -Raw).
    [string] $Raw
)
$ErrorActionPreference = 'Stop'

# A scenario value's escapes, as the QEMU harness's send: takes them: \r,
# \n, \t, \e (ESC), \\ and \xHH; any other character is its UTF-8 bytes.
function ConvertFrom-L4Escape([string] $Text) {
    $out = [System.Collections.Generic.List[byte]]::new()
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -ne [char]'\') {
            $out.AddRange([System.Text.Encoding]::UTF8.GetBytes([string] $c))
            continue
        }
        $i++
        if ($i -ge $Text.Length) { throw "a '\' ends the text" }
        switch -CaseSensitive ([string] $Text[$i]) {
            'r' { $out.Add(13) }
            'n' { $out.Add(10) }
            't' { $out.Add(9) }
            'e' { $out.Add(27) }
            '\' { $out.Add(92) }
            'x' {
                if ($i + 2 -ge $Text.Length -or $Text.Substring($i + 1, 2) -notmatch '^[0-9A-Fa-f]{2}$') {
                    throw "'\x' needs two hex digits"
                }
                $out.Add([Convert]::ToByte($Text.Substring($i + 1, 2), 16))
                $i += 2
            }
            default { throw "unknown escape '\$_'" }
        }
    }
    return , $out.ToArray()
}

# The steps of a scenario file: expect, next, send (with its bytes),
# screendump and udp_echo (with its count), in order, the forbid texts and
# the cmdline, checked as the QEMU harness checks them.
function Read-L4Scenario([string] $Path) {
    $steps = [System.Collections.Generic.List[object]]::new()
    $forbid = [System.Collections.Generic.List[string]]::new()
    $cmdline = ''
    $n = 0
    foreach ($raw in Get-Content -LiteralPath $Path) {
        $n++
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        $colon = $line.IndexOf(':')
        if ($colon -lt 0) { throw "${Path}:${n}: expected 'key: value'" }
        $key = $line.Substring(0, $colon).Trim()
        $value = $line.Substring($colon + 1)
        $comment = $value.IndexOf(' #')
        if ($comment -ge 0) { $value = $value.Substring(0, $comment) }
        $value = $value.Trim()
        $last = if ($steps.Count -gt 0) { $steps[$steps.Count - 1].Kind } else { '' }
        if ($key -eq 'cmdline') {
            # The VHDX has its own; a udp_echo: takes its net.ip= from this.
            $cmdline = $value
        } elseif ($key -in 'kernel', 'exit', 'timeout', 'qemu_args', 'nic') {
            # QEMU's: the VHDX has its own kernel, and the VM its adapter.
        } elseif ($value -eq '' -and $key -in 'expect', 'next', 'send', 'forbid', 'screendump') {
            throw "${Path}:${n}: empty $key line"
        } elseif ($key -eq 'expect') {
            $steps.Add([pscustomobject]@{ Kind = 'expect'; Text = $value })
        } elseif ($key -eq 'next') {
            if ($last -notin 'expect', 'next') { throw "${Path}:${n}: a next: needs an expect: or next: right above it" }
            $steps.Add([pscustomobject]@{ Kind = 'next'; Text = $value })
        } elseif ($key -eq 'send') {
            if (-not ($steps | Where-Object Kind -eq 'expect')) { throw "${Path}:${n}: a send: needs an expect: above it" }
            try { $bytes = ConvertFrom-L4Escape $value } catch { throw "${Path}:${n}: $_" }
            $steps.Add([pscustomobject]@{ Kind = 'send'; Text = $value; Bytes = $bytes })
        } elseif ($key -eq 'forbid') {
            $forbid.Add($value)
        } elseif ($key -eq 'screendump') {
            if ($last -notin 'expect', 'next') { throw "${Path}:${n}: a screendump: needs an expect: or next: right above it" }
            if ($value -cnotmatch '^[a-z0-9_-]+$') { throw "${Path}:${n}: a screendump's name is lowercase letters, digits, '-' and '_'" }
            $steps.Add([pscustomobject]@{ Kind = 'screendump'; Text = $value })
        } elseif ($key -eq 'udp_echo') {
            if ($last -notin 'expect', 'next') { throw "${Path}:${n}: a udp_echo: needs an expect: or next: right above it" }
            if ($value -notmatch '^[0-9]{1,4}$' -or [int] $value -lt 1 -or [int] $value -gt 1000) {
                throw "${Path}:${n}: udp_echo's count must be a number from 1 to 1000"
            }
            $steps.Add([pscustomobject]@{ Kind = 'udp_echo'; Text = $value; Count = [int] $value })
        } else {
            throw "${Path}:${n}: unknown key '$key'"
        }
    }
    if (-not ($steps | Where-Object Kind -eq 'expect')) { throw "${Path}: needs at least one expect:" }
    # A udp_echo: goes to the guest's address, the first net.ip= word's.
    $guest = $null
    if ($steps | Where-Object Kind -eq 'udp_echo') {
        $word = @($cmdline -split '\s+' | Where-Object { $_.StartsWith('net.ip=', [System.StringComparison]::Ordinal) })
        if ($word.Count -eq 0 -or $word[0] -notmatch '^net\.ip=(\d{1,3}(\.\d{1,3}){3})/\d{1,2}$') {
            throw "${Path}: a udp_echo: needs net.ip=<a.b.c.d>/<n> in the cmdline:, the guest's address"
        }
        $guest = $Matches[1]
    }
    [pscustomobject]@{ Steps = $steps; Forbid = $forbid; Guest = $guest }
}

# Saves the VM's screen through Msvm_VirtualSystemManagementService's
# GetVirtualSystemThumbnailImage, which returns the image as raw RGB 565:
# 2 bytes a pixel. The byte and row order are not documented; this takes
# them as Windows' Format16bppRgb565 does (little-endian words, red in the
# top 5 bits, rows from the top), and keeps the raw bytes beside the PNG
# in case that is wrong.
function Save-L4Screen([string] $VMName, [string] $Path, [int] $Width = 1024, [int] $Height = 768) {
    $ns = 'root\virtualization\v2'
    $id = (Get-VM -Name $VMName).Id.ToString()
    $vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$id'"
    $settings = Get-CimAssociatedInstance -InputObject $vm -Association Msvm_SettingsDefineState `
        -ResultClassName Msvm_VirtualSystemSettingData
    $service = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
    $out = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{
        TargetSystem = $settings; WidthPixels = [uint16] $Width; HeightPixels = [uint16] $Height
    }
    if ($out.ReturnValue -eq 4096) {
        # A job: wait for it to end.
        $job = $out.Job
        do {
            Start-Sleep -Milliseconds 200
            $job = Get-CimInstance -InputObject $job
        } while ($job.JobState -in 3, 4) # starting, running
        if ($job.JobState -ne 7) { throw "GetVirtualSystemThumbnailImage: job state $($job.JobState): $($job.ErrorDescription)" }
    } elseif ($out.ReturnValue -ne 0) {
        throw "GetVirtualSystemThumbnailImage returned $($out.ReturnValue)"
    }
    # Every byte the API returned is kept, before any check. The pixels are
    # its last 2 x width x height bytes: on the owner's host the buffer
    # starts with a 4-byte header (1,572,868 bytes for 1024x768), and with
    # it skipped the three M8 screens equal the goldens reduced to RGB 565
    # pixel for pixel. Microsoft's samples, which copy from the start, are
    # 2 pixels off.
    $data = [byte[]] $out.ImageData
    [System.IO.File]::WriteAllBytes([System.IO.Path]::ChangeExtension($Path, '.rgb565'), $data)
    $skip = $data.Length - 2 * $Width * $Height
    if ($skip -lt 0) {
        throw "GetVirtualSystemThumbnailImage gave $($data.Length) bytes, fewer than $(2 * $Width * $Height) for ${Width}x${Height} at 2 bytes a pixel"
    }

    Add-Type -AssemblyName System.Drawing
    $rect = [System.Drawing.Rectangle]::new(0, 0, $Width, $Height)
    $bmp = [System.Drawing.Bitmap]::new($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
    try {
        $bits = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, $bmp.PixelFormat)
        try {
            for ($y = 0; $y -lt $Height; $y++) {
                [System.Runtime.InteropServices.Marshal]::Copy(
                    [byte[]] $data, [int] ($skip + 2 * $Width * $y), [IntPtr]::Add($bits.Scan0, $bits.Stride * $y), [int] (2 * $Width))
            }
        } finally {
            $bmp.UnlockBits($bits)
        }
        # GDI+ saves a 16-bit bitmap as PNG unreliably; 24-bit is safe.
        $rgb = $bmp.Clone($rect, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
        try {
            $rgb.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $rgb.Dispose()
        }
    } finally {
        $bmp.Dispose()
    }
}

$logDir = Split-Path -Parent $LogPath
if (-not $logDir) { $logDir = '.' }
# Absolute, since .NET (WriteAllBytes, Bitmap.Save) resolves a relative
# path against the process's starting directory, not the current location.
$logDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($logDir)

# The scenario's state, which the reader's callbacks below advance.
$scn = $null
$onConnect = $null
$onLine = $null
$onIdle = $null
if ($Scenario) {
    $parsed = Read-L4Scenario $Scenario
    $scn = @{
        Steps = $parsed.Steps; Forbid = $parsed.Forbid; Next = 0
        Broken = $null; Forbidden = $null
        # The first screendump that could not be saved: the run goes on, so
        # the rest of the log is kept, but it fails.
        Unsaved = $null
        # The guest's address for a udp_echo:, and the first exchange that
        # failed, which fails the run the same way.
        Guest = $parsed.Guest; Udp = $null
        # With -ConnectAfterSeconds: the texts of uart's expects above the
        # first send, whether each arrived, the first send's step, when the
        # last line came (or the pipe connected), the seconds with no line
        # after which the first send is typed anyway, and whether it was.
        Early = @(); Seen = @(); FirstSend = -1; Quiet = $null; LateWait = 10; Late = $false
    }

    # Types a send's bytes into COM1.
    $send = {
        param($pipe, $step)
        $pipe.Write($step.Bytes, 0, $step.Bytes.Length)
        $pipe.Flush()
        "l4: sent $($step.Text)"
    }
    # Takes the screen for a screendump step.
    $dump = {
        param($step)
        $png = Join-Path $logDir "l4-$($step.Text).png"
        try {
            Save-L4Screen -VMName $VMName -Path $png
            $raw = [System.IO.Path]::ChangeExtension($png, '.rgb565')
            $extra = (Get-Item -LiteralPath $raw).Length - 2 * 1024 * 768
            "l4: screendump $($step.Text) saved as $png ($extra header bytes before the pixels, kept in $raw)"
        } catch {
            if ($null -eq $scn.Unsaved) { $scn.Unsaved = "could not save screendump $($step.Text): $_" }
            "l4: screendump $($step.Text) failed: $_"
        }
    }
    # Pings the guest and has it echo a udp_echo step's datagrams.
    $sendUdp = Join-Path $PSScriptRoot 'Send-L4Udp.ps1'
    $udp = {
        param($step)
        $count = $step.Count
        try {
            $r = & $sendUdp -Address $scn.Guest -Count $count -VMName $VMName -Quiet -PassThru
            foreach ($l in $r.Lines) { "l4: $l" }
            $bad = @($r.Problems)
            if ($null -eq $scn.Udp -and ($r.Echoed -lt $count -or $bad.Count -gt 0)) {
                $scn.Udp = "udp_echo ${count}: $($r.Echoed) of $count echoed"
                if ($bad.Count -gt 0) { $scn.Udp += ", and $($bad.Count) bad echoes, the first $($bad[0])" }
            }
        } catch {
            if ($null -eq $scn.Udp) { $scn.Udp = "udp_echo ${count}: $_" }
            "l4: udp_echo $count failed: $_"
        }
    }

    if ($ConnectAfterSeconds -gt 0) {
        # Only uart's lines can show whether the transmitter waited for a
        # client: the loader's polled writes give up after 100,000 polls a
        # byte (loader/src/serial.rs), and the release kernel prints
        # nothing, while uart, which writes on THRE interrupts, loses
        # nothing. On the release kernel its first expected line is the
        # root task's 'root: cmdline'.
        $steps = $scn.Steps
        $first = 0
        while ($first -lt $steps.Count -and $steps[$first].Kind -ne 'send') { $first++ }
        if ($first -ge $steps.Count) { throw "${Scenario}: -ConnectAfterSeconds needs a send:" }
        $above = @($steps[0..($first - 1)] | Where-Object Kind -eq 'expect')
        $from = 0
        while ($from -lt $above.Count -and -not $above[$from].Text.StartsWith('root: cmdline', [System.StringComparison]::Ordinal)) {
            $from++
        }
        if ($from -ge $above.Count) {
            throw "${Scenario}: -ConnectAfterSeconds needs an expect: starting 'root: cmdline' above the first send:"
        }
        $scn.Early = @($above[$from..($above.Count - 1)] | ForEach-Object Text)
        $scn.Seen = @($scn.Early | ForEach-Object { $false })
        # The steps start at the first send's own expect: the lines above
        # it may be gone.
        $own = $first - 1
        while ($steps[$own].Kind -ne 'expect') { $own-- }
        $scn.Next = $own
        $scn.FirstSend = $first

        $onConnect = {
            param($pipe)
            $scn.Quiet = Get-Date
            $own = $scn.Steps[$scn.Next].Text
            "l4: connected $ConnectAfterSeconds s after the start; the first send: waits for '$own', or $($scn.LateWait) s with no line"
        }
        # A transmitter that drained has dropped the line that releases the
        # first send, and by now the root task waits in its Read with
        # nothing more to print: type it once the pipe has been quiet for
        # LateWait seconds. One that waited sends its held lines as soon as
        # the pipe connects, and the boot's quiet stretches after that,
        # such as the release kernel's own start, should be far shorter.
        $onIdle = {
            param($pipe)
            if ($scn.Next -le $scn.FirstSend -and ((Get-Date) - $scn.Quiet).TotalSeconds -ge $scn.LateWait) {
                $scn.Late = $true
                "l4: no line for $($scn.LateWait) s; typing the first send: now"
                $i = $scn.FirstSend
                while ($i -lt $scn.Steps.Count -and $scn.Steps[$i].Kind -eq 'send') {
                    & $send $pipe $scn.Steps[$i]
                    $i++
                }
                $scn.Next = $i
            }
        }
    }

    # Advances the steps over one line, as xtask's Matcher::feed does.
    $onLine = {
        param($line, $pipe)
        if ($null -eq $scn.Forbidden) {
            foreach ($f in $scn.Forbid) {
                if ($line.Contains($f)) { $scn.Forbidden = "printed forbidden '$f' in '$line'"; break }
            }
        }
        $scn.Quiet = Get-Date
        for ($i = 0; $i -lt $scn.Early.Count; $i++) {
            if (-not $scn.Seen[$i] -and $line.Contains($scn.Early[$i])) { $scn.Seen[$i] = $true }
        }
        $steps = $scn.Steps
        $rest = $line
        $sent = $false
        $matched = $false
        while ($scn.Next -lt $steps.Count) {
            $step = $steps[$scn.Next]
            if ($step.Kind -eq 'expect') {
                if ($sent) { break }
                $at = $rest.IndexOf($step.Text, [System.StringComparison]::Ordinal)
                if ($at -lt 0) { break }
                $rest = $rest.Substring($at + $step.Text.Length)
                $matched = $true
            } elseif ($step.Kind -eq 'next') {
                if ($matched) { break }
                if (-not $line.StartsWith($step.Text, [System.StringComparison]::Ordinal)) {
                    $above = $steps[$scn.Next - 1].Text
                    if ($null -eq $scn.Broken) {
                        $scn.Broken = "printed '$line' right after the line with '$above', where a line starting '$($step.Text)' must come"
                    }
                    "l4: a next: failed here; going on from the next step that is not a next:"
                    # The run has failed; go on so the log reaches its end.
                    # Nothing on this line has matched, so the step after
                    # the next: lines may match all of it.
                    while ($scn.Next -lt $steps.Count -and $steps[$scn.Next].Kind -eq 'next') { $scn.Next++ }
                    continue
                }
                $rest = $line.Substring($step.Text.Length)
                $matched = $true
            } elseif ($step.Kind -eq 'send') {
                $sent = $true
                & $send $pipe $step
            } elseif ($step.Kind -eq 'udp_echo') {
                # As a send: what comes after it answers it.
                $sent = $true
                & $udp $step
            } else {
                & $dump $step
            }
            $scn.Next++
        }
    }
}

& (Join-Path $PSScriptRoot 'Set-L4Vhdx.ps1') -VhdxPath $VhdxPath -VMName $VMName
# Hyper-V drops COM1 output while no client is connected, and the loader's
# first line comes a few seconds into the boot. Start the VM as a job and go
# straight into the reader, whose connect loop waits for the pipe to appear,
# unless -ConnectAfterSeconds asks to wait first.
$start = Start-VM -Name $VMName -AsJob
try {
    if ($ConnectAfterSeconds -gt 0) {
        Write-Host "Waiting $ConnectAfterSeconds s before opening \\.\pipe\$PipeName."
        Start-Sleep -Seconds $ConnectAfterSeconds
    }
    $result = & (Join-Path $PSScriptRoot 'Read-L4Com1.ps1') -PipeName $PipeName -TimeoutSeconds $TimeoutSeconds `
        -LogPath $LogPath -OnConnect $onConnect -OnLine $onLine -OnIdle $onIdle -Raw $Raw
} finally {
    # Surfaces a Start-VM failure, if there was one, then stops the VM.
    Receive-Job -Job $start -Wait -AutoRemoveJob | Out-Null
    Stop-VM -Name $VMName -TurnOff -Force
}

$missing = $null
$why = $null
if ($scn) {
    if ($scn.Early.Count -gt 0) {
        Write-Host ''
        $arrived = "Of the {0} uart lines above the first send: (from 'root: cmdline'), {1} arrived once the pipe connected."
        Write-Host ($arrived -f $scn.Early.Count, @($scn.Seen | Where-Object { $_ }).Count)
        if ($scn.Late) {
            Write-Host "The first send: was typed after $($scn.LateWait) s with no line."
        } elseif ($scn.Next -gt $scn.FirstSend) {
            Write-Host 'The first send: was typed when its own expect: line arrived.'
        }
    }
    if ($scn.Broken) {
        $why = $scn.Broken
    } elseif ($scn.Forbidden) {
        $why = $scn.Forbidden
    } elseif ($scn.Unsaved) {
        $why = $scn.Unsaved
    } elseif ($scn.Udp) {
        $why = $scn.Udp
    } else {
        $waiting = @($scn.Steps | Select-Object -Skip $scn.Next | Where-Object Kind -in 'expect', 'next')
        if ($waiting.Count -gt 0) { $missing = $waiting[0].Text }
    }
} else {
    # Every expectation must appear after the previous one.
    $i = 0
    foreach ($line in $result.Lines) {
        while ($i -lt $Expect.Count -and $line.Contains($Expect[$i])) { $i++ }
    }
    if ($i -lt $Expect.Count) { $missing = $Expect[$i] }
}

Write-Host ''
Write-Host "COM1 log: $LogPath"
if ($result.Marker -eq $Marker -and $null -eq $missing -and $null -eq $why) {
    Write-Host 'PASS'
    exit 0
}
if ($null -ne $why) {
    Write-Host "FAIL: $why"
} elseif ($null -ne $missing) {
    Write-Host "FAIL: never printed '$missing'"
} elseif ($null -eq $result.Marker) {
    Write-Host "FAIL: no marker line within $TimeoutSeconds s"
} else {
    Write-Host "FAIL: ended with '$($result.Marker)', expected '$Marker'"
}
exit 1
