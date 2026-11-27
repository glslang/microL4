<#
.SYNOPSIS
Pings the microL4 guest and sends it UDP datagrams to echo, as the QEMU
harness's udp_echo: does.

.DESCRIPTION
Pings -Address 4 times and prints each reply. Then sends -Count datagrams
to -Address port 7 from one System.Net.Sockets.UdpClient bound to the
host's address on the switch New-L4Switch.ps1 made, with xtask's payloads
(xtask/src/udp.rs): datagram k is 8, 9, 17, 18, 19, 64, 255, 256, 512,
952, 953, 1471 or 1472 bytes as k mod 13 is 0 to 12; bytes 0 to 3 are
'uL4E', 4 to 7 k as a little-endian 32-bit number, and byte j from 8 on
(k + 3j) mod 256. At most 8 go unanswered at a time, the next as each
echo arrives, with no retransmission. Each echo must come from -Address
port 7, equal an unanswered datagram's payload byte for byte, and answer
it once; anything else is a problem, printed. The exchange ends when all
are answered, after 5 s with no echo, or after 30 s in all.

It prints 'udp_echo: <n> sent, <k> echoed', with the missing indices when
k is short, then the guest's MAC as the host's neighbour table has it
(Get-NetNeighbor) beside the VM adapter's (Get-VMNetworkAdapter).

-PassThru returns an object with Count, Sent, Echoed, Missing, Problems,
Pings (the replies) and Lines (every line printed); -Quiet prints
nothing. Test-L4Vhdx.ps1 -Scenario runs it for a udp_echo: with both and
logs the lines itself.

.EXAMPLE
.\Send-L4Udp.ps1 -Address 192.168.77.2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Address,
    [ValidateRange(1, 1000)] [int] $Count = 100,
    [string] $VMName = 'l4',
    [string] $SwitchName = 'l4-net',
    [switch] $Quiet,
    [switch] $PassThru
)
$ErrorActionPreference = 'Stop'

$lines = [System.Collections.Generic.List[string]]::new()
function Out-L4([string] $Line) {
    $lines.Add($Line)
    if (-not $Quiet) { Write-Host $Line }
}

# Indices as ranges: 3, 17-99.
function Format-L4Ranges([int[]] $Indices) {
    $runs = [System.Collections.Generic.List[string]]::new()
    $i = 0
    while ($i -lt $Indices.Count) {
        $j = $i
        while ($j + 1 -lt $Indices.Count -and $Indices[$j + 1] -eq $Indices[$j] + 1) { $j++ }
        if ($j -eq $i) { $runs.Add("$($Indices[$i])") } else { $runs.Add("$($Indices[$i])-$($Indices[$j])") }
        $i = $j + 1
    }
    $runs -join ', '
}

# A MAC as the guest prints it: 00:15:5d:01:02:03.
function Format-L4Mac([string] $Mac) {
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
    if ($hex.Length -ne 12) { return $Mac }
    (0..5 | ForEach-Object { $hex.Substring(2 * $_, 2) }) -join ':'
}

$guest = [System.Net.IPAddress]::Parse($Address)
$hostIp = Get-NetIPAddress -InterfaceAlias "vEthernet ($SwitchName)" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $hostIp) {
    throw "The host has no IPv4 address on 'vEthernet ($SwitchName)'. Run New-L4Switch.ps1 first."
}

# Every payload first, so the exchange does no work but sending and checking.
$lengths = 8, 9, 17, 18, 19, 64, 255, 256, 512, 952, 953, 1471, 1472
$payloads = [System.Collections.Generic.List[byte[]]]::new()
for ($k = 0; $k -lt $Count; $k++) {
    $p = [byte[]]::new($lengths[$k % 13])
    $p[0] = 0x75; $p[1] = 0x4C; $p[2] = 0x34; $p[3] = 0x45 # uL4E
    $p[4] = [byte] ($k -band 255); $p[5] = [byte] (($k -shr 8) -band 255) # k < 65536: bytes 6 and 7 stay 0
    for ($j = 8; $j -lt $p.Length; $j++) { $p[$j] = [byte] (($k + 3 * $j) % 256) }
    $payloads.Add($p)
}
# The comparison: equal strings for equal bytes, without a loop per byte.
$wanted = @($payloads | ForEach-Object { [System.Convert]::ToBase64String($_) })

# Four pings, from the host's address on the switch, as routing picks it.
$pings = 0
$ping = [System.Net.NetworkInformation.Ping]::new()
try {
    for ($i = 1; $i -le 4; $i++) {
        $reply = $ping.Send($guest, 1000)
        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $pings++
            Out-L4 "ping ${Address}: reply $i, $($reply.Buffer.Length) bytes, $($reply.RoundtripTime) ms"
        } else {
            Out-L4 "ping ${Address}: request ${i}: $($reply.Status)"
        }
    }
} finally {
    $ping.Dispose()
}

$client = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($hostIp.IPAddress), 0))
$problems = [System.Collections.Generic.List[string]]::new()
$answered = [bool[]]::new($Count)
$sent = 0
$echoed = 0
$end = $null
try {
    # SIO_UDP_CONNRESET off: otherwise an ICMP port unreachable makes
    # Windows fail the next Receive with WSAECONNRESET.
    [void] $client.Client.IOControl(-1744830452, [byte[]] @(0, 0, 0, 0), $null)
    $target = [System.Net.IPEndPoint]::new($guest, 7)
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    # When the last datagram came back, or the start, in milliseconds.
    $last = 0
    while ($true) {
        while ($sent -lt $Count -and $sent - $echoed -lt 8) {
            [void] $client.Send($payloads[$sent], $payloads[$sent].Length, $target)
            $sent++
        }
        if ($echoed -eq $Count) { break }
        $now = $clock.ElapsedMilliseconds
        $idle = $last + 5000 - $now
        $total = 30000 - $now
        if ($idle -le 0) { $end = 'after 5 s with no echo'; break }
        if ($total -le 0) { $end = 'after 30 s in all'; break }
        $wait = [Math]::Min($idle, $total)
        if (-not $client.Client.Poll([int] ($wait * 1000), [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
        $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $echo = $client.Receive([ref] $from)
        $last = $clock.ElapsedMilliseconds
        if (-not ($from.Address.Equals($guest) -and $from.Port -eq 7)) {
            $problems.Add("an echo from $from, not from ${Address}:7")
            continue
        }
        if ($echo.Length -lt 8 -or $echo[0] -ne 0x75 -or $echo[1] -ne 0x4C -or $echo[2] -ne 0x34 -or $echo[3] -ne 0x45) {
            $problems.Add("an echo of $($echo.Length) bytes that begins as no datagram does")
            continue
        }
        $k = [BitConverter]::ToUInt32($echo, 4)
        if ($k -ge $sent) {
            $problems.Add("an echo of datagram $k, of $Count, which was never sent")
            continue
        }
        if ([System.Convert]::ToBase64String($echo) -cne $wanted[$k]) {
            $want = $payloads[$k]
            $how = "$($echo.Length) bytes, not $($want.Length)"
            for ($j = 0; $j -lt [Math]::Min($echo.Length, $want.Length); $j++) {
                if ($echo[$j] -ne $want[$j]) { $how = "byte $j differs"; break }
            }
            $problems.Add("an altered echo of datagram ${k}: $how")
            continue
        }
        if ($answered[$k]) {
            $problems.Add("a second echo of datagram $k")
            continue
        }
        $answered[$k] = $true
        $echoed++
    }
} finally {
    $client.Dispose()
}

$missing = @(for ($k = 0; $k -lt $Count; $k++) { if (-not $answered[$k]) { $k } })
$line = "udp_echo: $sent sent, $echoed echoed"
if ($echoed -lt $Count) {
    $line += "; missing $(Format-L4Ranges $missing) of $Count (ended $end)"
}
Out-L4 $line
foreach ($p in $problems) { Out-L4 "udp_echo: $p" }

$neighbour = Get-NetNeighbor -IPAddress $Address -ErrorAction SilentlyContinue | Select-Object -First 1
$adapter = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue | Select-Object -First 1
$seen = if ($neighbour) { Format-L4Mac $neighbour.LinkLayerAddress } else { 'no entry' }
$given = if ($adapter) { Format-L4Mac $adapter.MacAddress } else { 'no adapter' }
$same = if ($seen -eq $given) { 'the same' } else { 'they differ' }
Out-L4 "mac: the host's neighbour table has $Address at $seen; the adapter of VM '$VMName' has ${given}: $same"

if ($PassThru) {
    [pscustomobject]@{
        Count = $Count; Sent = $sent; Echoed = $echoed; Missing = $missing
        Problems = $problems.ToArray(); Pings = $pings; Lines = $lines.ToArray()
    }
}
