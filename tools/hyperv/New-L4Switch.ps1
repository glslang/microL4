<#
.SYNOPSIS
Puts the microL4 VM's network adapter on an internal switch with a fixed
subnet, for the M9 check.

.DESCRIPTION
Run once, from an elevated PowerShell. Creates the internal virtual switch
-SwitchName if there is none, gives the host's adapter on it,
'vEthernet (<SwitchName>)', the subnet's first address (192.168.77.1/24 by
default) and no other IPv4 address, and connects the VM's network adapter
to the switch, adding one, with the VM off, if it has none. The Default
Switch's NAT subnet changes when the host restarts; this one does not.
Run it again to change the subnet; it changes only what differs.

The CI images boot with net.ip=192.168.77.2/24 net.gw=192.168.77.1, the
default subnet's second and first addresses. If another of the host's
networks overlaps 192.168.77.0/24 the script stops and says so: pass
another -Subnet, then write the words it prints into each image with
Set-L4Cmdline.ps1.

Windows answers the guest's ARP request for the host's address, so the
guest learns the host's MAC. Its firewall may drop the guest's ping of the
host, which the check does not need; the host's ping of the guest and the
guest's UDP echoes come back as answers to the host's own requests.

.EXAMPLE
.\New-L4Switch.ps1

.EXAMPLE
.\New-L4Switch.ps1 -Subnet 10.77.0.0/24
#>
[CmdletBinding()]
param(
    [string] $VMName = 'l4',
    [string] $SwitchName = 'l4-net',
    # An IPv4 subnet with a prefix of 8 to 30, as net.ip= takes: the host
    # gets its first address, the guest its second.
    [string] $Subnet = '192.168.77.0/24'
)
$ErrorActionPreference = 'Stop'

# An IPv4 address as a number, or $null.
function ConvertTo-L4Number([string] $Ip) {
    if ($Ip -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $null }
    $value = [long] 0
    foreach ($i in 1..4) {
        $octet = [long] $Matches[$i]
        if ($octet -gt 255) { return $null }
        $value = $value * 256 + $octet
    }
    return $value
}

# A number as an IPv4 address.
function ConvertTo-L4Ip([long] $Value) {
    (@(24, 16, 8, 0) | ForEach-Object { ($Value -shr $_) -band 255 }) -join '.'
}

$bad = "-Subnet '$Subnet' is not an IPv4 subnet with a prefix of 8 to 30, such as 192.168.77.0/24"
$parts = $Subnet.Split('/')
if ($parts.Count -ne 2 -or $parts[1] -notmatch '^\d{1,2}$') { throw $bad }
$network = ConvertTo-L4Number $parts[0]
$length = [int] $parts[1]
if ($null -eq $network -or $length -lt 8 -or $length -gt 30) { throw $bad }
$size = [long] 1 -shl (32 - $length)
if ($network % $size -ne 0) {
    throw "-Subnet '$Subnet' has bits set past its /$length prefix; its network is $(ConvertTo-L4Ip ($network - $network % $size))/$length"
}
$hostIp = ConvertTo-L4Ip ($network + 1)
$guestIp = ConvertTo-L4Ip ($network + 2)
$alias = "vEthernet ($SwitchName)"

# No other network of the host's may overlap this one, or the host could
# not tell which way to send to the guest.
foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    if ($a.InterfaceAlias -eq $alias) { continue }
    $n = ConvertTo-L4Number $a.IPAddress
    if ($null -eq $n -or $a.PrefixLength -gt 32) { continue }
    $theirSize = [long] 1 -shl (32 - $a.PrefixLength)
    $theirs = $n - $n % $theirSize
    if ($theirs -lt $network + $size -and $network -lt $theirs + $theirSize) {
        throw "$Subnet overlaps '$($a.InterfaceAlias)', at $($a.IPAddress)/$($a.PrefixLength). Pass another -Subnet, then give each image its net.ip= and net.gw= with Set-L4Cmdline.ps1."
    }
}

$switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if (-not $switch) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Host "Created the internal switch '$SwitchName'."
} elseif ($switch.SwitchType -ne 'Internal') {
    throw "Switch '$SwitchName' exists but is $($switch.SwitchType), not Internal. Pass another -SwitchName."
}

# The host's adapter on the switch appears a moment after the switch.
$adapter = $null
for ($try = 0; $try -lt 20 -and -not $adapter; $try++) {
    $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
    if (-not $adapter) { Start-Sleep -Milliseconds 500 }
}
if (-not $adapter) { throw "The host's adapter '$alias' did not appear." }

# A fixed address: no DHCP, which would leave only a link-local one.
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled
$have = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
foreach ($a in $have) {
    if ($a.IPAddress -ne $hostIp -or $a.PrefixLength -ne $length) {
        $a | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
}
if (-not ($have | Where-Object { $_.IPAddress -eq $hostIp -and $_.PrefixLength -eq $length })) {
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $hostIp -PrefixLength $length | Out-Null
}

# The VM's adapter: netvsc takes one, so there must be one.
$nics = @(Get-VMNetworkAdapter -VMName $VMName)
if ($nics.Count -gt 1) {
    throw "VM '$VMName' has $($nics.Count) network adapters. Remove all but one (Remove-VMNetworkAdapter), then run this again."
}
if ($nics.Count -eq 0) {
    if ((Get-VM -Name $VMName).State -ne 'Off') { Stop-VM -Name $VMName -TurnOff -Force }
    Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName
} else {
    Connect-VMNetworkAdapter -VMNetworkAdapter $nics[0] -SwitchName $SwitchName
}

Write-Host "Switch '$SwitchName': the host is $hostIp/$length on '$alias', and VM '$VMName' has its network adapter on it."
$words = "net.ip=$guestIp/$length net.gw=$hostIp"
if ($words -eq 'net.ip=192.168.77.2/24 net.gw=192.168.77.1') {
    Write-Host "The CI images' $words fit it."
} else {
    Write-Host "The CI images boot with net.ip=192.168.77.2/24 net.gw=192.168.77.1: write '$words' in their place with Set-L4Cmdline.ps1, and change the scenario's cmdline: and the expect: lines that name the addresses to match."
}
