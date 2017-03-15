<#
.DESCRIPTION
     Name: wol.ps1
     Version: 1.0
     AUTHOR: ahubbard
     DATE  : 3/15/2017

.SYNOPSIS
     Wakes a physical machine with a Wake-on-Lan magic packet

.EXAMPLE
     <path>\wol.ps1

.NOTES
    Sanitized, replaced mac address with xx-xx-xx-xx-xx-xx

    Credit belongs to a couple WOL scripts found online which I borrowed peices from
#>

$MacAddress = [Net.NetworkInformation.PhysicalAddress]::Parse('xx-xx-xx-xx-xx-xx')

[byte[]]$MagicPacket = @(255,255,255,255,255,255)
$MagicPacket += ($MacAddress.GetAddressBytes()*16)

$UdpClient = New-Object Net.Sockets.UdpClient
$UdpClient.Connect(([System.Net.IPAddress]::Broadcast),0)
$UdpClient.Send($MagicPacket,$MagicPacket.Length) | Out-Null

# Most scripts only do port 7, but that was unrelable
$UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
$UdpClient.Send($MagicPacket,$MagicPacket.Length) | Out-Null

$UdpClient.Connect(([System.Net.IPAddress]::Broadcast),9)
$UdpClient.Send($MagicPacket,$MagicPacket.Length) | Out-Null
$UdpClient.Close()