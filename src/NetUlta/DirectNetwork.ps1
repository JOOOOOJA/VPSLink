$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore |
    Where-Object InterfaceAlias -ne 'VPSLink-Direct')
$vpn = @(Get-NetAdapter -Name 'AmneziaVPN' -ErrorAction SilentlyContinue | Where-Object Status -eq Up)
$defaults = @($routes | Where-Object {
    $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'AmneziaVPN'
})
if ($vpn.Count -ne 1 -or $defaults.Count -ne 1) { exit 3 }
$outside = Get-NetAdapter -InterfaceIndex $defaults[0].InterfaceIndex
if ($outside.Status -ne 'Up') { exit 3 }
$vpnIp = @(Get-NetIPAddress -InterfaceIndex $vpn[0].ifIndex -AddressFamily IPv4 | Where-Object AddressState -eq Preferred)
$outsideIp = @(Get-NetIPAddress -InterfaceIndex $outside.ifIndex -AddressFamily IPv4 | Where-Object AddressState -eq Preferred)
if ($vpnIp.Count -ne 1 -or $outsideIp.Count -ne 1) { exit 3 }
if (Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue) { exit 4 }

$protected = @($routes | Where-Object {
    $_.InterfaceIndex -ne $vpn[0].ifIndex -and $_.NextHop -ne '0.0.0.0' -and $_.DestinationPrefix -like '*/32'
} | ForEach-Object DestinationPrefix)
foreach ($ssh in Get-Process -Name ssh -ErrorAction SilentlyContinue) {
    $protected += @(Get-NetTCPConnection -OwningProcess $ssh.Id -State Established -ErrorAction SilentlyContinue | Where-Object {
        $_.RemoteAddress -notmatch ':|^127\.'
    } | ForEach-Object { $_.RemoteAddress + '/32' })
}
$prefixes = @($routes | Where-Object {
    $_.InterfaceIndex -eq $vpn[0].ifIndex -and $_.RouteMetric -eq 0 -and $_.NextHop -eq '0.0.0.0'
} | ForEach-Object DestinationPrefix | Sort-Object -Unique)
[pscustomobject]@{
    Physical = $outside.Name
    PhysicalAddress = $outsideIp[0].IPAddress
    PhysicalIndex = $outside.ifIndex
    Vpn = $vpn[0].Name
    VpnAddress = $vpnIp[0].IPAddress
    VpnIndex = $vpn[0].ifIndex
    Prefixes = $prefixes
    Protected = @($protected | Sort-Object -Unique)
} | ConvertTo-Json -Compress
