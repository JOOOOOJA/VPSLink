using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetUlta;

static class LocalUdpAddress
{
    internal static bool IsUnicastV4(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork &&
        address.GetAddressBytes()[0] is > 0 and < 224 && !address.Equals(IPAddress.Broadcast);

    // An explicit adapter prevents a live VPN's default route from becoming
    // the "Internet" interface used by Amnezia's application exclusions.
    public static NetworkInterface[] Adapters() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up &&
            n.NetworkInterfaceType is (NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or
                NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2) &&
            n.GetIPProperties().GatewayAddresses.Any(g => IsUnicastV4(g.Address)) &&
            !new[] { "virtual", "wireguard", "amnezia", "warp", "tailscale", "tap-windows" }
                .Any(word => (n.Name + " " + n.Description).Contains(word, StringComparison.OrdinalIgnoreCase)))
        .ToArray();

    public static IPAddress Resolve(string adapterId)
    {
        if (adapterId.Length == 0) return IPAddress.Loopback;
        var adapter = Adapters().SingleOrDefault(n => n.Id == adapterId)
            ?? throw new UserFault("Адаптер раздельного туннелирования недоступен. Подключите выбранный Ethernet/Wi-Fi или выберите другой в «VPN и UDP».");
        var addresses = adapter.GetIPProperties().UnicastAddresses.Select(a => a.Address)
            .Where(a => IsUnicastV4(a) && !IPAddress.IsLoopback(a) &&
                !(a.GetAddressBytes()[0] == 169 && a.GetAddressBytes()[1] == 254)).Distinct().ToArray();
        if (addresses.Length != 1) throw new UserFault("Для совместимости с AmneziaVPN нужен адаптер с одним рабочим IPv4-адресом.");
        return addresses[0];
    }
}
