using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace NetUlta;

static class DirectRouteWatch
{
    const int InsufficientBuffer = 122;
    const int RowBytes = 14 * sizeof(int); // MIB_IPFORWARDROW: fourteen DWORDs.
    static readonly IPAddress GlobalIPv6 = IPAddress.Parse("2001:4860:4860::8888");

    internal static string Snapshot(DirectNetwork net, int ignoredInterface)
    {
        if (TcpTransport.BestInterface(GlobalIPv6) != 0)
            throw new UserFault("Появился внешний маршрут IPv6. Прямой режим поддерживает только IPv4.");
        var adapters = NetworkInterface.GetAllNetworkInterfaces();
        if (!HasAddress(net.Physical, net.PhysicalAddress) || !HasAddress(net.Vpn, net.VpnAddress))
            throw new UserFault("Интерфейс провайдера или AmneziaVPN сменил IPv4-адрес.");

        int size = 0;
        int status = GetIpForwardTable(IntPtr.Zero, ref size, false);
        if (status != InsufficientBuffer || size is < 4 or > 1_048_576) throw InvalidRoutes();
        // Allow room for route changes between the size query and the read.
        size += 4096;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpForwardTable(buffer, ref size, false) != 0) throw InvalidRoutes();
            int rows = Marshal.ReadInt32(buffer);
            if (rows < 0 || rows > (size - 4) / RowBytes) throw InvalidRoutes();
            var snapshot = new List<string>();
            for (int i = 0; i < rows; ++i)
            {
                IntPtr row = IntPtr.Add(buffer, 4 + RowBytes * i);
                int index = Marshal.ReadInt32(row, 16);
                if (index == ignoredInterface) continue;
                int destination = Marshal.ReadInt32(row);
                int mask = Marshal.ReadInt32(row, 4);
                bool relevant = index == net.VpnIndex || index == net.PhysicalIndex || (destination == 0 && mask == 0);
                if (!relevant) continue;
                int nextHop = Marshal.ReadInt32(row, 12);
                int metric = Marshal.ReadInt32(row, 36);
                snapshot.Add($"{index}/{destination}/{mask}/{nextHop}/{metric}");
            }
            snapshot.Sort(StringComparer.Ordinal);
            return string.Join('\n', snapshot);
        }
        finally { Marshal.FreeHGlobal(buffer); }

        bool HasAddress(string name, string ip) => adapters.Any(adapter => adapter.Name == name && adapter.OperationalStatus == OperationalStatus.Up &&
            adapter.GetIPProperties().UnicastAddresses.Any(address => address.Address.ToString() == ip));
    }

    static UserFault InvalidRoutes() => new("Не удалось перепроверить маршруты Windows. Проверьте сеть и повторите запуск.");

    [DllImport("iphlpapi.dll")]
    static extern int GetIpForwardTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order);
}
