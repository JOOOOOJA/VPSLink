using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetUlta;

static class InternetProbe
{
    static readonly IPAddress Destination = IPAddress.Parse("1.1.1.1");
    static readonly Uri Url = new("https://1.1.1.1/cdn-cgi/trace");

    public static async Task<string> Run(Profile profile, CancellationToken ct)
    {
        if (profile.ProtectedVpnConfig.Length == 0)
            throw new UserFault("Для проверки выхода в интернет импортируйте профиль .conf в VPSLink.");
        var config = Setup.Open(profile, profile.ProtectedVpnConfig, "vpn-config");
        var addresses = ClientAddresses(config);
        int route = TcpTransport.BestInterface(Destination);
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
        {
            if (n.OperationalStatus != OperationalStatus.Up) return false;
            var props = n.GetIPProperties();
            return props.GetIPv4Properties()?.Index == route &&
                props.UnicastAddresses.Any(a => addresses.Contains(a.Address));
        });
        if (adapter == null)
            throw new UserFault("Маршрут до 1.1.1.1 проходит вне активного профиля AmneziaWG. Проверьте, что профиль включён и содержит этот адрес в AllowedIPs.");
        var source = adapter.GetIPProperties().UnicastAddresses.First(a => addresses.Contains(a.Address)).Address;
        using var handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, MaxResponseHeadersLength = 8,
            ConnectCallback = async (context, token) =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    if (TcpTransport.BestInterface(Destination) != route)
                        throw new IOException("Маршрут до тестового адреса изменился.");
                    socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder(route));
                    socket.Bind(new IPEndPoint(source, 0));
                    await socket.ConnectAsync(new IPEndPoint(Destination, context.DnsEndPoint.Port), token);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            } };
        using var http = new HttpClient(handler) { MaxResponseContentBufferSize = 8192, Timeout = TimeSpan.FromSeconds(10) };
        try
        {
            string body = await http.GetStringAsync(Url, ct);
            var line = body.Split('\n').FirstOrDefault(value => value.StartsWith("ip=", StringComparison.Ordinal));
            if (line == null || !IPAddress.TryParse(line[3..].Trim(), out var ip))
                throw new UserFault("HTTPS ответил, но адрес выхода определить не удалось.");
            return $"HTTPS через {adapter.Name} работает. Адрес выхода: {ip}.";
        }
        catch (HttpRequestException e) when (e.GetBaseException() is SocketException { SocketErrorCode: SocketError.AccessDenied })
        {
            throw new UserFault($"Windows заблокировала HTTPS через {adapter.Name} (10013 AccessDenied). Проверьте сетевые фильтры WARP и Amnezia.");
        }
        catch (HttpRequestException)
        {
            throw new UserFault($"HTTPS через {adapter.Name} не прошёл. Проверьте маршрутизацию и выход в интернет на VPS.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new UserFault($"HTTPS через {adapter.Name} не ответил за 10 секунд.");
        }
    }

    internal static HashSet<IPAddress> ClientAddresses(string config)
    {
        var addresses = new HashSet<IPAddress>();
        bool inInterface = false;
        foreach (var raw in config.Split('\n'))
        {
            string line = raw.Split('#', 2)[0].Trim();
            if (line.StartsWith('[')) inInterface = line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase);
            if (!inInterface) continue;
            int equal = line.IndexOf('=');
            if (equal < 0 || !line[..equal].Trim().Equals("Address", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (string value in line[(equal + 1)..].Split(','))
                if (IPAddress.TryParse(value.Split('/', 2)[0].Trim(), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                    addresses.Add(ip);
        }
        return addresses;
    }
}
