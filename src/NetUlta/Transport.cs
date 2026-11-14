using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;

namespace NetUlta;

interface ITransport
{
    string Name { get; }
    Task<Stream> Connect(string host, int port, CancellationToken ct);
}
sealed class TcpTransport : ITransport
{
    readonly string adapterId;
    public TcpTransport(string adapterId = "") { this.adapterId = adapterId; }
    public string Name => adapterId.Length == 0 ? "Системный маршрут (прямой, WARP или активный zapret)" :
        "Адаптер: " + (Model.Interfaces().FirstOrDefault(n => n.Id == adapterId)?.Name ?? "недоступен");

    public async Task<Stream> Connect(string host, int port, CancellationToken ct)
        => new NetworkStream(await ConnectSocket(host, port, ct), ownsSocket: true);

    internal async Task<Socket> ConnectSocket(string host, int port, CancellationToken ct)
    {
        var addresses = IPAddress.TryParse(host, out var literal)
            ? new[] { literal } : await Dns.GetHostAddressesAsync(host).WaitAsync(ct);
        var adapter = adapterId.Length == 0 ? null : NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.Id == adapterId && n.OperationalStatus == OperationalStatus.Up);
        if (adapter == null && adapterId.Length != 0)
            throw new UserFault("Выбранный сетевой адаптер сейчас недоступен.", false);
        Exception? last = null;
        foreach (var address in addresses.Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6).Take(8))
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                if (!IPAddress.IsLoopback(address))
                    BindEgress(socket, address, adapter);
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(TimeSpan.FromSeconds(4));
                await socket.ConnectAsync(new IPEndPoint(address, port), attempt.Token);
                return socket;
            }
            catch (Exception ex) when (ex is SocketException or NetworkInformationException or UserFault or OperationCanceledException)
            { socket.Dispose(); ct.ThrowIfCancellationRequested(); last = ex; }
            catch { socket.Dispose(); throw; }
        }
        if (last is UserFault fault) throw fault;
        if (last is SocketException { SocketErrorCode: SocketError.AccessDenied })
            throw new UserFault("Windows запретила TCP-подключение по выбранному пути.", false);
        throw new UserFault("Нет TCP-доступа до адреса по выбранному пути.", false);
    }
    static void BindEgress(Socket socket, IPAddress address, NetworkInterface? requested)
    {
        bool v4 = address.AddressFamily == AddressFamily.InterNetwork;
        int Index(NetworkInterface n)
        {
            try
            {
                var props = n.GetIPProperties();
                return (v4 ? props.GetIPv4Properties()?.Index : props.GetIPv6Properties()?.Index) ?? 0;
            }
            catch (NetworkInformationException) { return 0; }
        }
        int index;
        if (requested == null)
        {
            index = BestInterface(address);
            if (index <= 0)
                throw new UserFault("Windows не нашла маршрут до адреса.", false);
            requested = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
                n.OperationalStatus == OperationalStatus.Up && Index(n) == index);
            if (requested == null)
                throw new UserFault("Не удалось проверить адаптер системного маршрута.", false);
            if (!KnownOuter(requested) && requested.NetworkInterfaceType is not
                    (NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or
                    NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ppp or
                    NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2))
                throw new UserFault("Системный маршрут проходит через другой туннель. Выберите внешний адаптер или прокси в профиле.", false);
        }
        else index = Index(requested);
        var label = requested.Name + " " + requested.Description;
        if (label.Contains("Amnezia", StringComparison.OrdinalIgnoreCase) ||
            (!KnownOuter(requested) && label.Contains("WireGuard Tunnel", StringComparison.OrdinalIgnoreCase)))
            throw new UserFault("Внешний SSH нельзя направить через адаптер внутреннего VPN. Выберите WARP, прокси или другой внешний адаптер.", false);
        if (index <= 0) throw new UserFault("На выбранном адаптере нет интерфейса нужной версии IP.", false);
        // IP_UNICAST_IF and IPV6_UNICAST_IF. Pin each TCP socket without writing global routes.
        socket.SetSocketOption(v4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
            (SocketOptionName)31, v4 ? IPAddress.HostToNetworkOrder(index) : index);
    }

    static bool KnownOuter(NetworkInterface n) => (n.Name + " " + n.Description)
        .Replace(" ", "").Contains("CloudflareWARP", StringComparison.OrdinalIgnoreCase);

    internal static int BestInterface(IPAddress address)
    {
        var addr = new IPEndPoint(address, 0).Serialize();
        var bytes = Enumerable.Range(0, addr.Size).Select(i => addr[i]).ToArray();
        return GetBestInterfaceEx(bytes, out int index) == 0 ? index : 0;
    }

    [DllImport("iphlpapi.dll")]
    static extern uint GetBestInterfaceEx(byte[] destination, out int index);
}

sealed class ProxyTransport : ITransport
{
    readonly Profile p;
    public ProxyTransport(Profile p) { this.p = p; }
    public string Name => p.Proxy == ProxyKind.Socks5 ? "SOCKS5" : "HTTP CONNECT";

    public async Task<Stream> Connect(string host, int port, CancellationToken ct)
    {
        var stream = await new TcpTransport().Connect(p.ProxyHost, p.ProxyPort, ct);
        try
        {
            if (p.Proxy == ProxyKind.Socks5) await Socks(stream, host, port, ct);
            else await Http(stream, host, port, ct);
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }
    static async Task Socks(Stream s, string host, int port, CancellationToken ct)
    {
        await s.WriteAsync(new byte[] { 5, 1, 0 }, ct);
        var reply = new byte[4];
        await Wire.ReadFull(s, reply.AsMemory(0, 2), ct);
        if (reply[0] != 5 || reply[1] != 0) throw new UserFault("SOCKS5 требует авторизацию или не поддерживает этот режим.", false);
        byte[] addr;
        byte type;
        if (IPAddress.TryParse(host, out var ip))
        {
            type = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
            addr = ip.GetAddressBytes();
        }
        else { type = 3; addr = new[] { (byte)host.Length }.Concat(Encoding.ASCII.GetBytes(host)).ToArray(); }
        var request = new byte[] { 5, 1, 0, type }.Concat(addr).Concat(new[] { (byte)(port >> 8), (byte)port }).ToArray();
        await s.WriteAsync(request, ct);
        await Wire.ReadFull(s, reply, ct);
        if (reply[0] != 5 || reply[1] != 0 || reply[2] != 0)
            throw new UserFault($"SOCKS5 не открыл соединение с VPS (код {reply[1]}).", false);
        int len;
        if (reply[3] == 3) { await Wire.ReadFull(s, reply.AsMemory(0, 1), ct); len = reply[0]; }
        else len = reply[3] switch { 1 => 4, 4 => 16, _ => throw new IOException("SOCKS5 reply") };
        await Wire.ReadFull(s, new byte[len + 2], ct);
    }
    static async Task Http(Stream s, string host, int port, CancellationToken ct)
    {
        string authority = host.Contains(':') ? $"[{host}]:{port}" : $"{host}:{port}";
        await s.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"), ct);
        var header = new List<byte>();
        var next = new byte[1];
        while (header.Count < 16384)
        {
            await Wire.ReadFull(s, next, ct);
            header.Add(next[0]);
            int n = header.Count;
            if (n >= 4 && header[n - 4] == 13 && header[n - 3] == 10 && header[n - 2] == 13 && header[n - 1] == 10)
            {
                var first = Encoding.ASCII.GetString(header.ToArray()).Split('\r')[0].Split(' ');
                if (first.Length > 1 && first[0].StartsWith("HTTP/1.", StringComparison.Ordinal) &&
                    int.TryParse(first[1], out int status))
                {
                    if (status is >= 200 and < 300) return;
                    throw new UserFault($"Прокси отклонил CONNECT к SSH (HTTP {status}).", false);
                }
                break;
            }
        }
        throw new UserFault("Ответ HTTP CONNECT не распознан.", false);
    }
}
sealed class LoopbackBridge : IDisposable
{
    readonly TcpListener listener = new(IPAddress.Loopback, 0);
    readonly Stream transport;
    readonly CancellationTokenSource lifetime;
    readonly Task copy;
    public int Port { get; }
    LoopbackBridge(Stream transport, CancellationToken ct)
    {
        this.transport = transport;
        lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        listener.Server.ExclusiveAddressUse = true;
        listener.Start(1);
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        copy = Copy(lifetime.Token);
    }
    public static async Task<LoopbackBridge> Open(ITransport t, Profile p, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var stream = await t.Connect(p.Host, p.SshPort, timeout.Token);
        try { return new LoopbackBridge(stream, ct); } catch { stream.Dispose(); throw; }
    }
    async Task Copy(CancellationToken ct)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync(ct);
            listener.Stop();
            client.NoDelay = true;
            using var a = client.GetStream();
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var outgoing = a.CopyToAsync(transport, 32 * 1024, cancel.Token);
            var incoming = transport.CopyToAsync(a, 32 * 1024, cancel.Token);
            await Task.WhenAny(outgoing, incoming);
            cancel.Cancel();
            await Task.WhenAll(outgoing, incoming);
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
    }
    public void Dispose()
    {
        lifetime.Cancel();
        listener.Stop();
        transport.Dispose();
        _ = copy.ContinueWith(t => { _ = t.Exception; lifetime.Dispose(); }, TaskScheduler.Default);
    }
}


