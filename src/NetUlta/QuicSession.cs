using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetUlta;

enum DataRoute { ProfileSettings, Automatic, DirectQuic, WarpHttps }

sealed record QuicEgress(IPAddress Host, IPAddress Source, int Index, string AdapterId)
{
    public static async Task<QuicEgress> Resolve(Profile profile, CancellationToken ct)
    {
        var host = (await Dns.GetHostAddressesAsync(profile.Host).WaitAsync(ct))
            .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        if (host == null) throw new UserFault("Для прямого QUIC нужен IPv4-адрес VPS.", false);
        var physical = LocalUdpAddress.Adapters().Where(n => n.Supports(NetworkInterfaceComponent.IPv4)).Select(n =>
        {
            var properties = n.GetIPProperties();
            var source = properties.UnicastAddresses.Select(a => a.Address).FirstOrDefault(a =>
                LocalUdpAddress.IsUnicastV4(a) && !IPAddress.IsLoopback(a) &&
                !(a.GetAddressBytes()[0] == 169 && a.GetAddressBytes()[1] == 254));
            return (Adapter: n, Index: source == null ? 0 : properties.GetIPv4Properties()?.Index ?? 0, Source: source);
        }).Where(n => n.Source != null && n.Index > 0).ToArray();
        var preferred = physical.FirstOrDefault(n => n.Adapter.Id == profile.AdapterId);
        if (preferred.Adapter == null)
        {
            int route = TcpTransport.BestInterface(host);
            preferred = physical.FirstOrDefault(n => n.Index == route);
        }
        if (preferred.Adapter == null && WarpCore.Registered)
        {
            try
            {
                int outer = TcpTransport.BestInterface(WarpCore.ReadEndpoint());
                preferred = physical.FirstOrDefault(n => n.Index == outer);
            }
            catch (Exception e) when (e is UserFault or IOException or JsonException or UnauthorizedAccessException) { }
        }
        if (preferred.Adapter == null && physical.Length == 1) preferred = physical[0];
        if (preferred.Adapter == null)
            throw new UserFault("Выберите Ethernet, Wi-Fi или мобильный адаптер для прямого QUIC.", false);
        return new(host, preferred.Source!, preferred.Index, preferred.Adapter.Id);
    }
}

sealed class QuicSession : IDisposable
{
    internal const string Name = "Прямой QUIC DATAGRAM";
    const string Protocol = "vpslink-datagram/1";
    static readonly string Executable = Path.Combine(AppContext.BaseDirectory, "quic", "vpslink-quic.exe");
    static readonly string ServerImage = Path.Combine(AppContext.BaseDirectory, "quic", "vpslink-quic-linux.gz");
    readonly Process child;
    public Wire Wire { get; }
    public static bool Available => File.Exists(Executable) && File.Exists(ServerImage);

    QuicSession(Process child)
    {
        this.child = child;
        Wire = new Wire(SshSession.BufferOutput(child.StandardOutput.BaseStream), child.StandardInput.BaseStream);
        child.ErrorDataReceived += (_, _) => { };
        child.BeginErrorReadLine();
    }

    public static async Task<QuicSession> Open(SshSession ssh, QuicEgress egress, CancellationToken ct)
    {
        if (!Available) throw new UserFault("В сборке отсутствует модуль QUIC.", false);
        using var uploadDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        uploadDeadline.CancelAfter(TimeSpan.FromSeconds(55));
        using var abortUpload = uploadDeadline.Token.Register(ssh.Interrupt);
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            await using var image = File.OpenRead(ServerImage);
            if (image.Length is < 1 or > 8 * 1024 * 1024) throw new IOException("Неверный размер модуля QUIC.");
            var buffer = new byte[60 * 1024];
            while (true)
            {
                int count = await image.ReadAsync(buffer, uploadDeadline.Token);
                if (count == 0) break;
                await ssh.Wire.Send('B', buffer.AsMemory(0, count), uploadDeadline.Token);
            }
            var token = Convert.ToHexString(key);
            await ssh.Wire.Send('Q', Encoding.ASCII.GetBytes(token), uploadDeadline.Token);
            var info = await ssh.Wire.Read(uploadDeadline.Token);
            if (info.Type != 'Q') throw new IOException("VPS не подтвердил запуск QUIC.");
            var ready = JsonSerializer.Deserialize<QuicReady>(info.Payload);
            if (ready is not { Port: > 0 and <= 65535, Pin.Length: 64 } || !ready.Pin.All(Uri.IsHexDigit))
                throw new UserFault("VPS не смог запустить временный UDP-вход QUIC.", false);
            uploadDeadline.CancelAfter(Timeout.InfiniteTimeSpan);
            var child = Process.Start(SshSession.StartInfo(Executable, "client"))
                ?? throw new IOException("Не удалось запустить клиент QUIC.");
            var session = new QuicSession(child);
            try
            {
                using var probe = CancellationTokenSource.CreateLinkedTokenSource(ct);
                probe.CancelAfter(TimeSpan.FromSeconds(7));
                using var interrupt = probe.Token.Register(session.Interrupt);
                var settings = JsonSerializer.Serialize(new
                {
                    Key = token, ready.Pin, ready.Port, Host = egress.Host.ToString(),
                    Source = egress.Source.ToString(), Interface = egress.Index,
                });
                await child.StandardInput.WriteLineAsync(settings.AsMemory(), probe.Token);
                await child.StandardInput.FlushAsync();
                var hello = await session.Wire.Read(probe.Token);
                if (hello.Type != 'H' || !hello.Payload.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(Protocol)))
                    throw new IOException("QUIC не подтвердил подлинность соединения.");
                var challenge = RandomNumberGenerator.GetBytes(8);
                await session.Wire.Send('P', challenge, probe.Token);
                var ack = await session.Wire.Read(probe.Token);
                if (ack.Type != 'P' || !ack.Payload.AsSpan().SequenceEqual(challenge))
                    throw new IOException("Проверка двустороннего QUIC DATAGRAM не прошла.");
                return session;
            }
            catch { session.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public void Interrupt() => SshSession.Kill(child);
    public void Dispose()
    {
        Interrupt();
        child.Dispose();
    }

    sealed record QuicReady(int Port, string Pin);
}
