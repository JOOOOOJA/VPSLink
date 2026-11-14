using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NetUlta;

sealed class HttpsTransport : ITransport
{
    readonly Profile profile;
    readonly ITransport? upstream;
    public HttpsTransport(Profile profile, ITransport? upstream = null)
    {
        this.profile = profile;
        this.upstream = upstream;
    }
    public string Name => upstream == null ? "HTTPS-шлюз SSH" : "HTTPS-шлюз SSH через " + upstream.Name;

    internal static bool TryEndpoint(string value, out Uri? endpoint)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out endpoint) && endpoint.Scheme is "https" or "wss" &&
            Model.IsHost(endpoint.IdnHost.Trim('[', ']')) && endpoint.UserInfo.Length == 0 &&
            endpoint.Query.Length == 0 && endpoint.Fragment.Length == 0 &&
            Regex.IsMatch(endpoint.AbsolutePath, @"\A/[a-zA-Z0-9/_-]{1,128}\z"))
            return true;
        endpoint = null;
        return false;
    }

    internal static bool IsToken(string value) => Regex.IsMatch(value, @"\A[A-Za-z0-9_-]{43}\z");

    public async Task<Stream> Connect(string host, int port, CancellationToken ct)
    {
        if (!TryEndpoint(profile.HttpsRelay, out var endpoint) || endpoint == null)
            throw new UserFault("Неверный HTTPS-адрес шлюза SSH.");
        string token = Setup.Open(profile, profile.ProtectedRelayToken, "https-relay");
        if (!IsToken(token)) throw new UserFault("Проверьте токен HTTPS-шлюза.");
        string address = endpoint.IdnHost.Trim('[', ']');
        var network = await (upstream ?? new TcpTransport(profile.AdapterId)).Connect(address, endpoint.Port, ct);
        var tls = new SslStream(network, leaveInnerStreamOpen: false);
        try
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = address,
                ApplicationProtocols = new() { SslApplicationProtocol.Http11 }
            }, ct);
            string? websocketKey = endpoint.Scheme == "wss" ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)) : null;
            string upgrade = websocketKey == null ? "Upgrade: tfl-ssh\r\n" :
                $"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {websocketKey}\r\n";
            string request = $"GET {endpoint.AbsolutePath} HTTP/1.1\r\nHost: {endpoint.Authority}\r\n" +
                $"Connection: Upgrade\r\n{upgrade}Authorization: Bearer {token}\r\n\r\n";
            await tls.WriteAsync(Encoding.ASCII.GetBytes(request), ct);
            await ReadUpgrade(tls, websocketKey, ct);
            return websocketKey == null ? tls : new WebSocketStream(WebSocket.CreateFromStream(
                tls, isServer: false, subProtocol: null, keepAliveInterval: TimeSpan.FromSeconds(15)));
        }
        catch (AuthenticationException)
        {
            tls.Dispose();
            throw new UserFault("HTTPS-шлюз не прошёл проверку TLS. Проверьте адрес и сертификат сервера.", false);
        }
        catch { tls.Dispose(); throw; }
    }

    internal static async Task ReadUpgrade(Stream stream, string? websocketKey, CancellationToken ct)
    {
        var header = new byte[8192];
        for (int length = 1; length <= header.Length; length++)
        {
            await Wire.ReadFull(stream, header.AsMemory(length - 1, 1), ct);
            if (length < 4 || header[length - 4] != 13 || header[length - 3] != 10 ||
                header[length - 2] != 13 || header[length - 1] != 10) continue;

            var lines = Encoding.ASCII.GetString(header, 0, length).Split("\r\n");
            var status = lines[0].Split(' ', 3);
            string protocol = websocketKey == null ? "tfl-ssh" : "websocket";
            string? accept = websocketKey == null ? null : Convert.ToBase64String(SHA1.HashData(
                Encoding.ASCII.GetBytes(websocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            if (status.Length >= 2 && status[0] == "HTTP/1.1" && status[1] == "101" &&
                lines.Skip(1).Any(line => line.StartsWith("Upgrade:", StringComparison.OrdinalIgnoreCase) &&
                    line[8..].Trim().Equals(protocol, StringComparison.OrdinalIgnoreCase)) &&
                lines.Skip(1).Any(line => line.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase) &&
                    line[11..].Split(',').Any(part => part.Trim().Equals("upgrade", StringComparison.OrdinalIgnoreCase))) &&
                (accept == null || lines.Skip(1).Count(line => line.StartsWith("Sec-WebSocket-Accept:", StringComparison.OrdinalIgnoreCase)) == 1 &&
                    lines.Skip(1).Any(line => line.StartsWith("Sec-WebSocket-Accept:", StringComparison.OrdinalIgnoreCase) && line[21..].Trim() == accept)))
                return;
            if (status.Length >= 2 && status[1] is "401" or "403" or "404")
                throw new UserFault("HTTPS-шлюз отклонил запрос. Проверьте его адрес и токен.", false);
            break;
        }
        throw new UserFault("HTTPS-шлюз не открыл канал SSH.", false);
    }
}

// SSH is a byte stream; WebSocket message boundaries have no meaning to it.
sealed class WebSocketStream : Stream
{
    readonly WebSocket socket;
    readonly SemaphoreSlim writeGate = new(1, 1);
    public WebSocketStream(WebSocket socket) => this.socket = socket;
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).GetAwaiter().GetResult();
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.Length == 0) return 0;
        try
        {
            while (true)
            {
                var result = await socket.ReceiveAsync(buffer, ct);
                if (result.MessageType == WebSocketMessageType.Close) return 0;
                if (result.MessageType != WebSocketMessageType.Binary) throw new IOException("Шлюз прислал текст вместо SSH.");
                if (result.Count != 0) return result.Count;
            }
        }
        catch (WebSocketException ex) { throw new IOException("Канал WebSocket прервался.", ex); }
    }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.Length == 0) return;
        await writeGate.WaitAsync(ct);
        try { await socket.SendAsync(buffer, WebSocketMessageType.Binary, true, ct); }
        catch (WebSocketException ex) { throw new IOException("Канал WebSocket прервался.", ex); }
        finally { writeGate.Release(); }
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) socket.Dispose();
        base.Dispose(disposing);
    }
}
