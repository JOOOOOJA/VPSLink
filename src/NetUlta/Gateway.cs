using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetUlta;

sealed record GatewayOptions(string Zone, string Hostname, string ApiToken);
sealed record GatewayReply(bool Ready, bool Persistent, string? Hostname, string? Error);

sealed class CloudflareGateway : IDisposable
{
    readonly HttpClient http;
    internal CloudflareGateway(HttpClient client) => http = client;
    public CloudflareGateway(ITransport transport, string apiToken)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false,
            ConnectCallback = async (context, ct) => await transport.Connect(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct)
        };
        http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
    }

    internal static void Validate(GatewayOptions o)
    {
        const string dns = @"\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z";
        if (o.Zone.Length > 253 || o.Hostname.Length > 253 || !Regex.IsMatch(o.Zone, dns) ||
            !Regex.IsMatch(o.Hostname, dns) || !o.Hostname.EndsWith("." + o.Zone, StringComparison.Ordinal))
            throw new UserFault("Введите домен Cloudflare и отдельный поддомен шлюза, например link.example.com.");
        if (!Regex.IsMatch(o.ApiToken, @"\A[A-Za-z0-9_-]{20,256}\z"))
            throw new UserFault("Введите API-токен Cloudflare с правами Tunnel Edit, DNS Edit и Zone Read.");
    }

    internal async Task<JsonElement> Api(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, "https://api.cloudflare.com/client/v4/" + path);
        if (body != null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode)
            throw new UserFault($"Cloudflare API вернул HTTP {(int)response.StatusCode}. Проверьте права токена и повторите настройку.");
        using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        if (!json.RootElement.TryGetProperty("success", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !json.RootElement.TryGetProperty("result", out var result))
            throw new UserFault("Cloudflare не подтвердил операцию. Настройки существующего подключения сохранены.");
        return result.Clone();
    }

    static string Id(JsonElement element, string name)
    {
        string result = element.GetProperty(name).GetString() ?? "";
        if (!Regex.IsMatch(result, @"\A[a-fA-F0-9]{32}\z")) throw new UserFault("Cloudflare вернул некорректный идентификатор.");
        return result;
    }

    internal async Task<(Profile Profile, string TunnelToken)> Prepare(Profile p, GatewayOptions options,
        Func<Profile, CancellationToken, Task> save, Action<string> status, CancellationToken ct)
    {
        Validate(options);
        status("Проверяем домен Cloudflare…");
        var zones = await Api(HttpMethod.Get, "zones?name=" + Uri.EscapeDataString(options.Zone), null, ct);
        if (zones.ValueKind != JsonValueKind.Array || zones.GetArrayLength() != 1 || zones[0].GetProperty("status").GetString() != "active")
            throw new UserFault("Домен ещё не активен в Cloudflare. Завершите проверку DNS и делегирование домена.");
        string zoneId = Id(zones[0], "id"), account = Id(zones[0].GetProperty("account"), "id");
        if (p.GatewayHostname.Length != 0 && (p.GatewayHostname != options.Hostname || p.GatewayAccountId != account))
            throw new UserFault("Для этого профиля уже начата настройка другого шлюза. Используйте прежний поддомен и аккаунт.");
        string dnsPath = $"zones/{zoneId}/dns_records";
        var records = await Api(HttpMethod.Get, dnsPath + "?name=" + Uri.EscapeDataString(options.Hostname), null, ct);
        if (records.GetArrayLength() > 0 && (p.GatewayTunnelId.Length == 0 || records.GetArrayLength() != 1 ||
            records[0].GetProperty("type").GetString() != "CNAME" ||
            records[0].GetProperty("content").GetString() != p.GatewayTunnelId + ".cfargotunnel.com" ||
            records[0].GetProperty("proxied").ValueKind != JsonValueKind.True))
            throw new UserFault("Поддомен занят другой DNS-записью. Выберите свободный поддомен; существующая запись не изменена.");
        if (p.GatewayHostname.Length == 0)
        {
            string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            p = p with { GatewayHostname = options.Hostname, GatewayAccountId = account,
                ProtectedGatewayToken = Setup.Protect(p, secret, "gateway-relay") };
            await save(p, ct);
        }
        string tunnelPath = $"accounts/{account}/cfd_tunnel";
        string name = "thingsnotfun-link-" + p.Id.ToString("N");
        status("Создаём постоянный туннель…");
        JsonElement tunnel;
        if (p.GatewayTunnelId.Length == 0)
        {
            var matching = await Api(HttpMethod.Get, tunnelPath + "?is_deleted=false&name=" + name, null, ct);
            if (matching.GetArrayLength() > 1) throw new UserFault("Неоднозначный туннель Cloudflare.");
            tunnel = matching.GetArrayLength() == 1 ? matching[0] :
                await Api(HttpMethod.Post, tunnelPath, new { name, config_src = "cloudflare" }, ct);
            string tunnelId = tunnel.GetProperty("id").GetString() ?? "";
            if (!Guid.TryParseExact(tunnelId, "D", out _)) throw new UserFault("Некорректный идентификатор туннеля.");
            p = p with { GatewayTunnelId = tunnelId };
            await save(p, ct);
        }
        else
        {
            if (!Guid.TryParseExact(p.GatewayTunnelId, "D", out _)) throw new UserFault("Некорректный сохранённый туннель.");
            tunnel = await Api(HttpMethod.Get, tunnelPath + "/" + p.GatewayTunnelId, null, ct);
        }
        if (tunnel.GetProperty("name").GetString() != name || tunnel.GetProperty("config_src").GetString() != "cloudflare")
            throw new UserFault("Туннель не принадлежит этому профилю Link. Изменения отменены.");
        tunnelPath += "/" + p.GatewayTunnelId;
        await Api(HttpMethod.Put, tunnelPath + "/configurations", new
        {
            config = new { ingress = new object[] { new { hostname = options.Hostname, service = "http://127.0.0.1:18093" }, new { service = "http_status:404" } } }
        }, ct);
        if (records.GetArrayLength() == 0)
            await Api(HttpMethod.Post, dnsPath, new { type = "CNAME", name = options.Hostname, content = p.GatewayTunnelId + ".cfargotunnel.com", proxied = true, ttl = 1 }, ct);
        var token = await Api(HttpMethod.Get, tunnelPath + "/token", null, ct);
        string connectorToken = token.GetString() ?? "";
        if (!Regex.IsMatch(connectorToken, @"\A[A-Za-z0-9+/=_-]{40,4096}\z")) throw new UserFault("Cloudflare вернул некорректный токен подключения.");
        return (p, connectorToken);
    }

    public void Dispose() => http.Dispose();
}

static class GatewaySetup
{
    internal static async Task<SshSession> OpenBootstrap(ITransport transport, Profile profile, string directory,
        Action<string> status, CancellationToken ct, string? helperExe = null)
    {
        for (int attempt = 0; ; attempt++)
        {
            status($"Проверяем доступ к VPS… попытка {attempt + 1}/5");
            try { return await SshSession.Open(transport, profile, directory, ct, helperExe); }
            catch (Exception e) when (!ct.IsCancellationRequested &&
                (e is IOException or System.Net.Sockets.SocketException or OperationCanceledException || e is UserFault { Terminal: false }))
            {
                if (attempt == 4) throw new UserFault("Не удалось открыть SSH через текущий шлюз после пяти попыток. Проверьте USB-интернет и доступность шлюза.");
                await Task.Delay(TimeSpan.FromSeconds(3), ct);
            }
        }
    }

    public static async Task<Profile> Run(Profile p, GatewayOptions options, Func<Profile, CancellationToken, Task> save,
        Action<string> status, CancellationToken ct, string? helperExe = null)
    {
        Model.Validate(p);
        CloudflareGateway.Validate(options);
        using var core = p.UseWarpCore ? new RestartableWarpCore(p.ZapretPath) : null;
        ITransport upstream = core != null ? core : p.Proxy != ProxyKind.None ? new ProxyTransport(p) : new TcpTransport(p.AdapterId);
        ITransport bootstrap = p.HttpsRelay.Length == 0 ? upstream : new HttpsTransport(p, upstream);
        using var ssh = await OpenBootstrap(bootstrap, p, ProfileStore.DefaultDirectory, status, ct, helperExe);
        using var interrupt = ct.Register(ssh.Interrupt);
        using var cloudflare = new CloudflareGateway(upstream, options.ApiToken);
        var prepared = await cloudflare.Prepare(p, options, save, status, ct);
        p = prepared.Profile;
        status("Устанавливаем службы шлюза на VPS…");
        var request = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Owner = p.Id.ToString("N"), Hostname = options.Hostname, TunnelToken = prepared.TunnelToken,
            RelayToken = Setup.Open(p, p.ProtectedGatewayToken, "gateway-relay"), SshPort = p.SshPort
        });
        try { await ssh.Wire.Send('G', request, ct); }
        finally { CryptographicOperations.ZeroMemory(request); }
        var response = await ssh.Wire.Read(ct);
        if (response.Type != 'G') throw new UserFault("VPS не подтвердил установку шлюза.");
        var result = Vpn.Decode<GatewayReply>(response.Payload);
        if (!result.Ready || !result.Persistent || result.Hostname != options.Hostname)
            throw new UserFault(result.Error switch
            {
                "root" => "Для установки служб шлюза нужен вход root на VPS.",
                "platform" => "Автоустановка шлюза поддерживает Linux x64 с systemd.",
                "owned" => "На VPS уже есть постоянный шлюз другого профиля. Он не изменён.",
                "checksum" => "Контрольная сумма cloudflared не совпала. Установка остановлена.",
                _ => "Не удалось установить службы шлюза. Прежний адрес сохранён; повторите настройку."
            });
        var configured = p with { HttpsRelay = "wss://" + options.Hostname + "/link-ssh",
            ProtectedRelayToken = Setup.Protect(p, Setup.Open(p, p.ProtectedGatewayToken, "gateway-relay"), "https-relay") };
        status("Проверяем SSH через постоянный адрес…");
        for (int attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var verified = await SshSession.Open(new HttpsTransport(configured, upstream), configured,
                    ProfileStore.DefaultDirectory, ct, helperExe);
                break;
            }
            catch (Exception e) when (attempt < 5 && !ct.IsCancellationRequested &&
                e is UserFault or IOException or System.Net.Sockets.SocketException or OperationCanceledException)
            { await Task.Delay(TimeSpan.FromSeconds(10), ct); }
        }
        await save(configured, ct);
        return configured;
    }
}
