using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetUlta;

enum AuthKind { Password, Key }
enum ProxyKind { None, Socks5, HttpConnect }
sealed record Profile
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; init; } = "";
    public string Host { get; init; } = "";
    public int SshPort { get; init; } = 22;
    public string User { get; init; } = "";
    public string Fingerprint { get; init; } = "";
    public AuthKind Auth { get; init; }
    public string ProtectedCredential { get; init; } = "";
    public ProxyKind Proxy { get; init; }
    public string ProxyHost { get; init; } = "127.0.0.1";
    public int ProxyPort { get; init; } = 40000;
    public string HttpsRelay { get; init; } = "";
    public string ProtectedRelayToken { get; init; } = "";
    public string AdapterId { get; init; } = "";
    public bool AutoWarp { get; init; } = true;
    public bool UseSystemRoute { get; init; } = true;
    public string RemoteIp { get; init; } = "";
    public int RemotePort { get; init; }
    public int LocalPort { get; init; }
    public string ClientPublicKey { get; init; } = "";
    public string SourceId { get; init; } = "";
    public bool StartWarp { get; init; }
    public bool UseWarpCore { get; init; }
    public string ZapretPath { get; init; } = "";
    public VpnSetup VpnSetup { get; init; }
    public string ServerPublicKey { get; init; } = "";
    public int ConfigEndpointPort { get; init; }
    public string ProtectedVpnConfig { get; init; } = "";
    public string ProtectedClientKey { get; init; } = "";
    public string GatewayHostname { get; init; } = "";
    public string GatewayTunnelId { get; init; } = "";
    public string GatewayAccountId { get; init; } = "";
    public string ProtectedGatewayToken { get; init; } = "";
    public bool AutoConnect { get; init; }
    public bool StartWithWindows { get; init; }
    public int? AmneziaServerIndex { get; init; }
    public override string ToString() => Name;
}
sealed record Credential(string Passphrase, byte[]? Key);
sealed record InterfaceChoice(string Id, string Name) { public override string ToString() => Name; }

static class Model
{
    public static bool IsHost(string s) =>
        IPAddress.TryParse(s, out _) || (s.Length <= 253 && Uri.CheckHostName(s) == UriHostNameType.Dns
            && s.All(c => (c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9') || c is '-' or '.'));
    public static bool IsPeerKey(string s) => IsBase64(s, 32, false);
    public static bool IsFingerprint(string s) => s.StartsWith("SHA256:", StringComparison.Ordinal)
        && IsBase64(s[7..], 32, true);
    private static bool IsBase64(string s, int bytes, bool unpadded)
    {
        try
        {
            var value = Convert.FromBase64String(unpadded ? s + "=" : s);
            var normalized = Convert.ToBase64String(value);
            return value.Length == bytes && s == (unpadded ? normalized.TrimEnd('=') : normalized);
        }
        catch (FormatException) { return false; }
    }

    public static void Validate(Profile p, bool allowUnpinned = false)
    {
        if (p.Id == Guid.Empty || string.IsNullOrWhiteSpace(p.Name) || p.Name.Length > 120)
            throw new UserFault("Введите название профиля (до 120 символов).");
        if (!IsHost(p.Host) || p.SshPort is < 1 or > 65535 || !Regex.IsMatch(p.User, @"\A[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\z"))
            throw new UserFault("Проверьте адрес VPS, порт SSH и имя пользователя.");
        if (!(allowUnpinned && p.Fingerprint.Length == 0) && !IsFingerprint(p.Fingerprint))
            throw new UserFault("Введите проверенный отпечаток ED25519 вида SHA256:… из консоли хостера.");
        if (p.Proxy != ProxyKind.None && (!IsHost(p.ProxyHost) || p.ProxyPort is < 1 or > 65535))
            throw new UserFault("Введите корректный адрес и порт прокси.");
        if (p.HttpsRelay.Length != 0 && (!HttpsTransport.TryEndpoint(p.HttpsRelay, out _) || p.ProtectedRelayToken.Length == 0))
            throw new UserFault("Укажите HTTPS-адрес шлюза SSH и его токен.");
        if (p.Proxy == ProxyKind.None && p.HttpsRelay.Length == 0 && p.AdapterId.Length == 0 &&
            !p.UseSystemRoute && !p.AutoWarp && !p.UseWarpCore)
            throw new UserFault("Выберите хотя бы один способ добраться до VPS.");
        if (p.RemoteIp.Length != 0 && (!IPAddress.TryParse(p.RemoteIp, out var ip) ||
            ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast) ||
            ip.IsIPv6Multicast || (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && (ip.GetAddressBytes()[0] & 240) == 224)))
            throw new UserFault("Для UDP на VPS укажите IP назначения или оставьте поле пустым для автоопределения.");
        if (p.RemotePort is < 0 or > 65535 || p.LocalPort is < 0 or > 65535 ||
            p.ConfigEndpointPort is < 0 or > 65535 ||
            (p.ServerPublicKey.Length != 0 && !IsPeerKey(p.ServerPublicKey)) ||
            (p.ClientPublicKey.Length != 0 && !IsPeerKey(p.ClientPublicKey)))
            throw new UserFault("Проверьте порты UDP и открытый ключ клиента AmneziaWG.");
        if (p.SourceId.Length > 180 || (p.SourceId.Length > 0 && p.SourceId.Any(c => !(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9') && c is not ':' and not '-' and not '_' and not '.')))
            throw new UserFault("Проверьте идентификатор интерфейса VPN из диагностики.");
        if (!Enum.IsDefined(typeof(AuthKind), p.Auth) || !Enum.IsDefined(typeof(ProxyKind), p.Proxy) ||
            !Enum.IsDefined(typeof(VpnSetup), p.VpnSetup))
            throw new UserFault("Неизвестный тип подключения в профиле.");
        if (p.ProtectedCredential.Length == 0)
            throw new UserFault("Укажите пароль SSH или файл приватного ключа.");
        if (p.AmneziaServerIndex is < 0 or > 999)
            throw new UserFault("Проверьте номер сервера AmneziaVPN.");
        if (p.StartWithWindows && !p.AutoConnect)
            throw new UserFault("Для запуска вместе с Windows включите подключение при запуске Link.");
    }
    public static IReadOnlyList<InterfaceChoice> Interfaces() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                && n.GetIPProperties().UnicastAddresses.Count > 0)
            .Select(n => new InterfaceChoice(n.Id, n.Name + " · " + n.Description)).ToArray();
}
sealed class UserFault : Exception
{
    public bool Terminal { get; }
    public UserFault(string message, bool terminal = true) : base(message) { Terminal = terminal; }
}

sealed class ProfileStore
{
    public static string DefaultDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThingsNotFun-Link");
    readonly string directory;
    readonly JsonSerializerOptions options = new() { WriteIndented = true };
    string FileName => Path.Combine(directory, "profiles.json");
    public ProfileStore(string directory) { this.directory = directory; }
    static List<Profile> Read(string path)
    {
        var profiles = JsonSerializer.Deserialize<List<Profile>>(File.ReadAllText(path))
            ?? throw new JsonException("Expected a profile array.");
        if (profiles.Any(p => p == null || p.Id == Guid.Empty) ||
            profiles.Select(p => p.Id).Distinct().Count() != profiles.Count)
            throw new JsonException("Invalid or duplicate profile identity.");
        return profiles;
    }
    public List<Profile> Load() => File.Exists(FileName) ? Read(FileName) : new();
    public void Save(IReadOnlyList<Profile> profiles, Action? afterWrite = null)
    {
        Directory.CreateDirectory(directory);
        var snapshot = profiles.ToArray();
        byte[]? original = null;
        if (File.Exists(FileName))
        {
            _ = Read(FileName); // Never replace an unreadable store with an empty one.
            original = File.ReadAllBytes(FileName);
        }
        var temp = FileName + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(snapshot, options));
            if (!Read(temp).SequenceEqual(snapshot)) throw new IOException("Profile validation failed.");
            if (original == null) File.Move(temp, FileName);
            else File.Replace(temp, FileName, FileName + ".bak");
            try { afterWrite?.Invoke(); }
            catch
            {
                if (original == null) File.Delete(FileName);
                else
                {
                    File.WriteAllBytes(temp, original);
                    _ = Read(temp);
                    File.Move(temp, FileName, overwrite: true);
                }
                throw;
            }
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    static byte[] Entropy(Guid id) => id.ToByteArray();
    public static string Protect(Guid id, Credential credential)
    {
        var clear = JsonSerializer.SerializeToUtf8Bytes(credential);
        try { return Convert.ToBase64String(ProtectedData.Protect(clear, Entropy(id), DataProtectionScope.CurrentUser)); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    public static Credential Open(Profile p)
    {
        byte[]? clear = null;
        try
        {
            clear = ProtectedData.Unprotect(Convert.FromBase64String(p.ProtectedCredential), Entropy(p.Id), DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<Credential>(clear) ?? throw new CryptographicException();
        }
        catch (Exception e) when (e is CryptographicException or FormatException or JsonException)
        { throw new UserFault("Windows не смог расшифровать данные SSH. Заново укажите пароль или ключ в профиле."); }
        finally { if (clear != null) CryptographicOperations.ZeroMemory(clear); }
    }
}

static class VpnConfig
{
    public static void Export(string input, string output, int port, bool handshakeOnly = false, IPAddress? outerEndpoint = null)
    {
        if (Path.GetFullPath(input).Equals(Path.GetFullPath(output), StringComparison.OrdinalIgnoreCase))
            throw new UserFault("Выберите новое имя файла. Исходная конфигурация должна остаться для отката.");
        var info = new FileInfo(input);
        if (!info.Exists || info.Length > 1024 * 1024) throw new UserFault("Не удалось прочитать небольшую конфигурацию .conf.");
        ExportText(File.ReadAllText(input), output, port, handshakeOnly, outerEndpoint);
    }

    public static void ExportText(string text, string output, int port, bool handshakeOnly = false, IPAddress? outerEndpoint = null)
    {
        var outputLines = new List<string>();
        int peers = 0, endpoints = 0, interfaces = 0;
        string section = "";
        foreach (var original in text.Split('\n'))
        {
            int hash = original.IndexOf('#');
            string line = (hash < 0 ? original : original[..hash]).Trim();
            int equal = line.IndexOf('=');
            string key = equal < 0 ? "" : line[..equal].Trim().ToLowerInvariant();
            if (key is "preup" or "postup" or "predown" or "postdown")
                throw new UserFault("В конфигурации есть команды запуска. Выберите профиль AmneziaWG без команд.");
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line.ToLowerInvariant();
                if (section == "[peer]") peers++;
                if (section == "[interface]") interfaces++;
            }
            if (handshakeOnly && ((section == "[interface]" && key == "dns") ||
                (section == "[peer]" && key is "allowedips" or "persistentkeepalive"))) continue;
            if (!handshakeOnly && outerEndpoint != null && section == "[peer]" && key == "allowedips")
            {
                string routes = string.Join(", ", line[(equal + 1)..].Split(',')
                    .SelectMany(route => WithoutEndpoint(route.Trim(), outerEndpoint)));
                if (routes.Length == 0) throw new UserFault("В AllowedIPs остался только адрес внешнего транспорта.");
                outputLines.Add("AllowedIPs = " + routes + (original.EndsWith('\r') ? "\r" : ""));
                continue;
            }
            if (section != "[peer]" || key != "endpoint")
            {
                outputLines.Add(original);
                continue;
            }
            endpoints++;
            string comment = hash >= 0 ? " " + original[hash..].TrimEnd('\r') : "";
            string ending = original.EndsWith('\r') ? "\r" : "";
            outputLines.Add($"Endpoint = 127.0.0.1:{port}{comment}{ending}");
            if (handshakeOnly)
            {
                outputLines.Add("AllowedIPs = 1.1.1.1/32" + ending);
                outputLines.Add("PersistentKeepalive = 10" + ending);
            }
        }
        if (peers != 1 || interfaces != 1 || endpoints != 1)
            throw new UserFault("Нужна нативная .conf AmneziaWG с одним разделом [Peer] и одним Endpoint.");
        using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(file, new UTF8Encoding(false));
        writer.Write(string.Join("\n", outputLines));
    }

    internal static IEnumerable<string> WithoutEndpoint(string route, IPAddress endpoint)
    {
        var parts = route.Split('/', 2);
        if (IPAddress.TryParse(parts[0], out var address) &&
            address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && parts.Length == 2 &&
            int.TryParse(parts[1], out var lengthV6) && lengthV6 == 0)
        {
            yield return "::/1";
            yield return "8000::/1";
            yield break;
        }
        if (address == null || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            endpoint.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            yield return route;
            yield break;
        }
        int prefix = 32;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix is < 0 or > 32))
        {
            yield return route;
            yield break;
        }
        uint target = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(endpoint.GetAddressBytes());
        uint network = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        if ((target & mask) != (network & mask))
        {
            yield return route;
            yield break;
        }
        var bytes = new byte[4];
        for (int length = prefix + 1; length <= 32; length++)
        {
            uint bit = 1u << (32 - length);
            uint sibling = (target & (uint.MaxValue << (32 - length))) ^ bit;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, sibling);
            yield return new IPAddress(bytes) + "/" + length;
        }
    }
}


