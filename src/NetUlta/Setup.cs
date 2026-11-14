using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetUlta;

enum VpnSetup { Manual, Create, Import }

sealed record ClientKeys(string PublicKey, string? PrivateKey);
sealed record VpnProvision(string? Address, string? ServerKey, string? PresharedKey,
    Dictionary<string, string>? Settings, string? Error);

static class Setup
{
    public static string Protect(Profile profile, string text, string purpose)
    {
        byte[] clear = Encoding.UTF8.GetBytes(text);
        try { return Convert.ToBase64String(ProtectedData.Protect(clear, Entropy(profile, purpose), DataProtectionScope.CurrentUser)); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    public static string Open(Profile profile, string text, string purpose)
    {
        byte[]? clear = null;
        try
        {
            clear = ProtectedData.Unprotect(Convert.FromBase64String(text), Entropy(profile, purpose), DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(clear);
        }
        catch (Exception e) when (e is CryptographicException or FormatException)
        { throw new UserFault("Не удалось открыть сохранённый профиль VPN. Выберите конфигурацию заново."); }
        finally { if (clear != null) CryptographicOperations.ZeroMemory(clear); }
    }

    static byte[] Entropy(Profile profile, string purpose) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(profile.Id.ToString("N") + ":" + purpose));

    public static async Task<ClientKeys> Keys(string? privateKey, CancellationToken ct)
    {
        string exe = Path.Combine(AppContext.BaseDirectory, "tfl-awg-keys.exe");
        if (!File.Exists(exe)) throw new UserFault("Не найден компонент ключей. Распакуйте архив VPSLink целиком.");
        var info = SshSession.StartInfo(exe, privateKey == null ? "new" : "public");
        using var process = Process.Start(info) ?? throw new IOException("Не удалось открыть компонент ключей.");
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            var output = process.StandardOutput.ReadToEndAsync();
            if (privateKey != null) await process.StandardInput.WriteAsync(privateKey);
            process.StandardInput.Close();
            await process.WaitForExitAsync(limit.Token);
            if (process.ExitCode != 0) throw new UserFault("Некорректный ключ клиента AmneziaWG.");
            var result = JsonSerializer.Deserialize<ClientKeys>(await output);
            if (result == null || !Model.IsPeerKey(result.PublicKey) ||
                (privateKey == null && !Model.IsPeerKey(result.PrivateKey ?? "")))
                throw new UserFault("Не удалось подготовить ключ клиента AmneziaWG.");
            return result;
        }
        catch (JsonException)
        { throw new UserFault("Компонент AmneziaWG вернул неверный ключ. Распакуйте архив целиком."); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new UserFault("Компонент ключей не ответил. Повторите подключение."); }
        finally { SshSession.Kill(process); }
    }

    public static string ReadConfig(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length == 0 || file.Length > 128 * 1024)
            throw new UserFault("Выберите небольшой файл конфигурации AmneziaWG.");
        using var reader = new StreamReader(file, new UTF8Encoding(false, true));
        return reader.ReadToEnd();
    }

    public static async Task<Profile> Import(Profile profile, string config, CancellationToken ct)
    {
        var fields = Inspect(config);
        var keys = await Keys(fields.Private, ct);
        return profile with {
            ClientPublicKey = keys.PublicKey, ServerPublicKey = fields.Server, ConfigEndpointPort = fields.Port,
            ProtectedVpnConfig = Protect(profile, config, "vpn-config")
        };
    }

    internal static (string Private, string Server, int Port) Inspect(string config)
    {
        string section = "", privateKey = "", serverKey = "", endpoint = "";
        int interfaces = 0, peers = 0;
        foreach (var raw in config.Split('\n'))
        {
            var line = raw.Split('#', 2)[0].Trim();
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line.ToLowerInvariant();
                if (section == "[interface]") interfaces++;
                if (section == "[peer]") peers++;
                continue;
            }
            var kv = line.Split('=', 2);
            if (kv.Length != 2) continue;
            string key = kv[0].Trim().ToLowerInvariant(), value = kv[1].Trim();
            if (key is "preup" or "postup" or "predown" or "postdown")
                throw new UserFault("В конфигурации есть команды запуска. Выберите нативную конфигурацию AmneziaWG без команд.");
            if (section == "[interface]" && key == "privatekey") Set(ref privateKey, value);
            if (section == "[peer]" && key == "publickey") Set(ref serverKey, value);
            if (section == "[peer]" && key == "endpoint") Set(ref endpoint, value);
        }
        var colon = endpoint.LastIndexOf(':');
        if (interfaces != 1 || peers != 1 || !Model.IsPeerKey(privateKey) || !Model.IsPeerKey(serverKey) ||
            colon < 1 || !int.TryParse(endpoint[(colon + 1)..], out int port) || port is < 1 or > 65535)
            throw new UserFault("Нужна конфигурация AmneziaWG с одним сервером, ключами клиента и Endpoint.");
        return (privateKey, serverKey, port);

        static void Set(ref string field, string value)
        {
            if (field.Length != 0 || value.Length == 0) throw new UserFault("В конфигурации есть повторяющееся или пустое поле.");
            field = value;
        }
    }

    public static string BuildConfig(VpnProvision result, string privateKey)
    {
        if (!IPAddress.TryParse(result.Address, out var addr) ||
            addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !Model.IsPeerKey(result.ServerKey ?? "") || !Model.IsPeerKey(result.PresharedKey ?? "") ||
            result.Settings == null || !Model.IsPeerKey(privateKey))
            throw new UserFault("VPS вернул неполный профиль VPN.");
        var text = new StringBuilder("[Interface]\n")
            .AppendLine("PrivateKey = " + privateKey).AppendLine("Address = " + addr + "/32")
            .AppendLine("DNS = 1.1.1.1, 9.9.9.9");
        foreach (var pair in result.Settings)
        {
            if (!Regex.IsMatch(pair.Key, @"\A(?:Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|Hpk|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)\z") ||
                !Regex.IsMatch(pair.Value, @"\A[ -~]{1,4096}\z"))
                throw new UserFault("VPS вернул неподдерживаемые параметры AmneziaWG.");
            text.Append(pair.Key).Append(" = ").AppendLine(pair.Value);
        }
        return text.AppendLine().AppendLine("[Peer]").AppendLine("PublicKey = " + result.ServerKey)
            .AppendLine("PresharedKey = " + result.PresharedKey)
            .AppendLine("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1").AppendLine("Endpoint = 127.0.0.1:1")
            .AppendLine("PersistentKeepalive = 25").ToString();
    }
}
