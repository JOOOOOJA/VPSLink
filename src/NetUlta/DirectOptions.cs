using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace NetUlta;

sealed record DirectOptions(bool Enabled = false, bool Steam = false, bool Amnezia = false, string Executables = "");

static class DirectRules
{
    const string AmneziaKey = @"Software\AmneziaVPN.ORG\AmneziaVPN\Conf";

    internal static string? AmneziaConflict()
    {
        using var key = Registry.CurrentUser.OpenSubKey(AmneziaKey);
        if (key == null) return "Не найдены настройки AmneziaVPN для этой учётной записи Windows.";
        foreach (var field in new[] { "appsSplitTunnelingEnabled", "sitesSplitTunnelingEnabled", "killSwitchEnabled" })
        {
            // The client only writes its app and site flags after the user saves them.
            var value = key.GetValue(field);
            if (IsOff(value) || (value == null && field != "killSwitchEnabled")) continue;
            return "Выключите встроенное разделение по приложениям и сайтам, а также KillSwitch в AmneziaVPN. Затем переподключите VPN.";
        }
        return null;
    }

    static bool IsOff(object? value) => value is 0 || value is string text && (text == "0" || text.Equals("false", StringComparison.OrdinalIgnoreCase));

    internal static string[] AmneziaPaths()
    {
        using var key = Registry.CurrentUser.OpenSubKey(AmneziaKey);
        if (key?.GetValue("appsRouteMode") is not 2)
            throw new UserFault("Выберите в AmneziaVPN режим «исключить приложения из VPN». Список «только через VPN» сюда не переносится.");
        return key.GetValue("ExceptApps") switch
        {
            null => Array.Empty<string>(),
            byte[] data => DecodeAmnezia(data),
            _ => throw new UserFault("Формат списка AmneziaVPN изменился. Добавьте нужные .exe вручную.")
        };
    }

    internal static string[] DecodeAmnezia(byte[] value)
    {
        var error = new UserFault("Не удалось прочитать список AmneziaVPN. Добавьте нужные .exe вручную.");
        if (value.Length > 1_048_576 || value.Length % 2 != 0) throw error;
        var text = Encoding.Unicode.GetString(value);
        if (!text.StartsWith("@Variant(", StringComparison.Ordinal) || !text.EndsWith(')') || text.Length < 18) throw error;
        var body = text.AsSpan(9, text.Length - 10);
        foreach (var ch in body) if (ch > 255) throw error;
        var bytes = Encoding.Latin1.GetBytes(body.ToString());
        if (BinaryPrimitives.ReadInt32BigEndian(bytes) != 144 || BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(4)) != bytes.Length - 8)
            throw error;
        try
        {
            using var doc = JsonDocument.Parse(bytes.AsMemory(8));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) throw error;
            return doc.RootElement.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.Object && item.TryGetProperty("appPath", out var path) && path.ValueKind == JsonValueKind.String)
                .Select(item => NormalizeExe(item.GetProperty("appPath").GetString()))
                .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch (JsonException) { throw error; }
    }

    internal static string? NormalizeExe(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl)) return null;
        path = path.Trim().Replace('/', '\\');
        if (path.Length < 7 || path[0] is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z') || path[1] != ':' || path[2] != '\\' ||
            !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        try { return Path.GetFullPath(path); }
        catch (ArgumentException) { return null; }
        catch (IOException) { return null; }
    }

    internal static string[] SteamRoots()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
        var steam = NormalizeExe(key?.GetValue("SteamExe") as string) ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam", "steam.exe");
        if (!File.Exists(steam) || !Path.GetFileName(steam).Equals("steam.exe", StringComparison.OrdinalIgnoreCase))
            throw new UserFault("Не найден Steam. Проверьте его установку или добавьте отдельные .exe.");
        string root = Path.GetDirectoryName(steam)!;
        var roots = new List<string> { root };
        var vdf = new FileInfo(Path.Combine(root, "steamapps", "libraryfolders.vdf"));
        if (vdf.Exists && vdf.Length <= 1_048_576)
        {
            foreach (Match entry in Regex.Matches(File.ReadAllText(vdf.FullName), "\"path\"\\s+\"([^\"\r\n]+)\""))
            {
                var library = entry.Groups[1].Value.Replace(@"\\", @"\");
                var valid = NormalizeExe(Path.Combine(library, "steamapps", "common", "game.exe"));
                if (valid != null && Directory.Exists(Path.GetDirectoryName(valid))) roots.Add(Path.GetDirectoryName(valid)!);
            }
        }
        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    internal static string PathPattern(string root) =>
        "(?i)^" + Regex.Escape(root.TrimEnd('\\') + "\\").Replace(@"\ ", " ") + @".*\.exe$";
}
