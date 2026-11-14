using System.Diagnostics;
using System.Text.Json;

namespace NetUlta;

interface IWarpClient
{
    Task<Profile?> Activate(Profile profile, Action<string> progress, CancellationToken ct);
}

sealed class WarpClient : IWarpClient
{
    public const string InstallUrl = "https://developers.cloudflare.com/warp-client/get-started/windows/";

    static string? Executable()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return new[] { "Cloudflare WARP", "Cloudflare One Client" }
            .Select(name => Path.Combine(root, "Cloudflare", name, "warp-cli.exe")).FirstOrDefault(File.Exists);
    }

    public async Task<Profile?> Activate(Profile profile, Action<string> progress, CancellationToken ct)
    {
        var exe = Executable();
        if (exe == null) throw new UserFault("Установите Cloudflare WARP и завершите первый запуск в его окне.");
        var state = await Run(exe, ct, "status");
        var name = Property(state, "status");
        if (name is "Disconnected")
        {
            progress("Включаем Cloudflare WARP…");
            await Run(exe, ct, "connect");
        }
        else if (name is not ("Connecting" or "Connected"))
            throw new UserFault("Cloudflare WARP недоступен. Откройте его и завершите первый запуск.");
        for (int i = 0; name != "Connected" && i < 12; i++)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
            name = Property(await Run(exe, ct, "status"), "status");
        }
        if (name != "Connected")
            throw new UserFault("WARP не подключился. Проверьте его состояние и повторите попытку.", false);
        progress("WARP подключён. Проверяем доступ к серверу…");
        // Read a configured local proxy when present. The device's WARP mode is never changed.
        try
        {
            var settings = await Run(exe, ct, "settings");
            int port = ProxyPort(settings);
            if (port != 0)
                return profile with { Proxy = ProxyKind.Socks5, ProxyHost = "127.0.0.1", ProxyPort = port };
        }
        catch (UserFault) { } // Older clients still expose the adapter.
        return null;
    }

    internal static int ProxyPort(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return 0;
        var settings = root.TryGetProperty("settings", out var nested) ? nested : root;
        if (settings.ValueKind != JsonValueKind.Object ||
            (Property(settings, "service_mode") is not ("WarpProxy" or "Proxy") &&
             Property(settings, "operation_mode") != "proxy")) return 0;
        if (settings.TryGetProperty("proxy_port", out var port) && port.ValueKind == JsonValueKind.Number &&
            port.TryGetInt32(out int number) && number is > 0 and <= 65535)
            return number;
        // Cloudflare's default proxy port. A real SOCKS5 exchange and SSH pin are still required.
        return settings.TryGetProperty("proxy_port", out _) ? 0 : 40000;
    }

    static string? Property(JsonElement element, string key) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(key, out var result) &&
        result.ValueKind == JsonValueKind.String ? result.GetString() : null;

    static async Task<JsonElement> Run(string exe, CancellationToken ct, params string[] arguments)
    {
        var info = SshSession.StartInfo(exe, new[] { "--json", "--no-ansi" }.Concat(arguments).ToArray());
        using var process = Process.Start(info) ?? throw new IOException("Cloudflare WARP");
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            process.StandardInput.Close();
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(limit.Token);
            await error;
            if (process.ExitCode != 0) throw new UserFault("Откройте Cloudflare WARP и проверьте, что он готов к подключению.");
            if (arguments[0] == "connect") return default;
            using var json = JsonDocument.Parse(await output);
            return json.RootElement.Clone();
        }
        catch (JsonException) { throw new UserFault("Эта версия Cloudflare WARP вернула неизвестный статус."); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new UserFault("Cloudflare WARP не ответил вовремя.", false); }
        finally { SshSession.Kill(process); }
    }
}
