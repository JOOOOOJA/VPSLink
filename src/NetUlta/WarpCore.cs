using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace NetUlta;

sealed class WarpCore : ITransport, IDisposable
{
    static readonly string State = Path.Combine(ProfileStore.DefaultDirectory, "WarpCore");
    internal static readonly string Configuration = Path.Combine(State, "config.json");
    static readonly string Executable = Path.Combine(AppContext.BaseDirectory, "warp-core", "usque.exe");
    static readonly string BundledZapret = Path.Combine(AppContext.BaseDirectory, "zapret", "winws.exe");
    static readonly SemaphoreSlim RegistrationGate = new(1, 1);
    const string ExecutableSha256 = "122F2E40208E81BB814FCB4BE4FBBBDC9246860F1F3784F72AE4512B97667E91";
    readonly Process process;
    readonly IPAddress endpoint;
    readonly ProxyTransport proxy;
    readonly Process? zapret;
    volatile string failure = "";
    public string Name => "ядро WARP MASQUE";
    public bool HasExited => process.HasExited;
    public static bool Installed => File.Exists(Executable);
    public static bool Registered => File.Exists(Configuration);

    WarpCore(Process process, IPAddress endpoint, int port, Process? zapret)
    {
        this.process = process;
        this.endpoint = endpoint;
        this.zapret = zapret;
        proxy = new(new Profile { Proxy = ProxyKind.Socks5, ProxyPort = port });
    }

    static void VerifyExecutable()
    {
        if (!Installed) throw new UserFault("В сборке отсутствует ядро WARP.", false);
        using (var exe = File.OpenRead(Executable))
        {
            using var sha = SHA256.Create();
            if (Convert.ToHexString(sha.ComputeHash(exe)) != ExecutableSha256)
                throw new UserFault("Контрольная сумма ядра WARP не совпала.");
        }
    }

    public static async Task Register(CancellationToken ct)
    {
        await RegistrationGate.WaitAsync(ct);
        try
        {
            if (Registered) return;
            VerifyExecutable();
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User ?? throw new IOException("Windows identity");
            var acl = new DirectorySecurity();
            acl.SetOwner(owner);
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(State).Create(acl);
            string pending = Path.Combine(State, Guid.NewGuid().ToString("N") + ".json");
            try
            {
                var info = SshSession.StartInfo(Executable, "--config", pending, "register",
                    "--name", "VPSLink", "--accept-tos");
                using var child = Process.Start(info) ?? throw new IOException("WARP registration");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(30));
                child.StandardInput.Close();
                var output = child.StandardOutput.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
                var errors = child.StandardError.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
                try
                {
                    await child.WaitForExitAsync(timeout.Token);
                    await Task.WhenAll(output, errors);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                { throw new UserFault("Регистрация WARP не ответила за 30 секунд."); }
                finally { SshSession.Kill(child); }
                if (child.ExitCode != 0 || !File.Exists(pending))
                    throw new UserFault("Cloudflare не завершил регистрацию ядра WARP. Проверьте доступ к API Cloudflare.");
                File.Move(pending, Configuration);
            }
            finally { File.Delete(pending); }
        }
        finally { RegistrationGate.Release(); }
    }

    public static WarpCore Start(string zapretPath = "", WinwsStrategy? strategy = null, bool exclusive = false)
    {
        VerifyExecutable();
        if (!Registered) throw new UserFault("Ядро WARP ещё не зарегистрировано.");
        var endpoint = ReadEndpoint();
        RequirePhysicalRoute(endpoint);
        int port = PickLocalProxyPort();
        var info = SshSession.StartInfo(Executable, "--config", Configuration, "socks", "--http2",
            "--sni-address", "www.cloudflare.com",
            "--bind", "127.0.0.1", "--port", port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--always-reconnect", "--reconnect-delay", "3s");
        foreach (var key in info.Environment.Keys.Where(k => k.Equals("HTTP_PROXY", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("HTTPS_PROXY", StringComparison.OrdinalIgnoreCase) || k.Equals("ALL_PROXY", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("NO_PROXY", StringComparison.OrdinalIgnoreCase)).ToArray())
            info.Environment.Remove(key);
        var zapret = StartZapret(zapretPath, endpoint, strategy, exclusive);
        Process child;
        try { child = Process.Start(info) ?? throw new IOException("WARP core"); }
        catch { if (zapret != null) { SshSession.Kill(zapret); zapret.Dispose(); } throw; }
        var core = new WarpCore(child, endpoint, port, zapret);
        try
        {
            child.StandardInput.Close();
            child.OutputDataReceived += (_, e) => core.RecordFailure(e.Data);
            child.ErrorDataReceived += (_, e) => core.RecordFailure(e.Data);
            child.BeginOutputReadLine();
            child.BeginErrorReadLine();
            return core;
        }
        catch { core.Dispose(); throw; }
    }

    static int PickLocalProxyPort()
    {
        for (int attempt = 0; attempt < 12; attempt++)
        {
            using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            tcp.ExclusiveAddressUse = udp.ExclusiveAddressUse = true;
            tcp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var endpoint = (IPEndPoint)tcp.LocalEndPoint!;
            try
            {
                // usque binds both protocols on this port.
                udp.Bind(endpoint);
                return endpoint.Port;
            }
            catch (SocketException) { }
        }
        throw new UserFault("Не нашёлся свободный локальный порт TCP и UDP для WARP.", false);
    }

    internal static IPAddress ReadEndpoint()
    {
        var config = File.ReadAllBytes(Configuration);
        try
        {
            using var json = JsonDocument.Parse(config);
            if (!json.RootElement.TryGetProperty("endpoint_h2_v4", out var value) ||
                value.ValueKind != JsonValueKind.String || !IPAddress.TryParse(value.GetString(), out var ip) ||
                ip.AddressFamily != AddressFamily.InterNetwork)
                throw new UserFault("В регистрации ядра WARP отсутствует IPv4-адрес MASQUE.");
            return ip;
        }
        finally { CryptographicOperations.ZeroMemory(config); }
    }

    static Process? StartZapret(string path, IPAddress endpoint, WinwsStrategy? strategy, bool exclusive)
    {
        if (path.Length == 0 && File.Exists(BundledZapret)) path = BundledZapret;
        if (path.Length == 0)
        {
            if (exclusive || strategy != null) throw new UserFault("В сборке отсутствует winws. Установите полный пакет VPSLink.");
            return null;
        }
        var running = Process.GetProcessesByName("winws").Concat(
            exclusive || strategy != null ? Process.GetProcessesByName("winws2") : Array.Empty<Process>()).ToArray();
        try
        {
            if (running.Length > 0)
            {
                if (exclusive || strategy != null) throw new UserFault("Уже работает другой winws. Остановите его своим обычным способом перед проверкой или применением выбранной стратегии. VPSLink не останавливает чужие процессы.");
                return null;
            }
        }
        finally { foreach (var item in running) item.Dispose(); }
        if (!Path.IsPathFullyQualified(path) || !Path.GetFileName(path).Equals("winws.exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
            throw new UserFault("Проверьте путь к winws.exe.");
        string folder = Path.GetDirectoryName(path)!;
        if (new[] { "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys" }.Any(name => !File.Exists(Path.Combine(folder, name))))
            throw new UserFault("Рядом с winws.exe должны быть cygwin1.dll, WinDivert.dll и WinDivert64.sys.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UserFault("Для запуска WinDivert откройте VPSLink от администратора.");
        var info = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = folder };
        // Limit the filter to the selected MASQUE endpoint. Open connections to other services are outside it.
        foreach (string argument in WinwsStrategies.Arguments(endpoint, strategy ?? WinwsStrategies.Default)) info.ArgumentList.Add(argument);
        return Process.Start(info) ?? throw new IOException("zapret");
    }

    public async Task<Stream> Connect(string host, int port, CancellationToken ct)
    {
        RequirePhysicalRoute(endpoint);
        for (int attempt = 0; ; attempt++)
        {
            if (zapret?.HasExited == true)
                throw new UserFault($"winws завершился с кодом {zapret.ExitCode}. Проверьте запуск WinDivert.");
            if (process.HasExited)
                throw new UserFault($"Ядро WARP завершилось ({process.ExitCode}). {failure}", false);
            try { return await proxy.Connect(host, port, ct); }
            catch (UserFault) when (attempt < 12)
            {
                await Task.Delay(250, ct);
            }
        }
    }

    void RecordFailure(string? line)
    {
        if (line == null) return;
        if (line.Contains("unknown flag", StringComparison.OrdinalIgnoreCase))
            failure = "Версия ядра не поддерживает параметр запуска.";
        else if (line.Contains("Config not loaded", StringComparison.OrdinalIgnoreCase))
            failure = "Конфигурация регистрации не прочитана.";
        else if (line.Contains("Failed to start SOCKS proxy", StringComparison.OrdinalIgnoreCase))
            failure = "Не удалось открыть локальный SOCKS-порт.";
        else if (line.Contains("panic:", StringComparison.OrdinalIgnoreCase))
            failure = "Ядро завершилось с внутренней ошибкой.";
    }

    static void RequirePhysicalRoute(IPAddress endpoint)
    {
        int index = TcpTransport.BestInterface(endpoint);
        var adapters = NetworkInterface.GetAllNetworkInterfaces();
        if (index > 0 && adapters.Any(n => n.OperationalStatus == OperationalStatus.Up &&
            n.NetworkInterfaceType is (NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or
                NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2) &&
            !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase) &&
            n.GetIPProperties().GetIPv4Properties()?.Index == index)) return;
        throw new UserFault("До ядра WARP нет прямого маршрута через Ethernet или Wi‑Fi.", false);
    }

    public void Dispose()
    {
        SshSession.Kill(process);
        process.Dispose();
        if (zapret != null)
        {
            SshSession.Kill(zapret);
            zapret.Dispose();
        }
    }
}

sealed class RestartableWarpCore : ITransport, IDisposable
{
    readonly string zapretPath;
    readonly WinwsStrategy? strategy;
    WarpCore? core;
    public RestartableWarpCore(string zapretPath, WinwsStrategy? strategy = null)
    {
        this.zapretPath = zapretPath;
        this.strategy = strategy == null ? null : WinwsStrategies.Snapshot(strategy);
    }
    public string Name => "ядро WARP MASQUE";

    public async Task<Stream> Connect(string host, int port, CancellationToken ct)
    {
        if (core?.HasExited == true)
        {
            core.Dispose();
            core = null;
        }
        core ??= WarpCore.Start(zapretPath, strategy);
        return await core.Connect(host, port, ct);
    }

    public void Dispose() => core?.Dispose();
}
