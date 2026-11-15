using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace NetUlta;

sealed record DirectNetwork(string Physical, string PhysicalAddress, int PhysicalIndex,
    string Vpn, string VpnAddress, int VpnIndex, string[] Prefixes, string[] Protected);

static class DirectRouting
{
    internal const string Packages = "https://github.com/SagerNet/sing-box/releases/tag/v1.14.4";
    const string ZipHash = "99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF";
    const string Adapter = "VPSLink-Direct";
    static readonly string[] PrivateRanges = { "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/3" };
    internal static string ArchivePath(string directory) => Path.Combine(directory, "sing-box-1.14.4-windows-amd64.zip");

    internal static async Task ImportArchive(string source, string directory)
    {
        Directory.CreateDirectory(directory);
        var target = ArchivePath(directory);
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using var input = File.OpenRead(source);
            await VerifyArchive(input, CancellationToken.None);
            await using (var output = File.Open(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await input.CopyToAsync(output);
            File.Move(temporary, target, overwrite: true);
        }
        finally { File.Delete(temporary); }
    }

    static async Task VerifyArchive(FileStream file, CancellationToken ct)
    {
        using var hash = SHA256.Create();
        if (file.Length is < 1 or > 64 * 1024 * 1024 ||
            Convert.ToHexString(await hash.ComputeHashAsync(file, ct)) != ZipHash)
            throw new UserFault("Нужен официальный ZIP sing-box 1.14.4 для Windows amd64. Контрольная сумма выбранного файла не совпала.");
        file.Position = 0;
    }

    static async Task<DirectNetwork> ReadNetwork(CancellationToken ct)
    {
        using var script = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("NetUlta.DirectNetwork.ps1")!);
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(await script.ReadToEndAsync()));
        var output = await ReadProcess(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            ct, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded);
        if (output.Code == 3) throw new UserFault("Нужны подключённая AmneziaVPN и один активный основной шлюз Windows.");
        if (output.Code == 4) throw new UserFault("У Windows есть маршрут IPv6 по умолчанию. Режим «Напрямую» пока поддерживает только IPv4.");
        if (output.Code != 0) throw new UserFault("Не удалось прочитать маршруты Windows.");
        return JsonSerializer.Deserialize<DirectNetwork>(output.Text) ?? throw new UserFault("Не удалось прочитать маршруты Windows.");
    }

    static async Task CheckFilters(string stage, CancellationToken ct)
    {
        string path = Path.Combine(stage, "wfp.xml");
        try
        {
            var result = await ReadProcess(Path.Combine(Environment.SystemDirectory, "netsh.exe"), ct, "wfp", "show", "state", "file=" + path);
            var snapshot = new FileInfo(path);
            if (result.Code != 0 || !snapshot.Exists || snapshot.Length is < 1 or > 64 * 1024 * 1024)
                throw new UserFault("Не удалось проверить фильтры KillSwitch.");
            string xml = await File.ReadAllTextAsync(path, ct);
            var document = XDocument.Parse("<root>" + Regex.Replace(xml.TrimStart('\uFEFF'), @"<\?xml[^?]*\?>", "") + "</root>");
            if (document.Descendants("filters").Elements("item").Any(filter =>
                (string?)filter.Element("subLayerKey") == "{c78056ff-2bc1-4211-aadd-7f358def202d}" &&
                (string?)filter.Element("displayData")?.Element("name") == "Block Internet"))
                throw new UserFault("KillSwitch AmneziaVPN всё ещё блокирует прямой выход. Проверьте его состояние и переподключите VPN.");
        }
        finally { File.Delete(path); }
    }

    internal static string MakeConfig(DirectNetwork net, string[] paths, string[] roots)
    {
        var covered = new HashSet<string>(StringComparer.Ordinal);
        ulong coverage = 0;
        foreach (var prefix in net.Prefixes)
        {
            var parts = prefix.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
                !int.TryParse(parts[1], out int bits) || bits is < 0 or > 32)
                throw new UserFault("Не удалось определить диапазоны IPv4 профиля AmneziaVPN.");
            if (bits == 32) { covered.Add(prefix); continue; }
            uint number = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
            ulong block = 1UL << (32 - bits);
            coverage += block;
            covered.Add(ip + "/" + (bits + 1));
            var sibling = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(sibling, (uint)(number + block / 2));
            covered.Add(new IPAddress(sibling) + "/" + (bits + 1));
        }
        if (coverage < (1UL << 32) * 99 / 100 || covered.Count > 256)
            throw new UserFault("Нужен полный профиль AmneziaVPN с маршрутом для всего интернета. Проверьте, что включён основной профиль.");
        var exclusions = PrivateRanges.Concat(net.Protected).Append(net.PhysicalAddress + "/32").Distinct().ToArray();
        var rules = new List<object>();
        // Separate rule objects are intentional: path and folder matching must be alternatives.
        if (paths.Length != 0) rules.Add(new { process_path = paths, action = "route", outbound = "isp" });
        if (roots.Length != 0) rules.Add(new { process_path_regex = roots.Select(DirectRules.PathPattern).ToArray(), action = "route", outbound = "isp" });
        return JsonSerializer.Serialize(new
        {
            log = new { disabled = true },
            inbounds = new[] { new { type = "tun", tag = "vpslink", interface_name = Adapter, address = new[] { "172.31.254.1/30" },
                mtu = 1400, auto_route = true, strict_route = false, dns_mode = "disabled", stack = "gvisor",
                route_address = covered.OrderBy(s => s, StringComparer.Ordinal), route_exclude_address = exclusions } },
            outbounds = new[]
            {
                new { type = "direct", tag = "isp", bind_interface = net.Physical, inet4_bind_address = net.PhysicalAddress },
                new { type = "direct", tag = "vpn", bind_interface = net.Vpn, inet4_bind_address = net.VpnAddress }
            },
            route = new { rules, final = "vpn" }
        });
    }

    static string Signature(DirectNetwork net) => JsonSerializer.Serialize(net with { Protected = Array.Empty<string>() });

    internal static async Task Run(Profile profile, DirectOptions options, string directory, Action<string> report, CancellationToken ct)
    {
        if (DirectRules.AmneziaConflict() is { } conflict) throw new UserFault(conflict);
        var net = await ReadNetwork(ct);
        var paths = (options.Executables ?? "").Split('\n').Select(DirectRules.NormalizeExe).OfType<string>();
        if (options.Amnezia) paths = paths.Concat(DirectRules.AmneziaPaths());
        var executables = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var roots = options.Steam ? DirectRules.SteamRoots() : Array.Empty<string>();
        if (executables.Length == 0 && roots.Length == 0) throw new UserFault("Добавьте приложения или включите Steam в списке «Напрямую».");
        if (!File.Exists(ArchivePath(directory))) throw new UserFault("Подключите ZIP sing-box в разделе «Напрямую».");
        var adapters = NetworkInterface.GetAllNetworkInterfaces();
        if (adapters.Any(adapter => adapter.Name == Adapter || adapter.GetIPProperties().UnicastAddresses.Any(address =>
            address.Address.ToString().StartsWith("172.31.254.", StringComparison.Ordinal))))
            throw new UserFault("Имя или адрес адаптера VPSLink уже используются. Остановите другой тест или туннель.");

        // The executable and its DLL are staged outside the user-writable profile directory.
        var stage = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VPSLink Routing " + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stage);
        try
        {
            await CheckFilters(stage, ct);
            await using (var input = File.OpenRead(ArchivePath(directory)))
            {
                await VerifyArchive(input, ct);
                using var zip = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);
                foreach (var name in new[] { "sing-box.exe", "libcronet.dll" })
                {
                    ct.ThrowIfCancellationRequested();
                    var entry = zip.GetEntry("sing-box-1.14.4-windows-amd64/" + name)
                        ?? throw new UserFault("В архиве sing-box отсутствуют файлы Windows x64.");
                    entry.ExtractToFile(Path.Combine(stage, name));
                }
            }
            var config = Path.Combine(stage, "config.json");
            var protectedEndpoints = net.Protected;
            if (profile.UseWarpCore) protectedEndpoints = protectedEndpoints.Append(WarpCore.ReadEndpoint() + "/32").ToArray();
            await File.WriteAllTextAsync(config, MakeConfig(net with { Protected = protectedEndpoints }, executables, roots), ct);
            var exe = Path.Combine(stage, "sing-box.exe");
            if ((await ReadProcess(exe, ct, "check", "-c", config)).Code != 0)
                throw new UserFault("sing-box отклонил настройки обхода.");
            if (DirectRules.AmneziaConflict() is { } changed) throw new UserFault(changed);
            if (Signature(await ReadNetwork(ct)) != Signature(net)) throw new UserFault("Маршруты Windows поменялись во время запуска. Повторите попытку.");
            string initialRoutes = DirectRouteWatch.Snapshot(net, ignoredInterface: 0);
            using var job = new RoutingJob();
            using var process = Start(exe, false, "run", "-c", config);
            try
            {
                job.Attach(process);
                var ready = Stopwatch.StartNew();
                int tunIndex;
                while ((tunIndex = AdapterIndex()) == 0)
                {
                    if (process.HasExited || ready.Elapsed > TimeSpan.FromSeconds(12))
                        throw new UserFault("sing-box не открыл сетевой адаптер. Проверьте права Windows и конфликтующие туннели.");
                    await Task.Delay(250, ct);
                }
                report("Прямой маршрут включён. Перезапустите Steam и другие выбранные приложения для новых соединений.");
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), ct);
                    if (process.HasExited) throw new UserFault("sing-box завершился. Нажмите «Повторить запуск».");
                    if (DirectRules.AmneziaConflict() is { } activeConflict) throw new UserFault(activeConflict);
                    if (AdapterIndex() != tunIndex || DirectRouteWatch.Snapshot(net, tunIndex) != initialRoutes)
                        throw new UserFault("Маршруты Windows поменялись. Проверьте VPN и нажмите «Повторить запуск».");
                }
            }
            finally { await Stop(process); }
        }
        finally
        {
            // Only known files created in this session are removed.
            foreach (var name in new[] { "sing-box.exe", "libcronet.dll", "config.json", "wfp.xml" }) File.Delete(Path.Combine(stage, name));
            Directory.Delete(stage);
        }
    }

    static int AdapterIndex() => NetworkInterface.GetAllNetworkInterfaces()
        .FirstOrDefault(n => n.Name == Adapter && n.OperationalStatus == OperationalStatus.Up)?
        .GetIPProperties().GetIPv4Properties()?.Index ?? 0;

    static Process Start(string path, bool capture, params string[] arguments)
    {
        var info = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Environment.SystemDirectory,
            RedirectStandardOutput = capture, StandardOutputEncoding = capture ? Encoding.UTF8 : null };
        info.Environment["Path"] = Environment.SystemDirectory;
        if (Path.GetFileName(path).Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
            info.Environment["PSModulePath"] = Path.Combine(Path.GetDirectoryName(path)!, "Modules");
        foreach (var arg in arguments) info.ArgumentList.Add(arg);
        return Process.Start(info) ?? throw new UserFault("Не удалось запустить компонент прямого маршрута.");
    }

    static async Task<(int Code, string Text)> ReadProcess(string path, CancellationToken ct, params string[] args)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var process = Start(path, true, args);
        try
        {
            var read = process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync(timeout.Token);
            return (process.ExitCode, await read.WaitAsync(timeout.Token));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new UserFault("Проверка Windows или sing-box заняла слишком много времени."); }
        finally { await Stop(process); }
    }

    static async Task Stop(Process process)
    {
        if (process.HasExited) return;
        try { process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) when (process.HasExited) { return; }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await process.WaitForExitAsync(timeout.Token);
    }
}
