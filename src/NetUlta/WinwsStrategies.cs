using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetUlta;

sealed record WinwsStrategy(string Id, string Name, string Description, string[] Arguments, string Revision = "builtin")
{
    public override string ToString() => Name;
    public bool Equals(WinwsStrategy? other) => other != null && Id == other.Id && Name == other.Name &&
        Description == other.Description && Revision == other.Revision &&
        (ReferenceEquals(Arguments, other.Arguments) || (Arguments != null && other.Arguments != null && Arguments.SequenceEqual(other.Arguments)));
    public override int GetHashCode()
    {
        var hash = new HashCode(); hash.Add(Id); hash.Add(Name); hash.Add(Description); hash.Add(Revision);
        if (Arguments != null) foreach (var arg in Arguments) hash.Add(arg);
        return hash.ToHashCode();
    }
}

static class WinwsStrategies
{
    public const string Repository = "bol-van/zapret-win-bundle";
    public const string FlowsealRepository = "Flowseal/zapret-discord-youtube";
    public const string PresetPath = "zapret-winws/preset1_example.cmd";
    public static WinwsStrategy Default => Builtins()[0];
    public static WinwsStrategy[] Builtins() => new[]
    {
        new WinwsStrategy("split-1", "Базовая · как в 0.3.1", "Разделяет начало TLS-запроса. Начните с этого варианта; он сохраняет прежнее поведение VPSLink.", new[]{"--dpi-desync=multisplit", "--dpi-desync-split-pos=1"}),
        new WinwsStrategy("split-2", "Разделение · вариант 2", "Другая граница разделения TLS. Попробуйте, если базовая стратегия не соединяется.", new[]{"--dpi-desync=multisplit", "--dpi-desync-split-pos=2"}),
        new WinwsStrategy("split-sni", "Разделение имени сайта", "Разделяет имя в TLS-запросе к WARP. Зависит от фильтрации у провайдера.", new[]{"--dpi-desync=multisplit", "--dpi-desync-split-pos=1,midsld"}),
        new WinwsStrategy("disorder-sni", "Обратный порядок частей", "Меняет порядок частей TLS-запроса. Альтернатива обычному разделению.", new[]{"--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,midsld"}),
        new WinwsStrategy("fake-split", "Ложный пакет и разделение", "Добавляет ложный пакет перед разделением. Может помочь при более строгой фильтрации.", new[]{"--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=6"}),
        new WinwsStrategy("fake-disorder", "Ложный пакет и обратный порядок", "Запасной вариант с ложными пакетами. Если не помогает, вернитесь к базовой стратегии.", new[]{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-fooling=badseq,md5sig", "--dpi-desync-repeats=6"})
    };

    public static void Validate(WinwsStrategy strategy)
    {
        if (strategy == null || strategy.Id == null || !Regex.IsMatch(strategy.Id, @"\A[a-z0-9-]{1,64}\z") ||
            !DisplayText(strategy.Name, 110) || !DisplayText(strategy.Description, 600) ||
            strategy.Revision == null || (strategy.Revision != "builtin" && !Regex.IsMatch(strategy.Revision, @"\A[0-9a-f]{40}\z")) ||
            strategy.Arguments == null || strategy.Arguments.Length is < 1 or > 24 || strategy.Arguments.Sum(a => a?.Length ?? 0) > 24000)
            throw new UserFault("Повреждены данные стратегии winws. Выберите базовую стратегию.");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        int tlsCount = 0, httpCount = 0;
        foreach (string arg in strategy.Arguments)
        {
            if (arg == null || arg.Length > 8300 || arg.Any(c => c <= 32 || c > 126)) throw Invalid();
            int equal = arg.IndexOf('=');
            if (equal < 0) throw Invalid();
            string key = arg[..equal], value = arg[(equal + 1)..];
            bool first = keys.Add(key);
            if (key == "--dpi-desync-fake-tls") { if (++tlsCount > 4) throw Invalid(); }
            else if (key == "--dpi-desync-fake-http") { if (++httpCount > 4) throw Invalid(); }
            else if (!first) throw Invalid();
            if (key == "--dpi-desync-fooling" && value.Split(',').Contains("ts"))
                throw new UserFault("Требует TCP timestamps в Windows. VPSLink не меняет эту системную настройку; вариант пропущен.");
            bool valid = key switch
            {
                "--dpi-desync" => value is "multisplit" or "multidisorder" or "fake" or "fakedsplit" or "fakeddisorder" or
                    "fake,multisplit" or "fake,multidisorder" or "fake,fakedsplit" or "fake,fakeddisorder" or
                    "syndata" or "syndata,multidisorder" or "hostfakesplit" or "fake,hostfakesplit",
                "--dpi-desync-split-pos" => value.Split(',').Length <= 8 && value.Split(',').All(Position),
                "--dpi-desync-repeats" => Number(value, 1, 12),
                "--dpi-desync-fooling" => value.Split(',').Length <= 3 && value.Split(',').Distinct().Count() == value.Split(',').Length &&
                    value.Split(',').All(v => v is "badseq" or "md5sig" or "datanoack"),
                "--dpi-desync-ttl" => Number(value, 1, 20),
                "--dpi-desync-autottl" => Number(value, 1, 5),
                "--dpi-desync-fake-tls-mod" => TlsMods(value),
                "--ip-id" => value == "zero",
                "--dpi-desync-split-seqovl" => Number(value, 1, 1500),
                "--dpi-desync-badseq-increment" => Regex.IsMatch(value, @"\A-?[0-9]{1,8}\z") && int.TryParse(value, out int increment) && Math.Abs(increment) <= 10000000,
                "--dpi-desync-split-seqovl-pattern" or "--dpi-desync-fakedsplit-pattern" or "--dpi-desync-fake-http" => HexPayload(value),
                "--dpi-desync-fake-tls" => value == "!" || HexPayload(value),
                "--dpi-desync-hostfakesplit-mod" => Regex.IsMatch(value, @"\Ahost=[a-zA-Z0-9.-]{1,120}(?:,altorder=[01])?\z"),
                _ => false
            };
            if (!valid) throw Invalid();
        }
        if (!keys.Contains("--dpi-desync")) throw Invalid();
    }
    static UserFault Invalid() => new("В стратегии есть параметры, несовместимые с безопасным режимом WARP в этой версии VPSLink.");
    static bool DisplayText(string? value, int max) => !string.IsNullOrWhiteSpace(value) && value.Length <= max && !value.Any(char.IsControl);
    static bool Number(string value, int min, int max) => Regex.IsMatch(value, @"\A[0-9]{1,4}\z") && int.TryParse(value, out int number) && number >= min && number <= max;
    static bool Position(string value) => Number(value, 1, 1500) || Regex.IsMatch(value, @"\A(?:midsld|sld|host|endhost|sniext)(?:\+[1-9][0-9]{0,2})?\z");
    static bool HexPayload(string value) => value.Length is >= 4 and <= 8194 && value.Length % 2 == 0 && Regex.IsMatch(value, @"\A0x[0-9a-fA-F]+\z");
    static bool TlsMods(string value)
    {
        if (value == "none") return true;
        var parts = value.Split(',');
        return parts.Length is >= 1 and <= 3 && parts.Distinct().Count() == parts.Length && parts.Count(p => p.StartsWith("sni=")) <= 1 &&
            parts.All(p => p is "rnd" or "dupsid" || (p.StartsWith("sni=", StringComparison.Ordinal) && p.Length <= 128 &&
                Regex.IsMatch(p[4..], @"\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\z") && Uri.CheckHostName(p[4..]) == UriHostNameType.Dns));
    }
    public static string[] Arguments(IPAddress endpoint, WinwsStrategy strategy)
    {
        Validate(strategy);
        if (endpoint.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(endpoint) || endpoint.Equals(IPAddress.Any) ||
            endpoint.Equals(IPAddress.Broadcast) || endpoint.GetAddressBytes()[0] >= 224) throw new UserFault("Некорректный IPv4-адрес WARP.");
        return new[] { $"--wf-raw=outbound and ip and tcp and tcp.DstPort == 443 and ip.DstAddr == {endpoint}", "--filter-tcp=443" }
            .Concat(strategy.Arguments).ToArray();
    }
    public static WinwsStrategy Snapshot(WinwsStrategy strategy)
    {
        Validate(strategy);
        return strategy with { Arguments = strategy.Arguments.ToArray() };
    }

    // This is a restricted data importer, not a CMD interpreter. No downloaded command is executed.
    public static StrategyCatalog Import(string source, string revision, string blobSha, DateTime fetchedUtc,
        string? flowFile = null, IReadOnlyDictionary<string, byte[]>? payloads = null)
    {
        if (source.Length > 65536 || source.Contains('\0') || !Regex.IsMatch(revision, @"\A[0-9a-f]{40}\z") || !Regex.IsMatch(blobSha, @"\A[0-9a-f]{40}\z")) throw Invalid();
        var result = new List<WinwsStrategy>();
        int skipped = 0, tlsBlock = 0;
        var notes = new List<string>();
        string joined = Regex.Replace(source, @"\^\r?\n", " ");
        foreach (string block in Regex.Split(joined, @"(?<!\S)--new(?=\s|$)"))
        {
            var filter = Regex.Match(block, @"(?<!\S)--filter-tcp=([^\s]+)");
            if (!filter.Success || !filter.Groups[1].Value.Split(',').Contains("443")) continue;
            tlsBlock++;
            string section = block[filter.Index..].Trim();
            var tokens = Regex.Matches(section, "(?:[^\\s\"]|\"[^\"\\r\\n]*\")+").Cast<Match>().Select(m => m.Value).ToArray();
            var arguments = new List<string>();
            bool rejected = false, sawFilter = false;
            foreach (string original in tokens)
            {
                string token = original;
                if (token.StartsWith("--filter-tcp=", StringComparison.Ordinal))
                { if (sawFilter || token != filter.Value || !Regex.IsMatch(token, @"\A--filter-tcp=(?:[0-9]{1,5},)*[0-9]{1,5}\z")) rejected = true; sawFilter = true; continue; }
                if (new[]{"--hostlist=", "--hostlist-exclude=", "--hostlist-domains=", "--hostlist-exclude-domains=", "--ipset=", "--ipset-exclude="}.Any(p => token.StartsWith(p, StringComparison.Ordinal))) continue;
                if (flowFile != null && token.StartsWith("--dpi-desync", StringComparison.Ordinal))
                {
                    int equal = token.IndexOf('=');
                    string value = equal < 0 ? "" : token[(equal+1)..];
                    var file = Regex.Match(value, "\\A\"%BIN%([a-z0-9_]+\\.bin)\"\\z", RegexOptions.IgnoreCase);
                    if (file.Success && payloads != null && payloads.TryGetValue("bin/" + file.Groups[1].Value, out var bytes) && bytes.Length is > 0 and <= 4096)
                        token = token[..(equal+1)] + "0x" + Convert.ToHexString(bytes).ToLowerInvariant();
                    else if (value == "^!" && token.StartsWith("--dpi-desync-fake-tls=")) token = "--dpi-desync-fake-tls=!";
                }
                if (!token.StartsWith("--dpi-desync", StringComparison.Ordinal) && !token.StartsWith("--ip-id=", StringComparison.Ordinal)) { rejected = true; break; }
                arguments.Add(token);
            }
            string[] args = arguments.ToArray();
            string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", args)))).ToLowerInvariant();
            var strategy = new WinwsStrategy((flowFile == null ? "upstream-" : "flowseal-") + digest[..16],
                flowFile == null ? "zapret · TLS-вариант " + tlsBlock : "Flowseal · " + Path.GetFileNameWithoutExtension(flowFile) + " · TLS " + tlsBlock,
                "TLS-параметры " + (flowFile == null ? "примера bol-van" : flowFile) + ". Адаптированы для WARP; фильтры сайтов и IP заменены точным адресом MASQUE. Шаблоны пакетов сохраняются в параметрах.", args, revision);
            try { if (rejected) throw Invalid(); Validate(strategy); }
            catch (UserFault e) { skipped++; if (flowFile != null) notes.Add(flowFile + " · TLS " + tlsBlock + ": " + e.Message); continue; }
            if (!result.Any(s => s.Id == strategy.Id)) result.Add(strategy);
            if (result.Count > 32) throw Invalid();
        }
        if (result.Count == 0 && flowFile == null) throw new UserFault("В текущем примере zapret нет совместимых TLS-стратегий для winws этой версии. Прежний каталог сохранён.");
        return new(revision, blobSha, fetchedUtc, result.ToArray(), skipped, flowFile == null ? Repository : FlowsealRepository, notes.ToArray());
    }
}

sealed record StrategyCatalog(string Revision, string BlobSha, DateTime FetchedUtc, WinwsStrategy[] Strategies, int Skipped,
    string Repository = WinwsStrategies.Repository, string[]? Notes = null);

sealed class StrategyCatalogStore
{
    readonly string path;
    public StrategyCatalogStore(string directory) => path = Path.Combine(directory, "winws-catalog.json");
    public bool CanRollback => File.Exists(path + ".bak");
    static StrategyCatalog Read(string file)
    {
        if (new FileInfo(file).Length > 1048576) throw new UserFault("Каталог стратегий слишком большой.");
        var catalog = JsonSerializer.Deserialize<StrategyCatalog>(File.ReadAllBytes(file)) ?? throw new UserFault("Каталог стратегий повреждён.");
        Validate(catalog);
        return catalog;
    }
    internal static void Validate(StrategyCatalog catalog)
    {
        if (catalog.Revision == null || !Regex.IsMatch(catalog.Revision, @"\A[0-9a-f]{40}\z") || catalog.BlobSha == null ||
            !Regex.IsMatch(catalog.BlobSha, @"\A[0-9a-f]{40}\z") || catalog.Strategies == null || catalog.Strategies.Length is < 1 or > 96 ||
            catalog.Repository is not (WinwsStrategies.Repository or WinwsStrategies.FlowsealRepository) ||
            (catalog.Notes != null && (catalog.Notes.Length > 200 || catalog.Notes.Any(n => n == null || n.Length > 700 || n.Any(char.IsControl)))) ||
            catalog.Skipped is < 0 or > 200 || catalog.Strategies.Any(s => s == null || s.Revision != catalog.Revision) ||
            catalog.Strategies.Select(s => s.Id).Distinct().Count() != catalog.Strategies.Length) throw new UserFault("Каталог стратегий повреждён.");
        foreach (var strategy in catalog.Strategies)
        {
            WinwsStrategies.Validate(strategy);
            string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", strategy.Arguments)))).ToLowerInvariant();
            if (strategy.Id != (catalog.Repository == WinwsStrategies.Repository ? "upstream-" : "flowseal-") + digest[..16]) throw new UserFault("Идентификатор стратегии не соответствует её параметрам.");
        }
    }
    public StrategyCatalog? Load() => File.Exists(path) ? Read(path) : null;
    public void Save(StrategyCatalog catalog)
    {
        Validate(catalog);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(catalog));
            _ = Read(temp);
            if (File.Exists(path))
            {
                string backup = path + ".bak";
                try { _ = Read(path); }
                catch (Exception e) when (e is UserFault or JsonException)
                { backup = path + ".corrupt-" + Guid.NewGuid().ToString("N"); }
                File.Replace(temp, path, backup);
            }
            else File.Move(temp, path);
        }
        finally { File.Delete(temp); }
    }
    public StrategyCatalog Rollback()
    {
        var previous = Read(path + ".bak");
        Save(previous);
        return previous;
    }
}

sealed partial class StrategyCatalogClient : IDisposable
{
    readonly HttpClient http;
    const string Api = "https://api.github.com/repos/" + WinwsStrategies.Repository + "/";
    public StrategyCatalogClient(HttpMessageHandler? handler = null)
    {
        http = new(handler ?? new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("VPSLink-strategies/1");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    }
    async Task<JsonDocument> Read(string url, CancellationToken ct)
        => JsonDocument.Parse(await ReadBytes(url, 131072, ct));
    async Task<byte[]> ReadBytes(string url, int limit, CancellationToken ct)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            throw new UserFault("GitHub временно ограничил запросы. Повторите позже; текущие стратегии доступны без сети.");
        if ((int)response.StatusCode is >= 300 and < 400) throw new UserFault("GitHub изменил адрес каталога. Обновите VPSLink; прежний каталог сохранён.");
        response.EnsureSuccessStatusCode();
        using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream();
        var bytes = new byte[8192]; int count;
        while ((count = await stream.ReadAsync(bytes.AsMemory(), ct)) > 0)
        {
            if (output.Length + count > limit) throw new UserFault("Ответ каталога GitHub слишком большой.");
            output.Write(bytes, 0, count);
        }
        return output.ToArray();
    }
    public async Task<StrategyCatalog> Fetch(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(40));
        using var reference = await Read(Api + "git/ref/heads/master", timeout.Token);
        var obj = reference.RootElement.GetProperty("object");
        string revision = obj.GetProperty("sha").GetString() ?? "";
        if (obj.GetProperty("type").GetString() != "commit" || !Regex.IsMatch(revision, @"\A[0-9a-f]{40}\z")) throw new UserFault("GitHub вернул неизвестную версию каталога.");
        using var content = await Read(Api + "contents/" + WinwsStrategies.PresetPath + "?ref=" + revision, timeout.Token);
        var file = content.RootElement;
        if (file.GetProperty("type").GetString() != "file" || file.GetProperty("path").GetString() != WinwsStrategies.PresetPath ||
            file.GetProperty("encoding").GetString() != "base64" || file.GetProperty("size").GetInt32() is < 1 or > 65536)
            throw new UserFault("Неверный файл каталога zapret.");
        byte[] payload = Convert.FromBase64String(file.GetProperty("content").GetString() ?? "");
        string blob = file.GetProperty("sha").GetString() ?? "";
        byte[] header = Encoding.ASCII.GetBytes("blob " + payload.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\0");
        string actual = Convert.ToHexString(SHA1.HashData(header.Concat(payload).ToArray())).ToLowerInvariant();
        if (payload.Length != file.GetProperty("size").GetInt32() || blob != actual) throw new UserFault("Контрольная сумма каталога GitHub не совпала.");
        return WinwsStrategies.Import(new UTF8Encoding(false, true).GetString(payload), revision, blob, DateTime.UtcNow);
    }
    public void Dispose() => http.Dispose();
}
