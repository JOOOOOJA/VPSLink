using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetUlta;

sealed partial class StrategyCatalogClient
{
    sealed record SourceFile(string Path, string Sha, int Size);
    internal static bool IsFlowPreset(string path) => Regex.IsMatch(path, @"\Ageneral(?: \([A-Z0-9 ]{1,40}\))?\.bat\z");
    internal static bool IsFlowPayload(string path) => Regex.IsMatch(path, @"\Abin/(?:tls_clienthello_[a-z0-9_]{1,80}|stun[0-9]?)\.bin\z");
    public Task<StrategyCatalog> Fetch(string repository, CancellationToken ct) => repository switch
    {
        WinwsStrategies.Repository => Fetch(ct),
        WinwsStrategies.FlowsealRepository => FetchFlowseal(ct),
        _ => throw new UserFault("Неизвестный источник стратегий.")
    };
    static void VerifyBlob(byte[] bytes, SourceFile file)
    {
        byte[] header = Encoding.ASCII.GetBytes("blob " + bytes.Length.ToString(CultureInfo.InvariantCulture) + "\0");
        string actual = Convert.ToHexString(SHA1.HashData(header.Concat(bytes).ToArray())).ToLowerInvariant();
        if (bytes.Length != file.Size || actual != file.Sha) throw new UserFault("Контрольная сумма файла Flowseal не совпала. Прежний каталог сохранён.");
    }
    async Task<StrategyCatalog> FetchFlowseal(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(3));
        ct = timeout.Token;
        const string api = "https://api.github.com/repos/" + WinwsStrategies.FlowsealRepository + "/";
        using var reference = await Read(api + "git/ref/heads/main", ct);
        var obj = reference.RootElement.GetProperty("object");
        string revision = obj.GetProperty("sha").GetString() ?? "";
        if (obj.GetProperty("type").GetString() != "commit" || !Regex.IsMatch(revision, @"\A[0-9a-f]{40}\z")) throw new UserFault("Неизвестная версия Flowseal.");
        using var tree = JsonDocument.Parse(await ReadBytes(api + "git/trees/" + revision + "?recursive=1", 1048576, ct));
        string treeSha = tree.RootElement.GetProperty("sha").GetString() ?? "";
        if (tree.RootElement.GetProperty("truncated").GetBoolean() || !Regex.IsMatch(treeSha, @"\A[0-9a-f]{40}\z")) throw new UserFault("Неполный список файлов Flowseal. Прежний каталог сохранён.");
        var entries = tree.RootElement.GetProperty("tree");
        if (entries.GetArrayLength() > 2000) throw new UserFault("Слишком много файлов в источнике Flowseal.");
        var manifest = new Dictionary<string, SourceFile>(StringComparer.Ordinal);
        foreach (var item in entries.EnumerateArray())
        {
            string path = item.GetProperty("path").GetString() ?? "";
            if (!IsFlowPreset(path) && !IsFlowPayload(path)) continue;
            int max = IsFlowPreset(path) ? 65536 : 4096;
            string sha = item.GetProperty("sha").GetString() ?? "";
            int size = item.GetProperty("size").GetInt32();
            if (item.GetProperty("type").GetString() != "blob" || item.GetProperty("mode").GetString() != "100644" ||
                size < 1 || size > max || !Regex.IsMatch(sha, @"\A[0-9a-f]{40}\z") || !manifest.TryAdd(path, new(path,sha,size)))
                throw new UserFault("Неожиданный файл в каталоге Flowseal. Прежний каталог сохранён.");
        }
        var presets = manifest.Values.Where(f => IsFlowPreset(f.Path)).OrderBy(f => f.Path == "general.bat" ? "" : f.Path, StringComparer.Ordinal).ToArray();
        if (presets.Length is < 1 or > 40 || manifest.Count > 80) throw new UserFault("Неожиданный размер каталога Flowseal.");
        async Task<byte[]> Download(SourceFile file, int limit)
        {
            string path = string.Join("/", file.Path.Split('/').Select(Uri.EscapeDataString));
            byte[] bytes = await ReadBytes("https://raw.githubusercontent.com/" + WinwsStrategies.FlowsealRepository + "/" + revision + "/" + path, limit, ct);
            VerifyBlob(bytes, file); return bytes;
        }
        var payloads = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        var all = new List<WinwsStrategy>(); var notes = new List<string>(); int skipped = 0;
        foreach (var file in presets)
        {
            string text = new UTF8Encoding(false, true).GetString(await Download(file,65536));
            foreach (Match match in Regex.Matches(text, "\"%BIN%([a-z0-9_]+\\.bin)\"", RegexOptions.IgnoreCase))
            {
                string path = "bin/" + match.Groups[1].Value;
                if (!IsFlowPayload(path) || payloads.ContainsKey(path) || !manifest.TryGetValue(path, out var payload)) continue;
                payloads.Add(path, await Download(payload,4096));
            }
            var imported = WinwsStrategies.Import(text,revision,file.Sha,DateTime.UtcNow,file.Path,payloads);
            foreach (var strategy in imported.Strategies)
            {
                var existing = all.FirstOrDefault(s => s.Id == strategy.Id);
                if (existing == null) all.Add(strategy);
                else notes.Add(file.Path + ": одинаковые TLS-параметры уже доступны как «" + existing.Name + "».");
            }
            notes.AddRange(imported.Notes ?? Array.Empty<string>()); skipped += imported.Skipped;
            if (all.Count > 96 || notes.Count > 200) throw new UserFault("Слишком много вариантов Flowseal.");
        }
        if (all.Count == 0) throw new UserFault("Нет совместимых TLS-вариантов Flowseal для текущего winws. Прежний каталог сохранён.");
        var catalog = new StrategyCatalog(revision,treeSha,DateTime.UtcNow,all.ToArray(),skipped,WinwsStrategies.FlowsealRepository,notes.ToArray());
        StrategyCatalogStore.Validate(catalog);
        return catalog;
    }
}
