using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetUlta;

sealed record ReleaseUpdate(Version Version, Uri Download, string Sha256, long Size, string FileName);

static class UpdateSource
{
    public static readonly string Repository = "JOOOOOJA/VPSLink";
    public static readonly bool IncludePrereleases = true; // Explicit Proof-of-Concept channel.
    public static bool Configured => Repository.Length > 0;
}

sealed class Updates : IDisposable
{
    const long MaxInstaller = 256L * 1024 * 1024;
    readonly HttpClient http;
    readonly string repository;
    readonly bool includePrereleases;
    public Updates(string repository, HttpMessageHandler? handler = null, bool includePrereleases = false)
    {
        if (!Regex.IsMatch(repository, @"\A[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\z"))
            throw new UserFault("Источник обновлений ещё не настроен.");
        this.repository = repository;
        this.includePrereleases = includePrereleases;
        http = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("VPSLink/" + Application.ProductVersion.Split('+')[0]);
    }
    public async Task<ReleaseUpdate?> Check(Version current, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/repos/" + repository +
            (includePrereleases ? "/releases?per_page=20" : "/releases/latest"));
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.Add("X-GitHub-Api-Version", "2026-03-10");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (response.StatusCode == HttpStatusCode.NotFound) throw new UserFault("Публичный релиз пока не опубликован.");
        response.EnsureSuccessStatusCode();
        using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(chunk.AsMemory(), timeout.Token)) > 0)
        {
            if (buffer.Length + count > 1024 * 1024) throw new UserFault("Ответ сервера обновлений слишком большой.");
            buffer.Write(chunk, 0, count);
        }
        if (!includePrereleases) return Parse(buffer.ToArray(), repository, current);
        using var releases = JsonDocument.Parse(buffer.ToArray());
        if (releases.RootElement.ValueKind != JsonValueKind.Array) throw new UserFault("Неизвестный ответ сервера обновлений.");
        return releases.RootElement.EnumerateArray()
            .Select(item => Parse(System.Text.Encoding.UTF8.GetBytes(item.GetRawText()), repository, current, true))
            .Where(item => item != null).OrderByDescending(item => item!.Version).FirstOrDefault();
    }
    internal static ReleaseUpdate? Parse(byte[] json, string repository, Version current, bool includePrereleases = false)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.GetProperty("draft").GetBoolean() || (!includePrereleases && root.GetProperty("prerelease").GetBoolean())) return null;
        string tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!Regex.IsMatch(tag, @"\Av?\d+\.\d+\.\d+\z") || !Version.TryParse(tag.TrimStart('v'), out var version))
            throw new UserFault("Неизвестный формат версии обновления.");
        if (version <= new Version(current.Major, current.Minor, Math.Max(0, current.Build))) return null;
        string name = $"VPSLink-{version}-Setup.exe";
        var assets = root.GetProperty("assets").EnumerateArray().Where(a => a.GetProperty("name").GetString() == name).ToArray();
        if (assets.Length != 1) throw new UserFault("В релизе не найден единственный установщик Windows x64.");
        var asset = assets[0];
        string expected = $"https://github.com/{repository}/releases/download/{tag}/{name}";
        if (asset.GetProperty("browser_download_url").GetString() != expected)
            throw new UserFault("Установщик находится вне репозитория приложения.");
        string digest = asset.TryGetProperty("digest", out var d) ? d.GetString() ?? "" : "";
        long size = asset.GetProperty("size").GetInt64();
        if (!Regex.IsMatch(digest, @"\Asha256:[a-fA-F0-9]{64}\z") || size <= 0 || size > MaxInstaller)
            throw new UserFault("Установщик не имеет допустимого размера или контрольной суммы SHA-256.");
        return new(version, new Uri(expected), digest[7..], size, name);
    }
    public async Task<string> Download(ReleaseUpdate release, string directory, CancellationToken ct)
    {
        Directory.CreateDirectory(directory);
        string temp = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".download");
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(5));
            var uri = release.Download;
            for (int redirect = 0; redirect <= 5; redirect++)
            {
                if (uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Port != 443 ||
                    uri.Host is not ("github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com"))
                    throw new UserFault("Сервер загрузки обновления не разрешён.");
                using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                if ((int)response.StatusCode is >= 300 and < 400)
                {
                    var next = response.Headers.Location ?? throw new UserFault("Сервер не указал адрес загрузки.");
                    uri = next.IsAbsoluteUri ? next : new Uri(uri, next);
                    continue;
                }
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentLength is long length && length != release.Size)
                    throw new UserFault("Размер обновления изменился. Проверьте обновления заново.");
                using (var source = await response.Content.ReadAsStreamAsync(timeout.Token))
                using (var target = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var chunk = new byte[65536];
                    long total = 0;
                    int count;
                    while ((count = await source.ReadAsync(chunk.AsMemory(), timeout.Token)) > 0)
                    {
                        total += count;
                        if (total > release.Size || total > MaxInstaller) throw new UserFault("Размер обновления превышен.");
                        await target.WriteAsync(chunk.AsMemory(0, count), timeout.Token);
                    }
                }
                Verify(temp, release);
                string path = Path.Combine(directory, release.FileName);
                File.Move(temp, path, overwrite: true);
                return path;
            }
            throw new UserFault("Слишком много перенаправлений загрузки.");
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public static void Verify(string path, ReleaseUpdate release)
    {
        using var file = File.OpenRead(path);
        using var sha = SHA256.Create();
        if (file.Length != release.Size || !Convert.ToHexString(sha.ComputeHash(file)).Equals(release.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new UserFault("Проверка обновления не пройдена. Установка отменена.");
    }
    public void Dispose() => http.Dispose();
}
