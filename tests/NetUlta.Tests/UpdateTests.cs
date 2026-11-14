using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NetUlta;

static class UpdateTests
{
    static void Assert(bool value, string message) { if (!value) throw new Exception(message); Console.WriteLine("PASS: " + message); }
    static byte[] Fixture(byte[] payload, string url = "", string digest = "", string tag = "v0.3.2", bool preview = false) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        draft = false, prerelease = preview, tag_name = tag,
        assets = new[] { new { name = "VPSLink-0.3.2-Setup.exe", size = payload.Length,
            digest = digest.Length == 0 ? "sha256:" + Convert.ToHexString(SHA256.HashData(payload)) : digest,
            browser_download_url = url.Length == 0 ? "https://github.com/fixture/link/releases/download/v0.3.2/VPSLink-0.3.2-Setup.exe" : url } }
    });
    public static async Task Run()
    {
        byte[] payload = Encoding.UTF8.GetBytes("fixture installer bytes; never executed");
        var current = new Version(0, 3, 1);
        var release = Updates.Parse(Fixture(payload), "fixture/link", current)!;
        Assert(Updates.Parse(Fixture(payload, preview: true), "fixture/link", current, true)?.Version == new Version(0, 3, 2),
            "explicit PoC channel accepts a preview release");
        using (var previewClient = new Updates("fixture/link", new Handler(request =>
        {
            Assert(request.RequestUri!.Query == "?per_page=20", "PoC channel queries release list");
            return new(HttpStatusCode.OK) { Content = new StringContent("[" + Encoding.UTF8.GetString(Fixture(payload, preview: true)) + "]") };
        }), includePrereleases: true))
            Assert((await previewClient.Check(current, CancellationToken.None))?.Version == new Version(0, 3, 2), "PoC release is discoverable through GitHub list response");
        Assert(release.Version == new Version(0, 3, 2) &&
            Updates.Parse(Fixture(payload), "fixture/link", new Version(0, 3, 2)) == null &&
            Updates.Parse(Fixture(payload), "fixture/link", new Version(0, 4, 0)) == null &&
            Updates.Parse(Fixture(payload, preview: true), "fixture/link", current) == null,
            "updater accepts only newer stable releases; no downgrade");
        foreach (var json in new[] { Fixture(payload, url: "https://example.org/setup.exe"), Fixture(payload, digest: "sha256:broken") })
        {
            bool rejected = false;
            try { Updates.Parse(json, "fixture/link", current); } catch (UserFault) { rejected = true; }
            Assert(rejected, "updater rejects foreign downloads or missing integrity data");
        }
        string dir = Path.Combine(Path.GetTempPath(), "tfl-updates-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using var client = new Updates("fixture/link", new Handler(request =>
            {
                if (request.RequestUri!.Host == "api.github.com") return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Fixture(payload)) };
                if (request.RequestUri.Host == "github.com") { var response = new HttpResponseMessage(HttpStatusCode.Redirect); response.Headers.Location = new Uri("https://release-assets.githubusercontent.com/fixture"); return response; }
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) };
            }));
            var checkedRelease = await client.Check(current, CancellationToken.None);
            string path = await client.Download(checkedRelease!, dir, CancellationToken.None);
            Assert(File.ReadAllBytes(path).SequenceEqual(payload), "updater follows GitHub asset redirect and verifies downloaded bytes");
            File.WriteAllText(path, "tampered");
            bool tamperRejected = false;
            try { Updates.Verify(path, release); } catch (UserFault) { tamperRejected = true; }
            Assert(tamperRejected, "updater rechecks installer before launch");
            foreach (bool foreignRedirect in new[] { false, true })
            {
                using var bad = new Updates("fixture/link", new Handler(_ =>
                {
                    if (foreignRedirect) { var response = new HttpResponseMessage(HttpStatusCode.Redirect); response.Headers.Location = new Uri("http://example.org/payload"); return response; }
                    return new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[payload.Length]) };
                }));
                bool rejected = false;
                try { await bad.Download(release, dir, CancellationToken.None); } catch (UserFault) { rejected = true; }
                Assert(rejected && File.ReadAllText(path) == "tampered" && Directory.GetFiles(dir, "*.download").Length == 0,
                    "failed update leaves prior file intact and removes partial download");
            }
        }
        finally { Directory.Delete(dir, true); }
    }
    sealed class Handler : HttpMessageHandler
    {
        readonly Func<HttpRequestMessage, HttpResponseMessage> respond;
        public Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) { this.respond = respond; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }
}
