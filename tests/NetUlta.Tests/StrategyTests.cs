using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NetUlta;

static class StrategyTests
{
    static void Assert(bool condition, string message) { if (!condition) throw new Exception("FAIL: " + message); Console.WriteLine("PASS: " + message); }
    static bool Rejected(Action action) { try { action(); return false; } catch (Exception e) when (e is UserFault or JsonException) { return true; } }
    const string Revision = "0123456789abcdef0123456789abcdef01234567";
    const string Preset = "start zapret /min winws.exe --wf-tcp=80,443 ^\r\n" +
        "--filter-tcp=80 --dpi-desync=fake --new ^\r\n" +
        "--filter-tcp=443 --hostlist=\"%~dp0files\\list.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new ^\r\n" +
        "--filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=badseq,md5sig --new ^\r\n" +
        "--filter-l7=quic --dpi-desync=fake --dpi-desync-fake-quic=\"payload.bin\"\r\n";
    static string Blob(byte[] data) => Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes("blob " + data.Length + "\0").Concat(data).ToArray())).ToLowerInvariant();
    static StrategyCatalog Catalog(string source = Preset) => WinwsStrategies.Import(source, Revision, Blob(Encoding.UTF8.GetBytes(source)), DateTime.UtcNow);
    public static async Task Run()
    {
        foreach (var strategy in WinwsStrategies.Builtins())
        {
            WinwsStrategies.Validate(strategy);
            var args = WinwsStrategies.Arguments(IPAddress.Parse("192.0.2.44"), strategy);
            Assert(args[0] == "--wf-raw=outbound and ip and tcp and tcp.DstPort == 443 and ip.DstAddr == 192.0.2.44" && args[1] == "--filter-tcp=443" && args.Skip(2).SequenceEqual(strategy.Arguments),
                "strategy filter remains limited to one endpoint and TCP 443: " + strategy.Id);
        }
        Assert(WinwsStrategies.Default.Arguments.SequenceEqual(new[]{"--dpi-desync=multisplit","--dpi-desync-split-pos=1"}), "default strategy preserves 0.3.1 behavior");
        foreach (var invalid in new[] { "--wf-tcp=1-65535", "--wf-raw=true", "--filter-udp=443", "--new", "--debug=@secret.txt", "--dpi-desync-fake-tls=@secret.txt", "--dpi-desync=lua", "--dpi-desync-repeats=999999", "--dpi-desync-split-pos=1&calc.exe", "--dpi-desync=multisplit\n--wf-tcp=80", "--dpi-desync-fake-tls-mod=sni=x;evil", "--dpi-desync-fooling=ts" })
            Assert(Rejected(() => WinwsStrategies.Validate(WinwsStrategies.Default with { Arguments = new[]{"--dpi-desync=fake",invalid} })), "unsafe or incompatible strategy argument rejected");
        Assert(Rejected(() => WinwsStrategies.Arguments(IPAddress.Loopback, WinwsStrategies.Default)), "strategy cannot target loopback proxy");
        var catalog = Catalog();
        Assert(catalog.Strategies.Length == 2 && catalog.Strategies.All(s => s.Arguments.All(a => a.StartsWith("--dpi-desync"))), "only compatible TLS sections imported; host lists and UDP are not applied");
        foreach (string tail in new[]{" & calc.exe", " --lua-init=@payload.lua", " --dpi-desync-fake-tls=@file.bin", " --wf-raw=true", " --filter-tcp=443"})
            Assert(Rejected(() => Catalog("--filter-tcp=443 --dpi-desync=multisplit" + tail)), "unsupported section rejected as a whole");
        Assert(Catalog("--filter-tcp=443 --dpi-desync=multisplit --new --filter-tcp=443 --dpi-desync=multisplit").Strategies.Length == 1, "identical imported strategies are deduplicated");
        Assert(Rejected(() => Catalog(new string('x',65537))), "oversized strategy input rejected");
        string dir = Path.Combine(Path.GetTempPath(), "vpslink-strategies-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var store = new StrategyCatalogStore(dir); store.Save(catalog);
            byte[] before = File.ReadAllBytes(Path.Combine(dir,"winws-catalog.json"));
            Assert(Rejected(() => store.Save(catalog with { Strategies = new[]{WinwsStrategies.Default} })) && before.SequenceEqual(File.ReadAllBytes(Path.Combine(dir,"winws-catalog.json"))), "invalid catalog cannot replace known-good cache");
            Assert(Rejected(() => store.Save(catalog with { Strategies = new[]{catalog.Strategies[0] with {Id="split-1"}} })), "downloaded catalog cannot impersonate a built-in strategy");
            var changed = Catalog("--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=2"); store.Save(changed);
            Assert(store.CanRollback && store.Rollback().Strategies.Length == 2 && store.Load()!.Strategies.Length == 2, "previous catalog can be restored atomically");
            byte[] backup = File.ReadAllBytes(Path.Combine(dir,"winws-catalog.json.bak"));
            File.WriteAllText(Path.Combine(dir,"winws-catalog.json"), "{broken");
            store.Save(catalog);
            Assert(store.Load()!.Strategies.Length == 2 && backup.SequenceEqual(File.ReadAllBytes(Path.Combine(dir,"winws-catalog.json.bak"))), "repairing corrupt catalog preserves the last good backup");
            var snapshot = WinwsStrategies.Snapshot(catalog.Strategies[0]);
            var profile = new Profile { Name="fixture", WinwsStrategy=snapshot, ProtectedCredential="unchanged-encrypted-fixture" };
            var profiles = new ProfileStore(dir); profiles.Save(new[]{profile});
            store.Save(changed);
            var loaded = profiles.Load().Single();
            Assert(loaded.WinwsStrategy!.Arguments.SequenceEqual(snapshot.Arguments) && loaded.ProtectedCredential == profile.ProtectedCredential && !loaded.AutoConnect && !loaded.StartWithWindows, "catalog updates preserve per-profile strategy snapshot, credentials and manual connection");
            Assert(JsonSerializer.Deserialize<Profile>("{\"Name\":\"legacy\"}")!.WinwsStrategy == null, "legacy profiles default without a migration write");
            int requests = 0;
            using (var client = new StrategyCatalogClient(new Handler(request =>
            {
                requests++;
                Assert(request.RequestUri!.Host == "api.github.com" && request.RequestUri.AbsolutePath.StartsWith("/repos/bol-van/zapret-win-bundle/"), "catalog source is fixed to official repository");
                if (requests == 1) return Json(new { @object = new { sha=Revision, type="commit" } });
                Assert(request.RequestUri.Query == "?ref="+Revision, "catalog download pinned to resolved commit");
                byte[] data = Encoding.UTF8.GetBytes(Preset);
                return Json(new { type="file", path=WinwsStrategies.PresetPath, encoding="base64", size=data.Length, content=Convert.ToBase64String(data), sha=Blob(data) });
            }))) Assert((await client.Fetch(CancellationToken.None)).Strategies.Length == 2 && requests == 2, "GitHub catalog fetch verifies Git blob identity");
            foreach (string failure in new[]{"redirect","rate","oversize","hash","path"})
            {
                int calls=0;
                using var client = new StrategyCatalogClient(new Handler(_ =>
                {
                    calls++;
                    if (failure=="redirect") { var r=new HttpResponseMessage(HttpStatusCode.Redirect); r.Headers.Location=new Uri("https://example.com/commands"); return r; }
                    if (failure=="rate") return new(HttpStatusCode.Forbidden);
                    if (failure=="oversize") return new(HttpStatusCode.OK){Content=new StringContent(new string('x',131073))};
                    if (calls==1) return Json(new { @object = new { sha=Revision,type="commit" } });
                    byte[] bytes=Encoding.UTF8.GetBytes(Preset);
                    return Json(new {type="file",path=failure=="path"?"other.cmd":WinwsStrategies.PresetPath,encoding="base64",size=bytes.Length,content=Convert.ToBase64String(bytes),sha=failure=="hash"?new string('a',40):Blob(bytes)});
                }));
                bool failed=false;try{await client.Fetch(CancellationToken.None);}catch(UserFault){failed=true;}
                Assert(failed, "catalog rejects " + failure + " without executing or replacing anything");
            }
            var attempts=new List<StrategyAttempt>(); int probeCalls=0;
            var selected=await StrategyProbe.Select(WinwsStrategies.Builtins(), (s,ct)=>{probeCalls++; if(probeCalls==1)throw new UserFault("fixture failure"); return Task.CompletedTask;},attempts.Add,CancellationToken.None);
            Assert(probeCalls==2 && selected!.Id=="split-2" && attempts.Count==2 && !attempts[0].Success && attempts[1].Success, "automatic selection stops at first confirmed candidate and reports failures");
            var none = await StrategyProbe.Select(WinwsStrategies.Builtins(), (s,ct)=>throw new UserFault("unreachable fixture"), _=>{}, CancellationToken.None);
            Assert(none == null && profiles.Load().Single().WinwsStrategy == loaded.WinwsStrategy, "all failures leave the persisted strategy unchanged");
            using var cancel=new CancellationTokenSource();
            bool cancelled=false;try{await StrategyProbe.Select(WinwsStrategies.Builtins(), (s,ct)=>{cancel.Cancel();return Task.FromCanceled(ct);},_=>throw new Exception("unexpected report"),cancel.Token);}catch(OperationCanceledException){cancelled=true;}
            Assert(cancelled, "cancellation stops strategy iteration without selecting or saving a candidate");
        }
        finally { Directory.Delete(dir,true); }
    }
    static HttpResponseMessage Json(object value)=>new(HttpStatusCode.OK){Content=new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value))};
    sealed class Handler : HttpMessageHandler
    {
        readonly Func<HttpRequestMessage,HttpResponseMessage> response;
        public Handler(Func<HttpRequestMessage,HttpResponseMessage> response)=>this.response=response;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>Task.FromResult(response(request));
    }
}
