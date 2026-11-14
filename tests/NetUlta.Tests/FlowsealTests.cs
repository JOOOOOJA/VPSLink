using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NetUlta;

static class FlowsealTests
{
    const string Revision = "0123456789abcdef0123456789abcdef01234567";
    const string PayloadPath = "bin/tls_clienthello_fixture.bin";
    const string Preset = "@echo off\r\ncall service.bat check_updates\r\n" +
        "start winws.exe --wf-tcp=80,443 ^\r\n" +
        "--filter-tcp=443 --hostlist=\"%LISTS%list.txt\" --ipset-exclude=\"%LISTS%exclude.txt\" --ip-id=zero --dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-split-seqovl=681 --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_fixture.bin\" --new ^\r\n" +
        "--filter-tcp=443 --dpi-desync=fake --dpi-desync-fooling=ts\r\n";
    static readonly byte[] Payload = { 0x16,0x03,0x01,0,0 };
    static string Blob(byte[] data) => Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes("blob " + data.Length + "\0").Concat(data).ToArray())).ToLowerInvariant();
    static void Assert(bool value, string label) { if (!value) throw new Exception("FAIL: " + label); Console.WriteLine("PASS: " + label); }
    public static async Task Run()
    {
        var blobs = new Dictionary<string,byte[]> { [PayloadPath] = Payload };
        var imported = WinwsStrategies.Import(Preset,Revision,Blob(Encoding.UTF8.GetBytes(Preset)),DateTime.UtcNow,"general.bat",blobs);
        StrategyCatalogStore.Validate(imported);
        Assert(imported.Repository == WinwsStrategies.FlowsealRepository && imported.Strategies.Length == 1 && imported.Strategies[0].Name.Contains("general"), "Flowseal names and source retained");
        Assert(imported.Strategies[0].Arguments.Contains("--dpi-desync-split-seqovl-pattern=0x1603010000") && imported.Strategies[0].Arguments.Contains("--ip-id=zero"), "Flowseal packet data and compatible parameters preserved without file paths");
        Assert(imported.Skipped == 1 && imported.Notes!.Single().Contains("TCP timestamps"), "unsupported timestamp strategy is explained, not silently simplified");
        var repeated = WinwsStrategies.Import("--filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=0x00 --dpi-desync-fake-tls=^! --dpi-desync-fake-tls-mod=none",Revision,Revision,DateTime.UtcNow,"general (FAKE TLS AUTO).bat",blobs);
        Assert(repeated.Strategies.Single().Arguments.Count(a=>a.StartsWith("--dpi-desync-fake-tls=")) == 2 && repeated.Strategies[0].Arguments.Contains("--dpi-desync-fake-tls=!"), "multiple TLS templates and CMD escaped default marker preserved in order");
        var unknown = WinwsStrategies.Import("--filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=\"%BIN%missing.bin\"",Revision,Revision,DateTime.UtcNow,"general.bat",blobs);
        Assert(unknown.Strategies.Length == 0 && unknown.Skipped == 1, "unresolved packet template rejects entire TLS variant");
        Assert(!StrategyCatalogClient.IsFlowPreset("../general.bat") && !StrategyCatalogClient.IsFlowPreset("service.bat") &&
            !StrategyCatalogClient.IsFlowPayload("bin/../../secret.bin") && !StrategyCatalogClient.IsFlowPayload("bin/winws.exe"), "Flowseal file allowlist excludes traversal, services and executables");
        string legacy = JsonSerializer.Serialize(imported with {Repository=WinwsStrategies.Repository}).Replace(",\"Repository\":\"bol-van/zapret-win-bundle\"", "");
        Assert(JsonSerializer.Deserialize<StrategyCatalog>(legacy)!.Repository == WinwsStrategies.Repository, "0.3.2 catalogs keep the bol-van source when new metadata is absent");
        foreach (string failure in new[]{"none","hash","redirect","symlink","truncated","oversize"})
        {
            int calls=0;
            using var client = new StrategyCatalogClient(new Handler(request=>
            {
                calls++;
                var uri = request.RequestUri!;
                Assert(uri.Host is "api.github.com" or "raw.githubusercontent.com", "Flowseal download stays on fixed GitHub hosts");
                if (uri.AbsolutePath.EndsWith("git/ref/heads/main")) return Json(new { @object=new{type="commit",sha=Revision} });
                if (uri.Host=="api.github.com")
                {
                    Assert(uri.AbsolutePath.EndsWith("git/trees/"+Revision), "Flowseal manifest pinned to resolved commit");
                    return Json(new {sha=Revision,truncated=failure=="truncated",tree=new[]{
                        new {path="general.bat",type="blob",mode=failure=="symlink"?"120000":"100644",sha=Blob(Encoding.UTF8.GetBytes(Preset)),size=Encoding.UTF8.GetByteCount(Preset)},
                        new {path=PayloadPath,type="blob",mode="100644",sha=Blob(Payload),size=Payload.Length}
                    }});
                }
                Assert(uri.AbsolutePath.Contains("/"+Revision+"/"), "Flowseal raw files pinned to the same commit");
                if (uri.AbsolutePath.EndsWith("general.bat")) return Bytes(Encoding.UTF8.GetBytes(Preset));
                if (failure=="redirect") {var response=new HttpResponseMessage(HttpStatusCode.Redirect);response.Headers.Location=new Uri("https://example.com/template");return response;}
                return Bytes(failure=="oversize"?new byte[4097]:failure=="hash"?new byte[Payload.Length]:Payload);
            }));
            bool rejected=false;
            try {var fetched=await client.Fetch(WinwsStrategies.FlowsealRepository,CancellationToken.None);Assert(fetched.Strategies.Length==1 && calls==4,"complete Flowseal download validates and imports packet templates");}
            catch(UserFault){rejected=true;}
            Assert(rejected == (failure!="none"),"Flowseal fetch result: "+failure);
        }
    }
    static HttpResponseMessage Json(object value)=>Bytes(JsonSerializer.SerializeToUtf8Bytes(value));
    static HttpResponseMessage Bytes(byte[] bytes)=>new(HttpStatusCode.OK){Content=new ByteArrayContent(bytes)};
    sealed class Handler : HttpMessageHandler
    {
        readonly Func<HttpRequestMessage,HttpResponseMessage> response;
        public Handler(Func<HttpRequestMessage,HttpResponseMessage> response)=>this.response=response;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)=>Task.FromResult(response(request));
    }
}
