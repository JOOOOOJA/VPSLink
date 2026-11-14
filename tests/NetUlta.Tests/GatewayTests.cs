using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using NetUlta;

static class GatewayTests
{
    public static async Task Run()
    {
        var options = new GatewayOptions("example.com", "link.example.com", new string('t', 40));
        foreach (var scenario in new[] { "create", "resume", "occupied", "pending", "foreign" })
        {
            var p = new Profile { HttpsRelay = "wss://old.example.com/link-ssh", ProtectedRelayToken = "old" };
            using var fixture = new Fixture(p, scenario);
            using var api = new CloudflareGateway(new HttpClient(fixture));
            Profile saved = p;
            Task Save(Profile next, CancellationToken ct)
            {
                if (next.HttpsRelay != p.HttpsRelay || next.ProtectedRelayToken != "old")
                    throw new Exception("Active endpoint changed before public SSH verification");
                saved = next; return Task.CompletedTask;
            }
            bool failed = false;
            try { await api.Prepare(p, options, Save, _ => { }, default); }
            catch (UserFault) { failed = true; }
            if (scenario is "occupied" or "pending" or "foreign")
            {
                if (!failed || fixture.Mutations != 0) throw new Exception("Unsafe Cloudflare mutation: " + scenario);
            }
            else
            {
                if (failed || saved.GatewayTunnelId != Fixture.TunnelId || Setup.Open(saved, saved.ProtectedGatewayToken, "gateway-relay").Length != 43)
                    throw new Exception("Cloudflare provisioning failed");
                await api.Prepare(saved, options, Save, _ => { }, default);
                if (fixture.CreatedTunnels != (scenario == "create" ? 1 : 0) || fixture.CreatedRecords != 1)
                    throw new Exception("Retry duplicated a Cloudflare resource");
            }
            Console.WriteLine("PASS: Cloudflare gateway " + scenario + "; previous endpoint preserved");
        }
    }

    sealed class Fixture : HttpMessageHandler
    {
        public const string TunnelId = "11111111-2222-3333-4444-555555555555";
        readonly Profile profile;
        readonly string scenario;
        public int Mutations, CreatedTunnels, CreatedRecords;
        public Fixture(Profile p, string scenario) { profile = p; this.scenario = scenario; }
        object Tunnel => new { id = TunnelId, name = scenario == "foreign" ? "another-owner" : "thingsnotfun-link-" + profile.Id.ToString("N"), config_src = "cloudflare" };
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.AbsolutePath;
            bool write = request.Method != HttpMethod.Get;
            if (write) Mutations++;
            object result;
            if (path.EndsWith("/zones"))
                result = new[] { new { id = new string('1', 32), account = new { id = new string('2', 32) }, status = scenario == "pending" ? "pending" : "active" } };
            else if (path.EndsWith("/dns_records"))
            {
                if (write) { CreatedRecords++; result = new { id = "record" }; }
                else result = scenario == "occupied" ? new object[] { new { type = "A", content = "192.0.2.1", proxied = false } } :
                    CreatedRecords > 0 ? new object[] { new { type = "CNAME", content = TunnelId + ".cfargotunnel.com", proxied = true } } : Array.Empty<object>();
            }
            else if (path.EndsWith("/cfd_tunnel"))
            {
                if (write) { CreatedTunnels++; result = Tunnel; }
                else result = scenario is "resume" or "foreign" ? new[] { Tunnel } : Array.Empty<object>();
            }
            else if (path.EndsWith("/" + TunnelId)) result = Tunnel;
            else if (path.EndsWith("/configurations")) result = new { };
            else if (path.EndsWith("/token")) result = new string('c', 60);
            else throw new Exception("Unexpected API path");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent(JsonSerializer.Serialize(new { success = true, result }), Encoding.UTF8, "application/json") });
        }
    }
}
