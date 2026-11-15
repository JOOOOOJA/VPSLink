using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using NetUlta;

static class DirectRoutingTests
{
    public static async Task Run(string scratch)
    {
        var payload = Encoding.UTF8.GetBytes("[{\"appPath\":\"C:/Games/Steam/steam.exe\"},{\"appPath\":\"c:/games/steam/STEAM.exe\"}," +
            "{\"appPath\":\"relative.exe\"},{\"appPath\":\"\"},{\"packageName\":\"test.package\"}]");
        var body = new byte[8 + payload.Length];
        BinaryPrimitives.WriteInt32BigEndian(body, 144);
        BinaryPrimitives.WriteInt32BigEndian(body.AsSpan(4), payload.Length);
        payload.CopyTo(body, 8);
        var paths = DirectRules.DecodeAmnezia(Encoding.Unicode.GetBytes("@Variant(" + Encoding.Latin1.GetString(body) + ")"));
        Check(paths.SequenceEqual(new[] { @"C:\Games\Steam\steam.exe" }), "Amnezia exclusions import only unique absolute Win32 executables");
        body[7] ^= 1;
        Reject(() => DirectRules.DecodeAmnezia(Encoding.Unicode.GetBytes("@Variant(" + Encoding.Latin1.GetString(body) + ")")),
            "malformed Amnezia variant fails without falling back to a wider rule");

        var network = new DirectNetwork("Ethernet", "192.0.2.2", 1, "AmneziaVPN", "10.0.0.2", 2,
            new[] { "0.0.0.0/1", "128.0.0.0/1" }, new[] { "203.0.113.42/32" });
        var config = DirectRouting.MakeConfig(network, paths, new[] { @"E:\Game Library\steamapps\common" });
        using var json = JsonDocument.Parse(config);
        var inbound = json.RootElement.GetProperty("inbounds")[0];
        var addresses = inbound.GetProperty("route_address").EnumerateArray().Select(e => e.GetString()).ToHashSet();
        Check(addresses.SetEquals(new[] { "0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2" }) &&
            inbound.GetProperty("route_exclude_address").EnumerateArray().Any(e => e.GetString() == "203.0.113.42/32"),
            "direct-route config outranks VPN IPv4 routes and preserves the protected endpoint");
        var route = json.RootElement.GetProperty("route");
        Check(route.GetProperty("final").GetString() == "vpn" && route.GetProperty("rules").GetArrayLength() == 2,
            "app and Steam folder matches are alternatives and everything else uses the VPN");
        Reject(() => DirectRouting.MakeConfig(network with { Prefixes = new[] { "1.1.1.1/32" } }, paths, Array.Empty<string>()),
            "direct routing refuses a limited VPN test profile");

        var options = new DirectOptions(true, true, true, paths[0]);
        var profile = new Profile { Name = "Direct routing fixture", Direct = options };
        string subdirectory = Path.Combine(scratch, "direct-options");
        try
        {
            var store = new ProfileStore(subdirectory);
            store.Save(new[] { profile });
            Check(store.Load().Single().Direct == options && !new Profile().Direct.Enabled, "routing choices round-trip and default to off");
        }
        finally
        {
            if (Directory.Exists(subdirectory))
            {
                File.Delete(Path.Combine(subdirectory, "profiles.json"));
                Directory.Delete(subdirectory);
            }
        }

        if (Environment.GetEnvironmentVariable("VPSLINK_TEST_SINGBOX") is { Length: > 0 } binary)
        {
            string configPath = Path.Combine(scratch, "direct-fixture.json");
            await File.WriteAllTextAsync(configPath, config);
            var info = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var arg in new[] { "check", "-c", configPath }) info.ArgumentList.Add(arg);
            using var process = Process.Start(info)!;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try { await process.WaitForExitAsync(timeout.Token); }
            finally { if (!process.HasExited) process.Kill(); }
            Check(process.ExitCode == 0, "official sing-box accepts the generated production configuration");
        }
    }

    static void Reject(Action action, string description)
    {
        try { action(); }
        catch (UserFault) { Check(true, description); return; }
        Check(false, description);
    }

    static void Check(bool condition, string description)
    {
        if (!condition) throw new Exception("FAIL: " + description);
        Console.WriteLine("PASS: " + description);
    }
}
