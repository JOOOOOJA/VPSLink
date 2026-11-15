using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using NetUlta;

if (args.FirstOrDefault() == "--known-host") return SshSession.KnownHost(args);
if (AskPass.IsHelper) return AskPass.Run(args);
if (args.Length == 4 && args[0] == "--probe")
{
    var p = new Profile { Host = args[1], SshPort = int.Parse(args[2]), Fingerprint = args[3] };
    foreach (var t in Supervisor.Available(p))
    {
        try { await SshSession.Probe(t, p, CancellationToken.None); Console.WriteLine($"{t.Name}: PIN OK"); }
        catch (Exception e) { Console.WriteLine($"{t.Name}: {e.GetType().Name}: {e.Message}"); }
    }
    return 0;
}
string scratch = Path.Combine(Path.GetFullPath("artifacts/tests"), Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(scratch);
try
{
    RunUnit();
    await SshOutputTests.Run();
    await UdpBurstTests.Run();
    await LocalUdpTests.Run();
    await DirectRoutingTests.Run(scratch);
    await GatewayTests.Run();
    await UpdateTests.Run();
    await StrategyTests.Run();
    await FlowsealTests.Run();
    SharingTests.Run();
    if (args.Length == 3) await RunIntegration(args[0], args[1], args[2]);
    else if (args.Length == 0) Console.WriteLine("Optional integration skipped (Python, existing libssh and application exe paths required).");
    else throw new ArgumentException("Expected three paths.");
    return 0;
}
finally
{
    // No recursion; all files in this fresh directory are test fixtures.
    foreach (var file in Directory.EnumerateFiles(scratch)) File.Delete(file);
    if (!Directory.EnumerateFileSystemEntries(scratch).Any()) Directory.Delete(scratch);
}
static void Assert(bool condition, string name)
{
    if (!condition) throw new Exception("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
}
static bool Fails(Action action)
{
    try { action(); return false; } catch (UserFault) { return true; }
}
static string Fingerprint(byte[] bytes) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(bytes)).TrimEnd('=');
void RunUnit()
{
    Assert(HttpsTransport.TryEndpoint("https://example.com/link-ssh", out _), "HTTPS gateway accepts a TLS endpoint");
    Assert(HttpsTransport.TryEndpoint("wss://example.com/link-ssh", out var wss) && wss!.Port == 443 &&
        !HttpsTransport.TryEndpoint("ws://example.com/link-ssh", out _), "WebSocket gateway requires TLS");
    const string wsKey = "dGhlIHNhbXBsZSBub25jZQ==";
    const string wsReply = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    using (var response = new MemoryStream(Encoding.ASCII.GetBytes(wsReply)))
        HttpsTransport.ReadUpgrade(response, wsKey, CancellationToken.None).GetAwaiter().GetResult();
    Assert(Fails(() => HttpsTransport.ReadUpgrade(new MemoryStream(Encoding.ASCII.GetBytes(wsReply)),
        Convert.ToBase64String(new byte[16]), CancellationToken.None).GetAwaiter().GetResult()),
        "WebSocket handshake rejects an accept value for another client nonce");
    Assert(!HttpsTransport.TryEndpoint("http://example.com/link-ssh", out _) &&
        !HttpsTransport.TryEndpoint("https://user@example.com/link-ssh", out _) &&
        !HttpsTransport.TryEndpoint("https://example.com/link-ssh?token=secret", out _),
        "HTTPS gateway rejects plaintext and credentials in URLs");
    Assert(InternetProbe.ClientAddresses("[Interface]\nAddress = 10.8.3.6/32, fd00::2/128 # local\n" +
        "[Peer]\nAddress = 10.8.3.7/32\n").SetEquals(new[] { IPAddress.Parse("10.8.3.6") }),
        "Internet probe uses only the client interface's IPv4 addresses");
    var pin = new byte[51];
    BinaryPrimitives.WriteInt32BigEndian(pin, 11);
    Encoding.ASCII.GetBytes("ssh-ed25519").CopyTo(pin, 4);
    BinaryPrimitives.WriteInt32BigEndian(pin.AsSpan(15), 32);
    RandomNumberGenerator.Fill(pin.AsSpan(19));
    string text = Convert.ToBase64String(pin);
    var fingerprint = Fingerprint(pin);
    Assert(Model.IsFingerprint(fingerprint) && SshSession.VerifyKey(text, fingerprint) == text, "ED25519 fingerprint pins exact public key");
    pin[^1] ^= 1;
    Assert(Fails(() => SshSession.VerifyKey(text, Fingerprint(pin))), "different fingerprint is rejected");
    Assert(Fails(() => SshSession.VerifyKey("AAAA", fingerprint)), "malformed SSH key is rejected");
    var p = new Profile { Name = "First", Host = "vps.example", User = "fixture", Fingerprint = fingerprint };
    p = p with { ProtectedCredential = ProfileStore.Protect(p.Id, new("test-unique-password", new byte[] { 1, 2, 3 })) };
    var store = new ProfileStore(scratch);
    store.Save(new[] { p, p with { Id = Guid.NewGuid(), Name = "Second", ProtectedCredential = "" } });
    var list = store.Load();
    Assert(list.Count == 2 && ProfileStore.Open(list[0]).Passphrase == "test-unique-password" &&
        !File.ReadAllText(Path.Combine(scratch, "profiles.json")).Contains("test-unique-password"), "multiple profiles; DPAPI credential round-trip");
    Assert(Fails(() => ProfileStore.Open(p with { Id = Guid.NewGuid() })), "DPAPI blob is bound to its profile");
    var profilePath = Path.Combine(scratch, "profiles.json");
    var beforeStartup = File.ReadAllBytes(profilePath);
    bool registrationSawValidFile = false;
    bool registrationFailed = false;
    try
    {
        StartupConfiguration.Configure(store, p.Id, 4, enabled => {
            var staged = store.Load().Single(item => item.Id == p.Id);
            registrationSawValidFile = enabled && staged.StartWithWindows && staged.AutoConnect && staged.AmneziaServerIndex == 4;
            throw new IOException("Simulated task registration failure");
        });
    }
    catch (IOException) { registrationFailed = true; }
    Assert(registrationFailed && registrationSawValidFile && File.ReadAllBytes(profilePath).SequenceEqual(beforeStartup),
        "failed startup registration restores original profile bytes after validating saved settings");
    StartupConfiguration.Configure(store, p.Id, 4, enabled => Assert(enabled, "startup registration requested"));
    var configured = store.Load();
    Assert(configured.Single(item => item.Id == p.Id).AmneziaServerIndex == 4 &&
        configured.Count(item => item.AutoConnect && item.StartWithWindows) == 1 &&
        ProfileStore.Open(configured[0]).Passphrase == "test-unique-password" &&
        File.ReadAllBytes(profilePath + ".bak").SequenceEqual(beforeStartup),
        "startup settings preserve DPAPI credentials, other profiles and exact backup");
    var afterStartup = File.ReadAllBytes(profilePath);
    Assert(Fails(() => StartupConfiguration.Configure(store, Guid.NewGuid(), 0, _ => throw new Exception("unexpected registration"))) &&
        Fails(() => StartupConfiguration.Configure(store, p.Id, -1, _ => throw new Exception("unexpected registration"))) &&
        File.ReadAllBytes(profilePath).SequenceEqual(afterStartup), "invalid startup selection cannot change profiles");
    bool manualRollback = false;
    try { StartupConfiguration.UseManualStart(store, _ => throw new IOException("Simulated unregister failure")); }
    catch (IOException) { manualRollback = true; }
    Assert(manualRollback && File.ReadAllBytes(profilePath).SequenceEqual(afterStartup),
        "manual startup conversion rolls back if unregister fails");
    StartupConfiguration.UseManualStart(store, enabled => Assert(!enabled, "manual startup removes Link task"));
    Assert(store.Load().SequenceEqual(configured.Select(item => item with
        { AutoConnect = false, StartWithWindows = false, AmneziaServerIndex = null })) &&
        ProfileStore.Open(store.Load()[0]).Passphrase == "test-unique-password",
        "manual startup preserves profiles and credentials while clearing automatic actions");
    foreach (var malformed in new[] { "null", "{\"value\":" + Encoding.UTF8.GetString(afterStartup) + ",\"Count\":2}" })
    {
        File.WriteAllText(profilePath, malformed);
        bool rejected = false;
        try { store.Save(list); } catch (System.Text.Json.JsonException) { rejected = true; }
        Assert(rejected && File.ReadAllText(profilePath) == malformed,
            "null or PowerShell-wrapped store cannot be silently replaced");
    }
    bool visibleStorageError = false;
    Exception? uiFailure = null;
    var uiThread = new Thread(() => {
        try
        {
            using var window = new MainWindow(scratch);
            IEnumerable<System.Windows.Forms.Control> Children(System.Windows.Forms.Control parent) =>
                parent.Controls.Cast<System.Windows.Forms.Control>().SelectMany(child => new[] { child }.Concat(Children(child)));
            visibleStorageError = Children(window).Any(control => control.Text == "Не удалось прочитать профили");
        }
        catch (Exception error) { uiFailure = error; }
    });
    uiThread.SetApartmentState(ApartmentState.STA);
    uiThread.Start(); uiThread.Join();
    Assert(uiFailure == null && visibleStorageError && File.ReadAllText(profilePath).StartsWith("{\"value\":"),
        "unreadable profile store is explained in main window and remains untouched");
    File.WriteAllBytes(profilePath, beforeStartup);
    var ipv4 = new PortBinding("127.0.0.1", 15077, 513);
    var ipv6 = new PortBinding("::1", 15077, 513);
    var key = Convert.ToBase64String(new byte[32]);
    var awg31 = new VpnProvision("10.8.1.9", key, key, new() {
        ["HeaderProtectionKey"] = key, ["ContentPaddingAddition"] = "10-100",
        ["RekeyAfterTime"] = "120-180", ["RekeyTimeout"] = "5-10", ["RejectAfterTime"] = "180",
        ["KeepaliveTimeout"] = "10", ["MaxHandshakeAttempts"] = "20",
        ["RandomTrailers"] = "on", ["DisableCookies"] = "on" }, null);
    var awg31Config = Setup.BuildConfig(awg31, key);
    Assert(awg31.Settings!.All(field => awg31Config.Contains(field.Key + " = " + field.Value)),
        "AWG 3.1 export preserves header protection, padding, timings and flags");
    Assert(Fails(() => Setup.BuildConfig(awg31 with { Settings = new() { ["PostUp"] = "command" } }, key)),
        "AWG export still rejects executable hooks");
    var source = new VpnSource("fake:wg0", "fake", "wg0", "awg", 513, new[] { ipv4, ipv6 }, 1, new[] { key });
    var inventory = new Inventory(true, "", new[] { source }, new[] { ipv4, ipv6 }, null);
    Assert(Vpn.Select(p with { ClientPublicKey = key }, inventory) == new TunnelTarget("127.0.0.1", 15077, "fake:wg0", key),
        "mapped port, binding and exact peer discovery");
    Assert(Fails(() => Vpn.Select(p, inventory with { Ports = new[] { ipv4, ipv4 with { Port = 15078 } } })),
        "ambiguous UDP port requires explicit choice");
    Assert(Vpn.Select(p with { RemotePort = 48822 }, inventory).SourceId == "", "no unsupported claim for a manual port");
    var serverKey = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray());
    var otherKey = Convert.ToBase64String(Enumerable.Repeat((byte)8, 32).ToArray());
    var otherPort = ipv4 with { Port = 15078 };
    var guided = inventory with { Sources = new[] {
        source with { ServerKey = serverKey, CanProvision = true, Label = "amnezia-awg3" },
        source with { Id = "fake:awg2", ServerKey = otherKey, CanProvision = true,
            Ports = new[] { otherPort }, Label = "amnezia-awg2" }
    }, Ports = new[] { ipv4, otherPort } };
    Assert(Vpn.Select(p with { ServerPublicKey = serverKey, ClientPublicKey = key, ConfigEndpointPort = 15078 }, guided).Port == 15077,
        "import chooses verified server key over a stale port or another VPN");
    Assert(Fails(() => Vpn.Select(p with { ServerPublicKey = serverKey, ClientPublicKey = otherKey }, guided)),
        "import rejects an unregistered client peer");
    Assert(Vpn.ProvisionOptions(guided, p).Length == 2 &&
        Vpn.ProvisionOptions(guided, p with { ServerPublicKey = serverKey }).Single().Port == 15077,
        "wizard displays available VPNs and resumes only the selected server");
    var sample = $"[Interface]\nPrivateKey = {key}\n[Peer]\nPublicKey = {serverKey}\nEndpoint = [::1]:9609 # sample";
    Assert(Setup.Inspect(sample) == (key, serverKey, 9609) &&
        Fails(() => Setup.Inspect(sample + "\nPostUp = ignored")),
        "import extracts endpoint and keys and rejects executable config hooks");
    using var warpSettings = System.Text.Json.JsonDocument.Parse(@"{""settings"":{""operation_mode"":""proxy"",""proxy_port"":40001}}");
    Assert(WarpClient.ProxyPort(warpSettings.RootElement) == 40001, "detect configured WARP local proxy");
    var v = new Verification();
    v.Seed(new PeerStats(500, 480, 100, 100, null));
    Assert(!v.Check(new(501, 480, 200, 200, null), 1, 1), "old VPN handshake cannot verify");
    Assert(!v.Check(new(501, 500, 200, 200, null), 1, 0), "one-way UDP cannot verify");
    Assert(!v.Check(new(501, 500, 200, 100, null), 1, 1), "one-way VPN counters cannot verify");
    Assert(v.Check(new(501, 500, 200, 200, null), 1, 1), "fresh handshake and bidirectional evidence");
    Assert(!v.Check(new(502, 501, 10, 10, null), 1, 1), "counter reset requires new baseline");
    var input = Path.Combine(scratch, "input.conf");
    var output = Path.Combine(scratch, "output.conf");
    var config = "[Interface]\r\nPrivateKey = dummy\r\nJc = 7\r\n\r\n[Peer]\r\nEndpoint = old.example:1 # note\r\n";
    File.WriteAllText(input, config);
    var compatible = Path.Combine(scratch, "compatible.conf");
    VpnConfig.ExportText(config, compatible, 40055, localAddress: IPAddress.Parse("192.0.2.25"));
    Assert(File.ReadAllText(compatible) == config.Replace("old.example:1", "192.0.2.25:40055"),
        "compatibility export changes only endpoint, preserves keys and parameters");
    Assert(Fails(() => VpnConfig.ExportText(config, Path.Combine(scratch,"invalid-address.conf"), 40055,
        localAddress: IPAddress.Any)), "export refuses wildcard endpoint");
    VpnConfig.Export(input, output, 40055);
    Assert(File.ReadAllText(output) == config.Replace("old.example:1", "127.0.0.1:40055") && File.ReadAllText(input) == config,
        "export changes only endpoint and preserves original");
    var full = config.Replace("Jc = 7", "Jc = 7\r\nDNS = 8.8.8.8") +
        "AllowedIPs = 0.0.0.0/0, ::/0\r\nPersistentKeepalive = 25\r\n";
    var diagnostic = Path.Combine(scratch, "warp-test.conf");
    VpnConfig.ExportText(full, diagnostic, 40055, handshakeOnly: true);
    var expected = config.Replace("old.example:1", "127.0.0.1:40055") +
        "AllowedIPs = 1.1.1.1/32\r\nPersistentKeepalive = 10\r\n";
    Assert(File.ReadAllText(diagnostic) == expected, "WARP test preserves VPN keys and uses only the test route and local endpoint");
    var edge = IPAddress.Parse("162.159.198.2");
    var routes = VpnConfig.WithoutEndpoint("0.0.0.0/0", edge).ToArray();
    Assert(routes.Length == 32 && !routes.Contains("162.159.198.2/32") &&
        routes.Sum(route => 1L << (32 - int.Parse(route.Split('/')[1]))) == (1L << 32) - 1 &&
        routes.Contains("162.159.198.3/32"),
        "WARP export covers all IPv4 except the single outer endpoint");
    Assert(Fails(() => VpnConfig.Export(input, input, 2)), "export refuses the original filename");
    File.AppendAllText(input, "[Peer]\nEndpoint = other:2\n");
    Assert(Fails(() => VpnConfig.Export(input, Path.Combine(scratch, "multi.conf"), 2)), "multi-peer export is refused");
}

async Task RunIntegration(string python, string libssh, string app)
{
    using var cap = new CancellationTokenSource(TimeSpan.FromSeconds(95));
    var ct = cap.Token;
    var keygen = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe");
    var host = Path.Combine(scratch, "host");
    var client = Path.Combine(scratch, "client");
    foreach (var entry in new[] { (host, ""), (client, "fixture-passphrase!") })
    {
        using var gen = Process.Start(SshSession.StartInfo(keygen, "-q", "-t", "ed25519", "-N", entry.Item2, "-f", entry.Item1))!;
        await gen.WaitForExitAsync(ct);
        Assert(gen.ExitCode == 0, "generated disposable fixture key");
    }
    string pin = Fingerprint(Convert.FromBase64String(File.ReadAllText(host + ".pub").Split(' ')[1]));
    string drop = Path.Combine(scratch, "drop");
    using var sshd = Process.Start(SshSession.StartInfo(python, "-u", Path.GetFullPath("tests/ssh_fixture.py"), libssh, host, client + ".pub", drop))!;
    try
    {
        var line = await sshd.StandardOutput.ReadLineAsync().WaitAsync(ct);
        if (!int.TryParse(line, out int port))
            throw new Exception("Fixture failed: " + await sshd.StandardError.ReadToEndAsync());
        var pending = new Profile { Host = "127.0.0.1", SshPort = port };
        Assert(await SshSession.DiscoverFingerprint(new TcpTransport(), pending, ct) == pin,
            "first-run discovery gets the actual SSH fingerprint before authentication");
        // Start the same WinExe helper used in the shipped package; pipe never contains real credentials.
        var info = SshSession.StartInfo(app, "fixture@127.0.0.1's password:");
        using (var h = new AskPass(info, AuthKind.Password, "synthetic-helper-check", ct))
        using (var helper = Process.Start(info)!)
        {
            var response = await helper.StandardOutput.ReadToEndAsync().WaitAsync(ct);
            await helper.WaitForExitAsync(ct);
            Assert(helper.ExitCode == 0 && response.Trim() == "synthetic-helper-check", $"published GUI AskPass inherits stdout (exit {helper.ExitCode}, {response.Length} chars)");
        }
        using var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int echoPort = ((IPEndPoint)echo.Client.LocalEndPoint!).Port;
        async Task Echo()
        {
            try
            {
                while (true)
                {
                    var packet = await echo.ReceiveAsync(ct);
                    await echo.Client.SendToAsync(packet.Buffer, SocketFlags.None, packet.RemoteEndPoint, ct);
                }
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException) { }
        }
        var echoTask = Echo();
        var p = new Profile { Name = "Fixture", Host = "127.0.0.1", SshPort = port, User = "fixture", Fingerprint = pin,
            RemotePort = echoPort, AutoWarp = false };
        p = p with { ProtectedCredential = ProfileStore.Protect(p.Id, new("fixture-password!", null)) };
        await SshSession.Probe(new TcpTransport(), p, ct);
        var delayed = new DelayedGatewayTransport();
        using (var warm = await GatewaySetup.OpenBootstrap(delayed, p, scratch, _ => { }, ct, app))
            Assert(delayed.Attempts == 2, "gateway retries a cold-start timeout before provisioning");
        try { using var bad = await SshSession.Open(new TcpTransport(), p with { Fingerprint = Fingerprint(new byte[1]) }, scratch, ct, app); throw new Exception("bad PIN accepted"); }
        catch (UserFault e) { Assert(e.Terminal, "actual Windows OpenSSH rejects wrong pin"); }
        await Scenario(p, "real SSH password + UDP", true);
        using var http = new FixtureProxy(ProxyKind.HttpConnect, port, ct);
        var importedKey = File.ReadAllBytes(client);
        var k = p with { Auth = AuthKind.Key, ProtectedCredential = ProfileStore.Protect(p.Id, new("fixture-passphrase!", importedKey)),
            Proxy = ProxyKind.HttpConnect, ProxyPort = http.Port, UseSystemRoute = false };
        CryptographicOperations.ZeroMemory(importedKey);
        await Scenario(k, "encrypted SSH key + HTTP CONNECT + UDP", false);
        using var socks = new FixtureProxy(ProxyKind.Socks5, port, ct);
        var fallback = new FixtureWarp(socks.Port);
        var wizard = new SetupInteraction(
            (candidate, offered, token) => Task.FromResult(candidate.Fingerprint.Length == 0 && offered == pin),
            (_, _) => throw new InvalidOperationException("Manual profile must not prompt for VPN"),
            (profile, _) =>
            {
                Assert(profile.Fingerprint == pin, "wizard saves only the confirmed SSH pin");
                return Task.CompletedTask;
            });
        await Scenario(p with { Fingerprint = "", AutoWarp = true, StartWarp = true, UseSystemRoute = false },
            "first-run SSH + automatic WARP provider + SOCKS5 + UDP", false, fallback, wizard);
        Assert(fallback.Started == 1, "fallback activates the WARP provider exactly once");
        echo.Dispose();
        await echoTask;

        async Task Scenario(Profile config, string title, bool reconnect, IWarpClient? warp = null,
            SetupInteraction? interaction = null)
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var updates = System.Threading.Channels.Channel.CreateUnbounded<LinkUpdate>();
            var supervisor = new Supervisor(scratch, u => updates.Writer.TryWrite(u), helperExe: app,
                interaction: interaction, warp: warp,
                transports: warp == null ? null : _ => Array.Empty<ITransport>());
            var running = supervisor.Run(config, stop.Token);
            async Task<int> Ready()
            {
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
                limit.CancelAfter(TimeSpan.FromSeconds(26));
                while (true)
                {
                    var result = await updates.Reader.ReadAsync(limit.Token);
                    Console.WriteLine("  " + result.Status + (result.Ready ? "" : ": " + result.Detail.Split('\n')[0]));
                    if (result.Ready && result.Port is int value) return value;
                    if (result.Status is "Нужно действие" or "Ошибка запуска") throw new Exception(result.Detail);
                }
            }
            async Task RoundTrip(UdpClient local, int udp, int size)
            {
                var data = RandomNumberGenerator.GetBytes(size);
                await local.Client.SendToAsync(data, SocketFlags.None, new IPEndPoint(IPAddress.Loopback, udp), ct);
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
                limit.CancelAfter(TimeSpan.FromSeconds(8));
                var rx = await local.ReceiveAsync(limit.Token);
                Assert(rx.RemoteEndPoint.Port == udp && data.AsSpan().SequenceEqual(rx.Buffer), title + $" ({size} bytes)");
            }
            int livePort = 0;
            try
            {
                livePort = await Ready();
                using var local = new UdpClient(AddressFamily.InterNetwork);
                await RoundTrip(local, livePort, 1144);
                await RoundTrip(local, livePort, 60000);
                if (reconnect)
                {
                    File.WriteAllText(drop, "drop");
                    Assert(await Ready() == livePort, "reconnect preserves local port");
                    await RoundTrip(local, livePort, 93);
                }
            }
            finally { stop.Cancel(); await running.WaitAsync(TimeSpan.FromSeconds(10)); }
            using var released = new LocalUdp(livePort);
            Assert(released.Port == livePort, "stop releases local UDP port");
            Assert(!Directory.EnumerateDirectories(scratch, "session-*").Any(), "private SSH scratch files removed");
        }
    }
    finally { SshSession.Kill(sshd); }
}

sealed class FixtureWarp : IWarpClient
{
    readonly int port;
    public FixtureWarp(int port) { this.port = port; }
    public int Started { get; private set; }
    public Task<Profile?> Activate(Profile profile, Action<string> progress, CancellationToken ct)
    {
        Started++;
        progress("Test WARP provider ready");
        return Task.FromResult<Profile?>(profile with { Proxy = ProxyKind.Socks5, ProxyPort = port });
    }
}

sealed class FixtureProxy : IDisposable
{
    readonly TcpListener listener = new(IPAddress.Loopback, 0);
    readonly ProxyKind kind;
    readonly int upstream;
    readonly CancellationTokenSource stop;
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    public FixtureProxy(ProxyKind kind, int upstream, CancellationToken ct)
    {
        this.kind = kind; this.upstream = upstream;
        stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        listener.Start();
        _ = Accept(stop.Token);
    }
    async Task Accept(CancellationToken ct)
    {
        try { while (true) _ = Handle(await listener.AcceptTcpClientAsync(ct), ct); }
        catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }
    async Task Handle(TcpClient client, CancellationToken ct)
    {
        using (client)
        using (var target = new TcpClient(AddressFamily.InterNetwork))
        {
            try
            {
                var stream = client.GetStream();
                if (kind == ProxyKind.Socks5)
                {
                    var hello = new byte[3];
                    await Wire.ReadFull(stream, hello, ct);
                    if (!hello.SequenceEqual(new byte[] { 5, 1, 0 })) return;
                    await stream.WriteAsync(new byte[] { 5, 0 }, ct);
                    var request = new byte[10];
                    await Wire.ReadFull(stream, request, ct);
                    if (!request.AsSpan(0, 8).SequenceEqual(new byte[] { 5, 1, 0, 1, 127, 0, 0, 1 }) ||
                        BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(8)) != upstream) return;
                    await target.ConnectAsync(IPAddress.Loopback, upstream, ct);
                    await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, ct);
                }
                else
                {
                    var request = new StringBuilder();
                    var next = new byte[1];
                    while (!request.ToString().EndsWith("\r\n\r\n") && request.Length < 1000)
                    { await Wire.ReadFull(stream, next, ct); request.Append((char)next[0]); }
                    if (!request.ToString().StartsWith($"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\n")) return;
                    await target.ConnectAsync(IPAddress.Loopback, upstream, ct);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), ct);
                }
                using var pair = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var remote = target.GetStream();
                var a = remote.CopyToAsync(stream, pair.Token);
                var b = stream.CopyToAsync(remote, pair.Token);
                await Task.WhenAny(a, b);
                pair.Cancel();
                await Task.WhenAll(a, b);
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or IOException or ObjectDisposedException) { }
        }
    }
    public void Dispose() { stop.Cancel(); listener.Stop(); stop.Dispose(); }
}





