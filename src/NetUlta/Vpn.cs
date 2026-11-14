using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace NetUlta;

sealed record PortBinding(string Host, int Port, int Inside);
sealed record VpnSource(string Id, string Container, string Interface, string Tool, int ListenPort, PortBinding[] Ports,
    int PeerCount, string[] PeerKeys, string Label = "", string ServerKey = "", bool CanProvision = false);
sealed record Inventory(bool UdpEcho, string? Details, VpnSource[]? Sources, PortBinding[]? Ports, string? Error);
sealed record PeerStats(long Now, long Handshake, ulong Rx, ulong Tx, string? Error);
sealed record TunnelTarget(string Host, int Port, string SourceId, string Peer);
sealed record LinkUpdate(string Status, string Detail = "", int? Port = null, bool Ready = false);
sealed record Ack(bool Ready, string? Error);
sealed record VpnOption(string SourceId, int Port, string Label)
{
    public override string ToString() => $"{Label} · UDP {Port}";
}
sealed record SetupInteraction(
    Func<Profile, string, CancellationToken, Task<bool>> ConfirmHost,
    Func<IReadOnlyList<VpnOption>, CancellationToken, Task<VpnOption?>> SelectVpn,
    Func<Profile, CancellationToken, Task> Save);

static class Vpn
{
    public static TunnelTarget Select(Profile p, Inventory i)
    {
        var sources = i.Sources ?? Array.Empty<VpnSource>();
        var ports = i.Ports ?? Array.Empty<PortBinding>();
        if (p.ServerPublicKey.Length != 0)
        {
            var trusted = sources.Where(s => s.ServerKey == p.ServerPublicKey).ToArray();
            if (trusted.Length == 0)
                throw new UserFault("На этом VPS не найден сервер AmneziaWG с ключом из профиля VPN.");
            if (p.ClientPublicKey.Length != 0)
            {
                var matchingPeer = trusted.Where(s => s.PeerKeys.Contains(p.ClientPublicKey)).ToArray();
                if (matchingPeer.Length > 0) trusted = matchingPeer;
                else if (trusted.All(s => s.PeerCount <= s.PeerKeys.Length))
                    throw new UserFault("Этот клиентский профиль VPN не зарегистрирован на выбранном сервере.");
            }
            sources = trusted;
            ports = trusted.SelectMany(s => s.Ports).ToArray();
            var matchingPort = ports.Any(b => b.Port == p.ConfigEndpointPort);
            p = p with { SourceId = "", RemotePort = p.RemotePort != 0 ? p.RemotePort :
                matchingPort ? p.ConfigEndpointPort : 0 };
        }
        var requested = p.SourceId.Length == 0 ? null : sources.FirstOrDefault(s => s.Id == p.SourceId)
            ?? throw new UserFault("Интерфейс для проверки больше не найден. Проверьте идентификатор в диагностике.");
        if (requested != null && p.RemotePort != 0 && requested.Ports.Length > 0 && !requested.Ports.Any(b => b.Port == p.RemotePort))
            throw new UserFault("Выбранный интерфейс VPN не соответствует указанному порту UDP.");
        var candidates = (requested?.Ports ?? ports).Select(b => b.Port).Distinct().OrderBy(x => x).ToArray();
        int port = p.RemotePort;
        if (p.ServerPublicKey.Length != 0 && port != 0 && !candidates.Contains(port))
            throw new UserFault("Этот UDP-порт больше не принадлежит серверу из профиля VPN.");
        if (port == 0)
        {
            if (candidates.Length != 1)
                throw new UserFault(candidates.Length == 0 ?
                    "Порт VPN не определён. Укажите опубликованный UDP-порт в профиле." :
                    "Найдено несколько UDP-портов VPN: " + string.Join(", ", candidates) + ". Укажите нужный в профиле.");
            port = candidates[0];
        }
        var hostList = (requested?.Ports ?? ports).Where(b => b.Port == port).Select(b => b.Host).Distinct().ToArray();
        string host = p.RemoteIp;
        if (host.Length == 0)
        {
            var ipv4 = hostList.Where(h => !h.Contains(':')).ToArray();
            if (ipv4.Length > 1 || (ipv4.Length == 0 && hostList.Length > 1))
                throw new UserFault("Порт опубликован на нескольких адресах. Укажите IP назначения UDP на VPS.");
            host = ipv4.FirstOrDefault() ?? hostList.FirstOrDefault() ?? "127.0.0.1";
        }
        var matched = requested != null ? new[] { requested } :
            sources.Where(s => s.Ports.Any(b => b.Port == port && b.Host == host)).ToArray();
        if (requested == null && matched.Length == 0 && p.RemoteIp.Length != 0)
            matched = sources.Where(s => s.Ports.Any(b => b.Port == port)).ToArray();
        if (p.ClientPublicKey.Length != 0 && matched.Length > 1)
        {
            var keyed = matched.Where(s => s.PeerKeys.Contains(p.ClientPublicKey, StringComparer.Ordinal)).ToArray();
            if (keyed.Length == 1 && matched.All(s => s.PeerCount <= s.PeerKeys.Length)) matched = keyed;
        }
        // Require the user's exact peer key: activity from other clients cannot stand in for their connection.
        string source = matched.Length == 1 ? matched[0].Id : "";
        return new TunnelTarget(host, port, source, p.ClientPublicKey);
    }

    public static VpnOption[] ProvisionOptions(Inventory inventory, Profile profile) =>
        (inventory.Sources ?? Array.Empty<VpnSource>())
        .Where(s => s.CanProvision && Model.IsPeerKey(s.ServerKey) &&
            (profile.ServerPublicKey.Length == 0 || s.ServerKey == profile.ServerPublicKey) &&
            (profile.SourceId.Length == 0 || s.Id == profile.SourceId))
        .SelectMany(s => s.Ports.Select(p => p.Port).Distinct()
            .Where(port => profile.RemotePort == 0 || port == profile.RemotePort)
            .Select(port => new VpnOption(s.Id, port,
                s.Label.Length == 0 ? s.Interface : new string(s.Label.Where(c => !char.IsControl(c)).ToArray()))))
        .OrderByDescending(s => s.Label, StringComparer.OrdinalIgnoreCase).ThenBy(s => s.Port).ToArray();

    public static T Decode<T>(byte[] payload) => JsonSerializer.Deserialize<T>(payload) ??
        throw new IOException("Некорректный ответ моста.");
}

sealed class Verification
{
    PeerStats? baseline;
    public void Seed(PeerStats? stats) => baseline = stats?.Error == null ? stats : null;
    public bool Check(PeerStats current, long sent, long received)
    {
        if (current.Error != null || current.Now < 1 || current.Handshake < 0) return false;
        if (baseline == null || current.Rx < baseline.Rx || current.Tx < baseline.Tx ||
            current.Handshake < baseline.Handshake)
        { baseline = current; return false; }
        return sent > 0 && received > 0 && current.Handshake > baseline.Handshake &&
               current.Handshake <= current.Now + 5 && current.Handshake >= current.Now - 180 &&
               current.Rx > baseline.Rx && current.Tx > baseline.Tx;
    }
}

sealed class LocalUdp : IDisposable
{
    public UdpClient Client { get; }
    public int Port => ((IPEndPoint)Client.Client.LocalEndPoint!).Port;
    public LocalUdp(int port)
    {
        Client = new UdpClient(AddressFamily.InterNetwork);
        try
        {
            Client.ExclusiveAddressUse = true;
            Client.Client.Bind(new IPEndPoint(IPAddress.Loopback, port));
            // Ignore Windows ICMP port-unreachable on the socket if the VPN closes while a reply is in flight.
            Client.Client.IOControl(unchecked((int)0x9800000C), new byte[] { 0 }, null);
        }
        catch { Client.Dispose(); throw; }
    }
    public void Dispose() => Client.Dispose();
}

sealed class Supervisor
{
    readonly string root;
    readonly Action<LinkUpdate> update;
    readonly Func<Profile, IReadOnlyList<ITransport>> transports;
    readonly string? helperExe;
    readonly SetupInteraction? interaction;
    readonly IWarpClient warp;
    public Supervisor(string root, Action<LinkUpdate> update, Func<Profile, IReadOnlyList<ITransport>>? transports = null,
        string? helperExe = null, SetupInteraction? interaction = null, IWarpClient? warp = null)
    {
        this.root = root;
        this.update = update;
        this.transports = transports ?? Available;
        this.helperExe = helperExe;
        this.interaction = interaction;
        this.warp = warp ?? new WarpClient();
    }
    public static IReadOnlyList<ITransport> Available(Profile p)
    {
        var list = new List<ITransport>();
        if (p.HttpsRelay.Length != 0) list.Add(new HttpsTransport(p));
        if (p.Proxy != ProxyKind.None) list.Add(new ProxyTransport(p));
        if (p.AdapterId.Length != 0) list.Add(new TcpTransport(p.AdapterId));
        if (p.AutoWarp)
            foreach (var adapter in Model.Interfaces().Where(i => i.Id != p.AdapterId &&
                (i.Name.Contains("Cloudflare WARP", StringComparison.OrdinalIgnoreCase) ||
                 i.Name.Contains("CloudflareWARP", StringComparison.OrdinalIgnoreCase))))
                list.Add(new TcpTransport(adapter.Id));
        if (p.UseSystemRoute) list.Add(new TcpTransport());
        return list;
    }
    public async Task Run(Profile p, CancellationToken ct)
    {
        try
        {
            Model.Validate(p, allowUnpinned: interaction != null);
            using var local = new LocalUdp(p.LocalPort);
            update(new("Ищем путь до VPS…", Port: local.Port));
            using var coreTransport = p.UseWarpCore ? new RestartableWarpCore(p.ZapretPath, p.WinwsStrategy) : null;
            var candidates = Candidates();
            int delay = 2;
            bool triedWarp = false;
            Profile? warpProxy = null;
            TunnelTarget? previousTarget = null;
            List<ITransport> Candidates()
            {
                if (coreTransport == null) return transports(p).ToList();
                ITransport viaCore = p.HttpsRelay.Length == 0 ? coreTransport : new HttpsTransport(p, coreTransport);
                return new List<ITransport> { viaCore };
            }
            while (!ct.IsCancellationRequested)
            {
                bool interrupted = false;
                foreach (var transport in candidates.ToArray())
                {
                    bool active = false;
                    try
                    {
                        update(new("Проверяем SSH…", transport.Name, local.Port));
                        if (p.Fingerprint.Length == 0)
                        {
                            string fingerprint = await SshSession.DiscoverFingerprint(transport, p, ct);
                            if (!await interaction!.ConfirmHost(p, fingerprint, ct))
                                throw new UserFault("Подключение отменено. Подтвердите ключ сервера при следующей попытке.");
                            p = p with { Fingerprint = fingerprint };
                            await interaction.Save(p, ct);
                        }
                        using var ssh = await SshSession.Open(transport, p, root, ct, helperExe);
                        using var close = ct.Register(ssh.Interrupt);
                        update(new("SSH защищён. Проверяем VPS…", "Ключ ED25519 совпал. Вход выполнен.", local.Port));
                        var info = Vpn.Decode<Inventory>(await Exchange(ssh, 'I', Array.Empty<byte>(), 60, ct));
                        if (info.Error != null) throw new UserFault("Не удалось получить инвентаризацию VPS.");
                        var details = info.Details ?? "";
                        var ports = (info.Ports ?? Array.Empty<PortBinding>()).Select(b => b.Port).Distinct().OrderBy(x => x);
                        details += "\nПорты VPN: " + string.Join(", ", ports);
                        details += "\nUDP эхо внутри VPS: " + (info.UdpEcho ? "двусторонний обмен" : "сбой");
                        update(new("Проверяем UDP…", details, local.Port));
                        if (!info.UdpEcho) throw new UserFault("Не прошла локальная UDP-проверка на VPS. Проверьте сетевые ограничения VPS.");
                        if (p.VpnSetup == VpnSetup.Create && p.ProtectedVpnConfig.Length == 0)
                        {
                            p = await Provision(ssh, p, info, local.Port, ct);
                            info = Vpn.Decode<Inventory>(await Exchange(ssh, 'I', Array.Empty<byte>(), 60, ct));
                            if (info.Error != null || !info.UdpEcho)
                                throw new UserFault("Профиль создан. VPS не подтвердил готовность моста, попробуйте подключиться снова.");
                        }
                        // A reconnect must not silently switch the target while a client uses the same local endpoint.
                        var target = Vpn.Select(previousTarget != null ? p with { RemotePort = previousTarget.Port, RemoteIp = previousTarget.Host } : p, info);
                        if (interaction != null && p.LocalPort == 0 && p.ProtectedVpnConfig.Length != 0)
                        {
                            p = p with { LocalPort = local.Port };
                            await interaction.Save(p, ct);
                        }
                        var ack = Vpn.Decode<Ack>(await Exchange(ssh, 'S',
                            JsonSerializer.SerializeToUtf8Bytes(new { target.Host, target.Port }), 7, ct));
                        if (!ack.Ready) throw new UserFault("VPS не смог создать UDP-сокет до выбранного адреса и порта.");
                        previousTarget = target;
                        var verification = new Verification();
                        var canVerify = target.SourceId.Length > 0 && target.Peer.Length > 0;
                        var query = JsonSerializer.SerializeToUtf8Bytes(new { Id = target.SourceId, target.Peer });
                        if (canVerify)
                        {
                            var baseline = Vpn.Decode<PeerStats>(await Exchange(ssh, 'T', query, 9, ct));
                            verification.Seed(baseline);
                            if (baseline.Error != null)
                                update(new("Мост доступен. Нет данных VPN", "Проверьте открытый ключ клиента и разрешения на чтение статистики awg/wg.", local.Port, true));
                        }
                        update(new(canVerify ? "Мост готов. Ожидаем VPN-клиент" : "Мост готов. VPN не проверен",
                            $"UDP 127.0.0.1:{local.Port} → VPS {target.Host}:{target.Port}. Путь: {transport.Name}." +
                            (canVerify ? "\nСтатистика VPN: " + target.SourceId :
                                "\nДля подтверждения нужен открытый ключ клиента и однозначно найденный интерфейс awg/wg."),
                            local.Port, true));
                        active = true;
                        triedWarp = false;
                        delay = 2;
                        await Forward(ssh, local, verification, canVerify, query, ct);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
                    catch (UserFault e) when (e.Terminal)
                    { update(new("Нужно действие", e.Message, local.Port)); return; }
                    catch (Exception e) when (e is UserFault or IOException or SocketException or OperationCanceledException or JsonException)
                    {
                        var reason = e is UserFault ? e.Message : e is OperationCanceledException ?
                            "Истекло время ожидания ответа." : "Передача прервалась или сервер закрыл канал.";
                        update(new("Путь недоступен", transport.Name + ": " + reason, local.Port));
                        if (active)
                        {
                            interrupted = true;
                            candidates.Remove(transport);
                            candidates.Insert(0, transport);
                            break;
                        }
                    }
                }
                if (!interrupted && !triedWarp && coreTransport == null && p.AutoWarp && p.StartWarp)
                {
                    triedWarp = true;
                    try
                    {
                        warpProxy = await warp.Activate(p, status => update(new(status, Port: local.Port)), ct);
                        candidates = Candidates();
                        if (warpProxy != null) candidates.Insert(0, new ProxyTransport(warpProxy));
                        continue;
                    }
                    catch (UserFault e) when (!e.Terminal) { update(new("Не удалось использовать WARP", e.Message, local.Port)); }
                }
                if (!interrupted)
                {
                    candidates = Candidates();
                    if (warpProxy != null) candidates.Insert(0, new ProxyTransport(warpProxy));
                }
                if (candidates.Count == 0 && previousTarget == null)
                    throw new UserFault("Нет доступного пути до VPS. Включите WARP или проверьте подключение.");
                update(new($"Повторим через {delay} с", "Локальный UDP-порт сохранён. Проверьте сеть или нажмите «Остановить».", local.Port));
                await Task.Delay(TimeSpan.FromSeconds(delay), ct);
                delay = Math.Min(30, delay * 2);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (SocketException) { update(new("Не удалось открыть локальный UDP", "Порт занят или недоступен. Укажите другой порт или 0 для автоматического выбора.")); }
        catch (UserFault e) { update(new("Нужно действие", e.Message)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { update(new("Ошибка запуска", "Проверьте наличие Windows OpenSSH Client и права записи в локальную папку приложения.")); }
    }

    async Task<Profile> Provision(SshSession ssh, Profile profile, Inventory inventory, int localPort, CancellationToken ct)
    {
        if (interaction == null) throw new UserFault("Откройте мастер для настройки нового профиля VPN.");
        var options = Vpn.ProvisionOptions(inventory, profile);
        if (options.Length == 0)
            throw new UserFault("На VPS не найден поддерживаемый AmneziaWG для автоматической настройки. Установите AmneziaWG или выберите существующий файл .conf.");
        var choice = options.Length == 1 ? options[0] : await interaction.SelectVpn(options, ct);
        if (choice == null) throw new UserFault("Настройка отменена. Выберите VPN при следующей попытке.");
        var source = inventory.Sources!.Single(s => s.Id == choice.SourceId);
        if (profile.ServerPublicKey.Length != 0 && profile.ServerPublicKey != source.ServerKey)
            throw new UserFault("Незавершённая настройка относится к другому VPN. Выберите исходный сервер VPN.");
        string privateKey;
        if (profile.ProtectedClientKey.Length == 0)
        {
            var keys = await Setup.Keys(null, ct);
            privateKey = keys.PrivateKey!;
            profile = profile with {
                ProtectedClientKey = Setup.Protect(profile, privateKey, "client-key"),
                ClientPublicKey = keys.PublicKey, ServerPublicKey = source.ServerKey,
                ConfigEndpointPort = choice.Port, LocalPort = localPort
            };
            // Persist before remote writes so a retry always reuses this exact peer.
            await interaction.Save(profile, ct);
        }
        else privateKey = Setup.Open(profile, profile.ProtectedClientKey, "client-key");
        update(new("Настраиваем профиль AmneziaWG…", Port: localPort));
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { Id = choice.SourceId, Peer = profile.ClientPublicKey });
        var result = Vpn.Decode<VpnProvision>(await Exchange(ssh, 'C', payload, 50, ct));
        if (result.Error != null)
            throw new UserFault(result.Error switch {
                "rollback" => "VPS не подтвердил откат. Проверьте выбранный интерфейс AmneziaWG перед повтором.",
                "changed" or "busy" => "Настройки VPN на VPS изменились или уже обновляются. Повторите попытку.",
                "subnet_full" => "В выбранном VPN нет свободных адресов для нового клиента.",
                "layout" => "В конфигурации VPS есть неподдерживаемые или повторяющиеся поля VPN. Обновите Link или импортируйте готовый профиль.",
                "subnet" => "Не удалось выбрать IPv4-подсеть VPN для нового клиента. Импортируйте готовый профиль.",
            _ => "VPS не смог добавить профиль VPN. Проверьте права SSH или подключите существующий файл .conf."
            });
        if (result.ServerKey != source.ServerKey) throw new UserFault("Ключ сервера VPN изменился во время настройки.");
        profile = profile with { ProtectedVpnConfig = Setup.Protect(profile, Setup.BuildConfig(result, privateKey), "vpn-config"),
            ProtectedClientKey = "", ConfigEndpointPort = choice.Port };
        await interaction.Save(profile, ct);
        return profile;
    }

    static async Task<byte[]> Exchange(SshSession ssh, char kind, byte[] data, int timeout, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(timeout));
        using var interrupt = limit.Token.Register(ssh.Interrupt);
        await ssh.Wire.Send(kind, data, limit.Token);
        var frame = await ssh.Wire.Read(limit.Token);
        if (frame.Type != kind) throw new IOException("Неожиданный ответ моста.");
        return frame.Payload;
    }

    async Task Forward(SshSession ssh, LocalUdp local, Verification verification, bool canVerify, byte[] query, CancellationToken ct)
    {
        using var next = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var interrupt = next.Token.Register(ssh.Interrupt);
        var token = next.Token;
        var w = ssh.Wire;
        var clock = Stopwatch.StartNew();
        long pong = 0, sent = 0, received = 0, lastPing = 0, lastVerified = -1;
        IPEndPoint? clientEndpoint = null;
        long clientActivity = 0;
        var peerGate = new object();
        bool reported = false, statsError = false;
        long lastLogged = -1;

        async Task FromClient()
        {
            while (true)
            {
                var packet = await local.Client.ReceiveAsync(token);
                if (packet.Buffer.Length is 0 or > Wire.MaxUdp) continue;
                lock (peerGate)
                {
                    if (clientEndpoint != null && !clientEndpoint.Equals(packet.RemoteEndPoint) &&
                        clock.ElapsedMilliseconds - clientActivity < 30000) continue;
                    clientEndpoint = packet.RemoteEndPoint;
                    clientActivity = clock.ElapsedMilliseconds;
                }
                await w.Send('D', packet.Buffer, token);
                Interlocked.Increment(ref sent);
            }
        }
        async Task FromServer()
        {
            while (true)
            {
                var frame = await w.Read(token);
                switch (frame.Type)
                {
                    case (byte)'P' when frame.Payload.Length == 8:
                        long value = BinaryPrimitives.ReadInt64BigEndian(frame.Payload);
                        if (value <= Interlocked.Read(ref lastPing) && value > Interlocked.Read(ref pong))
                            Interlocked.Exchange(ref pong, value);
                        break;
                    case (byte)'D' when frame.Payload.Length is > 0 and <= Wire.MaxUdp:
                        IPEndPoint? peer;
                        lock (peerGate) peer = clientEndpoint;
                        if (peer != null)
                        {
                            await local.Client.Client.SendToAsync(frame.Payload, SocketFlags.None, peer, token);
                            Interlocked.Increment(ref received);
                        }
                        break;
                    case (byte)'T' when canVerify:
                        var stats = Vpn.Decode<PeerStats>(frame.Payload);
                        long tx = Interlocked.Read(ref sent), rx = Interlocked.Read(ref received);
                        if (verification.Check(stats, tx, rx))
                        {
                            bool changed = tx + rx != lastLogged;
                            if (changed)
                            {
                                lastVerified = clock.ElapsedMilliseconds;
                                lastLogged = tx + rx;
                            }
                            if (changed && !reported)
                            {
                                reported = true;
                                update(new("AmneziaWG: рукопожатие и UDP",
                                    $"Свежий handshake, выросли счётчики приёма и отправки выбранного клиента. UDP-пакетов: {tx} → VPS, {rx} ← VPS.",
                                    local.Port, true));
                            }
                        }
                        if (reported && (stats.Error != null || clock.ElapsedMilliseconds - lastVerified > 180000))
                        {
                            reported = false;
                            update(new("Мост работает. Ждём свежий трафик VPN",
                                "Канал SSH отвечает. Для новой проверки создайте трафик через VPN.", local.Port, true));
                        }
                        if (stats.Error != null && !statsError)
                            update(new("Мост работает. VPN не проверен", "На VPS нет статистики выбранного клиента. Проверьте ключ и интерфейс.", local.Port, true));
                        statsError = stats.Error != null;
                        break;
                    default: throw new IOException("Неизвестное сообщение моста.");
                }
            }
        }
        async Task Monitor()
        {
            using var watchdog = new System.Threading.Timer(_ =>
            {
                if (clock.ElapsedMilliseconds - Interlocked.Read(ref pong) > 18000) ssh.Interrupt();
            }, null, 1000, 1000);
            var bytes = new byte[8];
            while (true)
            {
                long now = Math.Max(1, clock.ElapsedMilliseconds);
                if (now - Interlocked.Read(ref pong) > 18000) throw new IOException("Нет ответа моста.");
                Interlocked.Exchange(ref lastPing, now);
                BinaryPrimitives.WriteInt64BigEndian(bytes, now);
                await w.Send('P', bytes, token);
                if (canVerify) await w.Send('T', query, token);
                await Task.Delay(TimeSpan.FromSeconds(8), token);
            }
        }
        var tasks = new[] { FromClient(), FromServer(), Monitor() };
        var first = await Task.WhenAny(tasks);
        next.Cancel();
        try { await Task.WhenAll(tasks); } catch (Exception) { }
        if (!ct.IsCancellationRequested)
            update(new("Мост прервался", $"До обрыва передано UDP-пакетов: {sent} → VPS, {received} ← VPS.", local.Port));
        await first;
        throw new IOException("Мост остановился.");
    }
}




