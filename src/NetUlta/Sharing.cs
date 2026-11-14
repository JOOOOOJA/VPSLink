using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetUlta;

// An explicit transfer schema: never serialize Profile or owner credentials.
sealed record Invitation(int Version, string Id, string Name, string Host, int SshPort, string Fingerprint,
    string SshKey, string HttpsRelay, string RelayToken, bool UseWarpCore, string RemoteIp, int RemotePort,
    string SourceId, string ClientPublicKey, string VpnConfig);
sealed record InvitationEnvelope(string Format, int Version, string Salt, string Nonce, string Ciphertext, string Tag);
sealed record SharedEntry(string Id, string Name, string Peer, bool Active)
{
    public string Display => Name + (Active ? " — активен" : " — мост отозван");
}
sealed record SharedReply(bool Ready, string? Error, VpnProvision? Vpn, string? SourceId, SharedEntry[]? Invitations);

static class InvitationFile
{
    const int Iterations = 310_000;
    static readonly byte[] Aad = Encoding.ASCII.GetBytes("VPSLink invitation v1");
    public static void Validate(Invitation i)
    {
        if (i.Version != 1 || !Guid.TryParseExact(i.Id, "N", out _) || i.Name.Length is < 1 or > 80 ||
            !Model.IsHost(i.Host) || i.SshPort is < 1 or > 65535 || !Model.IsFingerprint(i.Fingerprint) ||
            i.RemotePort is < 1 or > 65535 || !System.Net.IPAddress.TryParse(i.RemoteIp, out _) ||
            !Model.IsPeerKey(i.ClientPublicKey) || i.SourceId.Length is < 1 or > 180 ||
            i.SshKey.Length is < 100 or > 8192 || i.VpnConfig.Length > 128 * 1024 ||
            i.RelayToken.Length > 1024 || (i.HttpsRelay.Length > 0 &&
                (!HttpsTransport.TryEndpoint(i.HttpsRelay, out _) || i.RelayToken.Length < 16)))
            throw new UserFault("Некорректное приглашение VPSLink.");
        _ = Setup.Inspect(i.VpnConfig);
    }
    static void Password(string password)
    {
        if (password.Length is < 12 or > 256) throw new UserFault("Пароль приглашения: от 12 до 256 символов.");
    }
    public static byte[] Encrypt(Invitation invitation, string password)
    {
        Password(password); Validate(invitation);
        var salt = RandomNumberGenerator.GetBytes(16); var nonce = RandomNumberGenerator.GetBytes(12);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        var clear = JsonSerializer.SerializeToUtf8Bytes(invitation); var cipher = new byte[clear.Length]; var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key); aes.Encrypt(nonce, clear, cipher, tag, Aad);
            return JsonSerializer.SerializeToUtf8Bytes(new InvitationEnvelope("VPSLinkInvitation", 1,
                Convert.ToBase64String(salt), Convert.ToBase64String(nonce), Convert.ToBase64String(cipher), Convert.ToBase64String(tag)));
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(clear); }
    }
    public static Invitation Decrypt(byte[] bytes, string password)
    {
        Password(password);
        if (bytes.Length is < 100 or > 256 * 1024) throw new UserFault("Неверный размер приглашения.");
        byte[]? key = null, clear = null;
        try
        {
            var e = JsonSerializer.Deserialize<InvitationEnvelope>(bytes) ?? throw new JsonException();
            if (e.Format != "VPSLinkInvitation" || e.Version != 1) throw new JsonException();
            var salt = Convert.FromBase64String(e.Salt); var nonce = Convert.FromBase64String(e.Nonce);
            var cipher = Convert.FromBase64String(e.Ciphertext); var tag = Convert.FromBase64String(e.Tag);
            if (salt.Length != 16 || nonce.Length != 12 || tag.Length != 16) throw new JsonException();
            key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
            clear = new byte[cipher.Length]; using var aes = new AesGcm(key); aes.Decrypt(nonce, cipher, tag, clear, Aad);
            var result = JsonSerializer.Deserialize<Invitation>(clear) ?? throw new JsonException();
            Validate(result); return result;
        }
        catch (Exception e) when (e is CryptographicException or FormatException or JsonException or ArgumentException or NullReferenceException)
        { throw new UserFault("Неверный пароль или повреждённое приглашение."); }
        finally { if (key != null) CryptographicOperations.ZeroMemory(key); if (clear != null) CryptographicOperations.ZeroMemory(clear); }
    }
    public static async Task<Profile> Import(Invitation i, CancellationToken ct)
    {
        Validate(i);
        var fields = Setup.Inspect(i.VpnConfig);
        var derived = await Setup.Keys(fields.Private, ct);
        if (derived.PublicKey != i.ClientPublicKey) throw new UserFault("Ключ VPN не соответствует приглашению.");
        var p = new Profile { Name = i.Name, Host = i.Host, SshPort = i.SshPort, User = "root", Fingerprint = i.Fingerprint,
            SharedAccess = true, InvitationId = i.Id, Auth = AuthKind.Key, VpnSetup = VpnSetup.Import,
            HttpsRelay = i.HttpsRelay, UseWarpCore = i.UseWarpCore, AutoWarp = false, UseSystemRoute = !i.UseWarpCore,
            RemoteIp = i.RemoteIp, RemotePort = i.RemotePort, LocalPort = 39609, SourceId = i.SourceId,
            ServerPublicKey = fields.Server, ConfigEndpointPort = i.RemotePort, ClientPublicKey = i.ClientPublicKey };
        var key = Encoding.UTF8.GetBytes(i.SshKey);
        try
        {
            p = p with { ProtectedCredential = ProfileStore.Protect(p.Id, new Credential("", key)),
                ProtectedVpnConfig = Setup.Protect(p, i.VpnConfig, "vpn-config"),
                ProtectedRelayToken = i.HttpsRelay.Length == 0 ? "" : Setup.Protect(p, i.RelayToken, "https-relay") };
            Model.Validate(p); return p;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}

static class Sharing
{
    internal static async Task<T> Exchange<T>(SshSession ssh, char kind, object? request, CancellationToken ct)
    {
        await ssh.Wire.Send(kind, request == null ? Array.Empty<byte>() : JsonSerializer.SerializeToUtf8Bytes(request), ct);
        var frame = await ssh.Wire.Read(ct);
        if (frame.Type != kind) throw new UserFault("Неожиданный ответ сервера приглашений.");
        return Vpn.Decode<T>(frame.Payload);
    }
    public static async Task<T> Session<T>(Profile p, string directory, Func<SshSession, ITransport, CancellationToken, Task<T>> work, CancellationToken ct)
    {
        if (p.SharedAccess || p.User != "root") throw new UserFault("Приглашения создаёт владелец с административным SSH-доступом root.");
        Model.Validate(p);
        using var core = p.UseWarpCore ? new RestartableWarpCore(p.ZapretPath, p.WinwsStrategy) : null;
        ITransport upstream = core != null ? core : p.Proxy != ProxyKind.None ? new ProxyTransport(p) : new TcpTransport(p.AdapterId);
        ITransport transport = p.HttpsRelay.Length > 0 ? new HttpsTransport(p, upstream) : upstream;
        using var ssh = await SshSession.Open(transport, p, directory, ct);
        using var interrupt = ct.Register(ssh.Interrupt);
        return await work(ssh, transport, ct);
    }
    public static void Check(SharedReply reply)
    {
        if (!reply.Ready) throw new UserFault(reply.Error == "peer_remove"
            ? "Мост отозван, но удалить VPN-ключ полностью не удалось. Повторите отзыв; до этого прямой VPN-доступ может сохраняться."
            : "Сервер не завершил действие. Обновите список приглашений: если запись появилась, отзовите её перед повтором. Код: " + reply.Error);
    }
    public static async Task<Invitation> Create(Profile owner, string name, string directory, CancellationToken ct)
    {
        return await Session(owner, directory, async (ssh, transport, token) =>
        {
            var inventory = await Exchange<Inventory>(ssh, 'I', null, token);
            if (inventory.Error != null) throw new UserFault("Не удалось проверить VPN на сервере.");
            var target = Vpn.Select(owner, inventory);
            var source = inventory.Sources?.SingleOrDefault(s => s.Id == target.SourceId && s.CanProvision)
                ?? throw new UserFault("Сначала подключите профиль владельца и выберите поддерживаемый сервер AmneziaWG.");
            var keys = await Setup.Keys(null, token);
            using var files = new SshFiles(directory);
            var info = SshSession.StartInfo(Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe"),
                "-q", "-t", "ed25519", "-N", "", "-C", "vpslink-invitation", "-f", files.Key);
            using var gen = Process.Start(info) ?? throw new IOException("ssh-keygen");
            using var kill = token.Register(() => SshSession.Kill(gen));
            await gen.WaitForExitAsync(token);
            if (gen.ExitCode != 0) throw new UserFault("Не удалось создать отдельный SSH-ключ.");
            string pub;
            try { pub = string.Join(" ", File.ReadAllText(files.Key + ".pub").Split(' ').Take(2)); }
            finally { File.Delete(files.Key + ".pub"); }
            string id = Guid.NewGuid().ToString("N");
            var reply = await Exchange<SharedReply>(ssh, 'J', new { Action = "Create", ShareId = id, Name = name,
                SshKey = pub, Id = source.Id, Peer = keys.PublicKey, target.Host, target.Port }, token);
            Check(reply);
            if (reply.Vpn == null || reply.Vpn.ServerKey != source.ServerKey) throw new UserFault("Изменился ключ VPN. Проверьте список приглашений.");
            var invitation = new Invitation(1, id, name, owner.Host, owner.SshPort, owner.Fingerprint,
                File.ReadAllText(files.Key), owner.HttpsRelay,
                owner.HttpsRelay.Length == 0 ? "" : Setup.Open(owner, owner.ProtectedRelayToken, "https-relay"),
                owner.UseWarpCore, target.Host, target.Port, source.Id, keys.PublicKey, Setup.BuildConfig(reply.Vpn, keys.PrivateKey!));
            var recipient = await InvitationFile.Import(invitation, token);
            // Verify that sshd enforces/accepts the installed restricted key before exporting.
            using var client = await SshSession.Open(transport, recipient, directory, token);
            using var cancelClient = token.Register(client.Interrupt);
            var proof = await Exchange<Inventory>(client, 'I', null, token);
            if (proof.Sources?.Length != 1 || proof.Sources[0].PeerKeys?.SingleOrDefault() != keys.PublicKey)
                throw new UserFault("Проверка ограниченного доступа не прошла. Отзовите приглашение из списка.");
            return invitation;
        }, ct);
    }
}
