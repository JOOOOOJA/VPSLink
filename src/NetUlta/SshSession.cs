using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace NetUlta;

sealed class AskPass : IDisposable
{
    const string PipeVariable = "TFL_ASKPASS_PIPE";
    const string ModeVariable = "TFL_ASKPASS_MODE";
    readonly NamedPipeServerStream pipe;
    readonly CancellationTokenSource stop;
    readonly Task write;
    public AskPass(ProcessStartInfo info, AuthKind kind, string secret, CancellationToken ct, string? helperExe = null)
    {
        string name = "TFL-" + Guid.NewGuid().ToString("N");
        pipe = new NamedPipeServerStream(name, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        info.Environment[PipeVariable] = name;
        info.Environment[ModeVariable] = kind.ToString();
        var executable = helperExe ?? Environment.ProcessPath!;
        // Win32 OpenSSH may read SSH_ASKPASS through a narrow environment API. Keep
        // the helper path relative; .NET sets the full Unicode working directory.
        info.WorkingDirectory = Path.GetDirectoryName(executable)!;
        info.Environment["SSH_ASKPASS"] = ".\\" + Path.GetFileName(executable);
        info.Environment["SSH_ASKPASS_REQUIRE"] = "force";
        write = Send(secret, stop.Token);
    }
    async Task Send(string secret, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(secret + "\n");
        try { await pipe.WaitForConnectionAsync(ct); await pipe.WriteAsync(bytes, ct); await pipe.FlushAsync(ct); }
        catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException) { }
        finally { CryptographicOperations.ZeroMemory(bytes); pipe.Dispose(); }
    }
    public static bool IsHelper => Environment.GetEnvironmentVariable(PipeVariable) != null;
    public static int Run(string[] args)
    {
        var name = Environment.GetEnvironmentVariable(PipeVariable);
        var mode = Environment.GetEnvironmentVariable(ModeVariable);
        if (name == null || name.Length != 36 || !name.StartsWith("TFL-") ||
            Environment.GetEnvironmentVariable("SSH_ASKPASS_PROMPT") is "confirm" or "none" ||
            args.Length != 1 || !(mode switch
            {
                "Key" => args[0].StartsWith("Enter passphrase for key ", StringComparison.Ordinal) && args[0].TrimEnd().EndsWith(':'),
                "Password" => args[0].TrimEnd().EndsWith("password:", StringComparison.Ordinal),
                _ => false
            })) return 1;
        try
        {
            using var input = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.CurrentUserOnly);
            input.Connect(3000);
            using var output = Console.OpenStandardOutput();
            input.CopyTo(output, 1024);
            output.Flush();
            return 0;
        }
        catch (Exception e) when (e is IOException or TimeoutException or UnauthorizedAccessException) { return 1; }
    }
    public void Dispose()
    {
        stop.Cancel();
        pipe.Dispose();
        _ = write.ContinueWith(t => { _ = t.Exception; stop.Dispose(); }, TaskScheduler.Default);
    }
}

sealed class SshFiles : IDisposable
{
    public string Folder { get; }
    public string Pin => Path.Combine(Folder, "known_hosts");
    public string Key => Path.Combine(Folder, "identity");
    const string Prefix = "session-";
    public SshFiles(string root)
    {
        Directory.CreateDirectory(root);
        var owner = WindowsIdentity.GetCurrent().User ?? throw new IOException();
        var acl = new DirectorySecurity();
        acl.SetOwner(owner);
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Folder = Path.Combine(root, Prefix + Guid.NewGuid().ToString("N"));
        new DirectoryInfo(Folder).Create(acl);
    }
    public void Dispose() => Clear(Folder);
    static void Clear(string folder)
    {
        try
        {
            if (!Directory.Exists(folder) || (File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) return;
            File.Delete(Path.Combine(folder, "identity"));
            File.Delete(Path.Combine(folder, "known_hosts"));
            Directory.Delete(folder);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
    public static void ClearOrphans(string root)
    {
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) return;
        foreach (var folder in Directory.EnumerateDirectories(root, Prefix + "*"))
            if (Guid.TryParseExact(Path.GetFileName(folder)[Prefix.Length..], "N", out _)) Clear(folder);
    }
}

sealed class SshSession : IDisposable
{
    internal static string SshPath(string file)
    {
        var bundledDirectory = Path.Combine(AppContext.BaseDirectory, "openssh");
        // Source builds can use system OpenSSH. A packaged client and its helper
        // tools must come from the same directory, including on Windows 10.
        var directory = Directory.Exists(bundledDirectory)
            ? bundledDirectory : Path.Combine(Environment.SystemDirectory, "OpenSSH");
        var path = Path.Combine(directory, file);
        if (!File.Exists(path)) throw new UserFault("Не найден " + file + ". Переустановите VPSLink или распакуйте архив целиком.");
        return path;
    }
    static readonly byte[] Relay = ReadRelay();
    const string Bootstrap = "python3 -u -c 'import sys; n=int(sys.stdin.buffer.readline()); exec(compile(sys.stdin.buffer.read(n), \"<thingsnotfun-link>\", \"exec\"))'";
    readonly Process process;
    readonly LoopbackBridge bridge;
    readonly Task<string> errors;
    public Wire Wire { get; }

    SshSession(Process p, LoopbackBridge bridge)
    {
        process = p;
        this.bridge = bridge;
        Wire = new Wire(BufferOutput(p.StandardOutput.BaseStream), p.StandardInput.BaseStream);
        errors = DrainErrors(p.StandardError);
    }
    // Headers and UDP payloads share a byte stream. Drain available pipe data in
    // larger reads instead of scheduling a pipe read for every header and body.
    // Only the receive side is buffered; writes/flushes keep their existing timing.
    internal static Stream BufferOutput(Stream output) => new BufferedStream(output, 64 * 1024);
    static byte[] ReadRelay()
    {
        using var dest = new MemoryStream();
        foreach (var resource in new[] { "NetUlta.awg_setup.py", "NetUlta.gateway_setup.py", "NetUlta.sharing_setup.py", "NetUlta.relay.py" })
        {
            using var src = typeof(SshSession).Assembly.GetManifestResourceStream(resource);
            if (src == null && resource == "NetUlta.gateway_setup.py") continue;
            if (src == null) throw new IOException("Missing SSH bridge resource.");
            if (resource == "NetUlta.sharing_setup.py")
            {
                foreach (var item in new[] { ("SHARED_RELAY_SOURCE", "relay.py"), ("SHARED_CLIENT_SOURCE", "shared_client.py") })
                {
                    using var embedded = typeof(SshSession).Assembly.GetManifestResourceStream("NetUlta." + item.Item2)!;
                    using var bytes = new MemoryStream(); embedded.CopyTo(bytes);
                    dest.Write(Encoding.ASCII.GetBytes(item.Item1 + " = '" + Convert.ToBase64String(bytes.ToArray()) + "'\n"));
                }
            }
            if (resource == "NetUlta.gateway_setup.py")
            {
                using var gateway = typeof(SshSession).Assembly.GetManifestResourceStream("NetUlta.https_relay.py")
                    ?? throw new IOException("Missing gateway resource.");
                using var content = new MemoryStream();
                gateway.CopyTo(content);
                var declaration = Encoding.ASCII.GetBytes("GATEWAY_RELAY_SOURCE = '" + Convert.ToBase64String(content.ToArray()) + "'\n");
                dest.Write(declaration);
            }
            src.CopyTo(dest);
            dest.WriteByte((byte)'\n');
        }
        return dest.ToArray();
    }
    public static ProcessStartInfo StartInfo(string exe, params string[] args)
    {
        var info = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        return info;
    }

    static async Task<string> DrainErrors(StreamReader reader)
    {
        var summary = new StringBuilder();
        var buffer = new char[512];
        int n;
        while ((n = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            if (summary.Length < 4096) summary.Append(buffer, 0, Math.Min(n, 4096 - summary.Length));
        }
        return summary.ToString();
    }

    public static async Task<SshSession> Open(ITransport transport, Profile p, string directory, CancellationToken ct, string? helperExe = null)
    {
        if (!Model.IsFingerprint(p.Fingerprint)) throw new UserFault("Подтвердите отпечаток SSH перед входом.");
        string ssh = SshPath("ssh.exe");
        var exe = (helperExe ?? Environment.ProcessPath!).Replace('\\', '/');
        var pinCommand = "KnownHostsCommand=\"" + exe + "\" --known-host " + p.Fingerprint + " %I %H %t %K";
        using var files = p.Auth == AuthKind.Key ? new SshFiles(directory) : null;
        var bridge = await LoopbackBridge.Open(transport, p, ct);
        SshSession? session = null;
        try
        {
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(ct);
            startup.CancelAfter(TimeSpan.FromSeconds(22));
            var token = startup.Token;
            var info = StartInfo(ssh, "-F", "NUL", "-T", "-4",
                "-o", "StrictHostKeyChecking=yes", "-o", "CheckHostIP=no", "-o", "UpdateHostKeys=no",
                "-o", "GlobalKnownHostsFile=none", "-o", "UserKnownHostsFile=none", "-o", pinCommand,
                "-o", "HostKeyAlias=tfl-" + p.Id.ToString("N"), "-o", "HostKeyAlgorithms=ssh-ed25519",
                "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "IdentityAgent=none",
                "-o", "IdentitiesOnly=yes", "-o", "NumberOfPasswordPrompts=1", "-o", "KbdInteractiveAuthentication=no",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "ConnectTimeout=9",
                "-o", p.Auth == AuthKind.Password ? "PreferredAuthentications=password" : "PreferredAuthentications=publickey",
                "-p", bridge.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), "-l", p.User);
            info.Environment.Remove("SSH_ASKPASS_PROMPT");
            info.Environment.Remove("SSH_AUTH_SOCK");
            info.Environment["LC_ALL"] = "C";
            var credentials = ProfileStore.Open(p);
            if (p.Auth == AuthKind.Key)
            {
                if (credentials.Key == null) throw new UserFault("В профиле нет приватного ключа.");
                try { File.WriteAllBytes(files!.Key, credentials.Key); }
                finally { CryptographicOperations.ZeroMemory(credentials.Key); }
                info.ArgumentList.Add("-i");
                info.ArgumentList.Add(files!.Key);
            }
            using var helper = new AskPass(info, p.Auth, credentials.Passphrase, token, helperExe);
            info.ArgumentList.Add("127.0.0.1");
            info.ArgumentList.Add(p.SharedAccess ? "vpslink-client-v1" : Bootstrap);
            var process = Process.Start(info) ?? throw new IOException("OpenSSH");
            session = new SshSession(process, bridge);
            using var interrupt = token.Register(session.Interrupt);
            try
            {
                var stdin = process.StandardInput.BaseStream;
                if (!p.SharedAccess)
                {
                    await stdin.WriteAsync(Encoding.ASCII.GetBytes(Relay.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n"), token);
                    await stdin.WriteAsync(Relay, token);
                    await stdin.FlushAsync(token);
                }
                var hello = await session.Wire.Read(token);
                if (hello.Type != 'H' || !hello.Payload.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes("TFL/1")))
                    throw new UserFault("Ответ SSH не совпал с протоколом моста. Проверьте, не печатает ли shell приветствие в stdout.");
            }
            catch (Exception e) when (e is IOException or OperationCanceledException)
            {
                ct.ThrowIfCancellationRequested();
                throw await session.Explain(e);
            }
            return session;
        }
        catch
        {
            if (session != null) session.Dispose(); else bridge.Dispose();
            throw;
        }
    }

    async Task<UserFault> Explain(Exception error)
    {
        string s = "";
        try { s = await errors.WaitAsync(TimeSpan.FromMilliseconds(750)); } catch (Exception) { }
        if (s.Contains("Host key verification failed", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("REMOTE HOST IDENTIFICATION", StringComparison.OrdinalIgnoreCase))
            return new UserFault("Ключ SSH не прошёл проверку. Сверьте отпечаток ED25519 в консоли хостера.");
        if (s.Contains("Bad configuration option: knownhostscommand", StringComparison.OrdinalIgnoreCase))
            return new UserFault("Версия системного OpenSSH устарела. Используйте комплектную сборку VPSLink с OpenSSH.");
        if (s.Contains("Permission denied", StringComparison.OrdinalIgnoreCase))
            return new UserFault("SSH отклонил пароль или ключ. Проверьте доступ и разрешённый способ входа.");
        if (s.Contains("python3", StringComparison.OrdinalIgnoreCase) && s.Contains("not found", StringComparison.OrdinalIgnoreCase))
            return new UserFault("На VPS не найден python3. Для UDP-моста нужен уже установленный Python 3.8+.");
        return new UserFault(error is OperationCanceledException ?
            "SSH не запустил мост за отведённое время. Проверьте доступ и работу python3 на VPS." :
            "SSH завершился до запуска моста. Проверьте, что учётная запись может выполнять команды и запускать python3.", false);
    }

    // Diagnostic probe: empty known_hosts and strict checking intentionally stop before user authentication.
    internal static async Task Probe(ITransport transport, Profile p, CancellationToken ct)
    {
        if (await DiscoverFingerprint(transport, p, ct) != p.Fingerprint)
            throw new UserFault("Отпечаток ED25519 не совпал. Учётные данные не отправлялись.");
    }

    internal static async Task<string> DiscoverFingerprint(ITransport transport, Profile p, CancellationToken ct)
    {
        string ssh = SshPath("ssh.exe");
        using var bridge = await LoopbackBridge.Open(transport, p, ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        var info = StartInfo(ssh, "-F", "NUL", "-v", "-T", "-4",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
            "-o", "GlobalKnownHostsFile=none", "-o", "UserKnownHostsFile=none", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "ConnectTimeout=8", "-p", bridge.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), "127.0.0.1");
        info.Environment["LC_ALL"] = "C";
        using var process = Process.Start(info)!;
        try
        {
            var read = process.StandardOutput.ReadToEndAsync();
            var error = DrainErrors(process.StandardError);
            await process.WaitForExitAsync(timeout.Token);
            await read;
            var match = System.Text.RegularExpressions.Regex.Match(await error,
                @"(?m)^debug1: Server host key: ssh-ed25519 (SHA256:[A-Za-z0-9+/]{43})\r?$");
            if (!match.Success) throw new UserFault("Через выбранный путь не получен ключ ED25519 сервера.", false);
            var fingerprint = match.Groups[1].Value;
            if (!Model.IsFingerprint(fingerprint)) throw new UserFault("VPS вернул неверный отпечаток SSH.");
            return fingerprint;
        }
        finally { Kill(process); }
    }

    // OpenSSH supplies its own negotiated key; output is an entry for that exact key only.
    internal static int KnownHost(string[] args)
    {
        if (args.Length != 6 || args[0] != "--known-host") return 1;
        if (args[2] != "HOSTNAME") return 0;  // ORDER and ADDRESS are intentionally empty.
        if (args[3].Length != 36 || !args[3].StartsWith("tfl-", StringComparison.Ordinal) ||
            !Guid.TryParseExact(args[3][4..], "N", out _) || args[4] != "ssh-ed25519") return 0;
        try
        {
            string key = VerifyKey(args[5], args[1]);
            using var output = Console.OpenStandardOutput();
            output.Write(Encoding.ASCII.GetBytes(args[3] + " ssh-ed25519 " + key + "\n"));
            output.Flush();
        }
        catch (UserFault) { } // Empty response fails the mandatory OpenSSH host-key check.
        return 0;
    }

    internal static string VerifyKey(string pin, string expected)
    {
        byte[] bytes;
        try { bytes = Convert.FromBase64String(pin); }
        catch (FormatException) { throw new UserFault("Сервер вернул некорректный ключ SSH."); }
        if (bytes.Length != 51 || BinaryPrimitives.ReadInt32BigEndian(bytes) != 11 ||
            !bytes.AsSpan(4, 11).SequenceEqual(Encoding.ASCII.GetBytes("ssh-ed25519")) ||
            BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(15)) != 32)
            throw new UserFault("Сервер вернул некорректный ключ ED25519.");
        var actual = "SHA256:" + Convert.ToBase64String(SHA256.HashData(bytes)).TrimEnd('=');
        if (actual != expected)
            throw new UserFault("Отпечаток SSH не совпал с сохранённым. Подключение прекращено до отправки учётных данных.");
        return Convert.ToBase64String(bytes);
    }
    public void Interrupt()
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }
    public static void Kill(Process p)
    {
        try { if (!p.HasExited) { p.Kill(entireProcessTree: true); p.WaitForExit(2000); } }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }
    public void Dispose()
    {
        bridge.Dispose();
        Kill(process);
        process.Dispose();
        _ = errors.ContinueWith(t => { _ = t.Exception; }, TaskScheduler.Default);
    }
}







