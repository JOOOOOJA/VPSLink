using System.Diagnostics;
using System.Net.NetworkInformation;

namespace NetUlta;

sealed record StrategyAttempt(WinwsStrategy Strategy, bool Success, long Milliseconds, string Message);

static class StrategyProbe
{
    public static void RequireIsolation()
    {
        if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.OperationalStatus == OperationalStatus.Up &&
            (n.Name.Contains("Amnezia", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase))))
            throw new UserFault("Для подбора сначала отключите профиль AmneziaVPN и системный WARP. Проверка сама их не выключает.");
        foreach (string name in new[] { "winws", "winws2", "usque" })
        {
            var processes = Process.GetProcessesByName(name);
            try { if (processes.Length != 0) throw new UserFault("Для подбора остановите мост VPSLink и другие запущенные winws/usque. Это нужно для независимой проверки. Они не будут остановлены автоматически."); }
            finally { foreach (var process in processes) process.Dispose(); }
        }
    }
    public static void RequireReady(Profile profile)
    {
        RequireIsolation();
        if (!profile.UseWarpCore) throw new UserFault("Эти стратегии предназначены для встроенного WARP. Включите его в настройках выбранного сервера.");
        if (!Model.IsFingerprint(profile.Fingerprint)) throw new UserFault("Сначала сохраните проверенный SSH-отпечаток сервера.");
        if (!WarpCore.Registered) throw new UserFault("Сначала выполните первое подключение VPSLink и регистрацию WARP. Затем можно подбирать стратегии.");
    }
    public static async Task Probe(Profile profile, WinwsStrategy strategy, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        RequireReady(profile);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(25));
        using var core = WarpCore.Start(profile.ZapretPath, strategy, exclusive: true);
        ITransport transport = profile.HttpsRelay.Length == 0 ? core : new HttpsTransport(profile, core);
        // No alternate transports, credentials, provisioning, system routes or VPN activation.
        await SshSession.Probe(transport, profile, timeout.Token);
    }
    internal static async Task<WinwsStrategy?> Select(IReadOnlyList<WinwsStrategy> choices,
        Func<WinwsStrategy, CancellationToken, Task> probe, Action<StrategyAttempt> report, CancellationToken ct)
    {
        foreach (var original in choices)
        {
            ct.ThrowIfCancellationRequested();
            var strategy = WinwsStrategies.Snapshot(original);
            var elapsed = Stopwatch.StartNew();
            try
            {
                await probe(strategy, ct);
                ct.ThrowIfCancellationRequested();
                report(new(strategy, true, elapsed.ElapsedMilliseconds, "Путь до VPS работает; SSH-ключ совпал. VPN и интернет проверяются после обычного подключения."));
                return strategy;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception e) when (e is UserFault or IOException or OperationCanceledException or System.Net.Sockets.SocketException or System.ComponentModel.Win32Exception or System.Security.Authentication.AuthenticationException or TimeoutException)
            {
                report(new(strategy, false, elapsed.ElapsedMilliseconds, e is UserFault ? e.Message : "За время проверки путь до VPS не подтвердился."));
            }
        }
        return null;
    }
}
