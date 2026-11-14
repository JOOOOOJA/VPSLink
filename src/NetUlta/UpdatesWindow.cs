using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace NetUlta;

sealed partial class MainWindow
{
    readonly Label updateStatus = new() { AutoSize = true, MaximumSize = new Size(620, 0), Margin = new Padding(0, 16, 0, 16) };
    readonly Button checkUpdate = Button("Проверить обновления"), downloadUpdate = Button("Скачать обновление"), installUpdate = Button("Установить и закрыть Link");
    readonly CheckBox automaticUpdates = new() { Text = "Автоматически проверять новые версии", AutoSize = true };
    readonly System.Windows.Forms.Timer updateTimer = new() { Interval = 30 * 60 * 1000 };
    readonly CancellationTokenSource updateStop = new();
    ReleaseUpdate? availableUpdate;
    string? downloadedUpdate;
    bool updateBusy;
    DateTime lastUpdateCheck;

    Control BuildUpdatesPage()
    {
        var page = Page(); var content = Stack();
        content.Controls.Add(Heading("Обновления", "Версия " + Application.ProductVersion.Split('+')[0] + ". Канал Proof of Concept: предварительные, экспериментальные версии. Обновление сохраняет серверы, ключи и VPN-профили."));
        updateStatus.Text = UpdateSource.Configured ? "Можно проверить наличие новой версии." : "Репозиторий GitHub ещё не подключён. Проверка станет доступна после его публикации.";
        content.Controls.Add(updateStatus);
        automaticUpdates.Checked = true;
        try
        {
            string path = Path.Combine(directory, "updates.json");
            if (File.Exists(path))
            {
                using var settings = JsonDocument.Parse(File.ReadAllText(path));
                automaticUpdates.Checked = settings.RootElement.GetProperty("automatic").GetBoolean();
                lastUpdateCheck = settings.RootElement.GetProperty("lastCheckUtc").GetDateTime();
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException) { }
        automaticUpdates.Enabled = checkUpdate.Enabled = UpdateSource.Configured;
        downloadUpdate.Enabled = installUpdate.Enabled = false;
        automaticUpdates.CheckedChanged += (_, _) => SaveUpdatePreferences();
        checkUpdate.Click += async (_, _) => await CheckUpdates(false);
        downloadUpdate.Click += async (_, _) => await DownloadUpdate();
        installUpdate.Click += (_, _) => InstallUpdate();
        content.Controls.Add(automaticUpdates);
        content.Controls.Add(Row(checkUpdate, downloadUpdate));
        content.Controls.Add(Row(installUpdate));
        content.Controls.Add(HelpText("Проверка не устанавливает обновления сама. Сначала скачайте пакет при работающем интернете. Для установки отключите профиль в AmneziaVPN, затем мост Link. Подтвердите запрос Windows; после обновления подключитесь вручную."));
        tips.SetToolTip(automaticUpdates, "Проверяет новые версии GitHub, включая PoC-релизы, при запуске и затем не чаще раза в сутки. VPN и другие программы автоматически не отключаются.");
        page.Controls.Add(content);
        Shown += async (_, _) => { updateTimer.Start(); await CheckUpdates(true); };
        updateTimer.Tick += async (_, _) => await CheckUpdates(true);
        FormClosed += (_, _) => { updateTimer.Stop(); updateTimer.Dispose(); updateStop.Cancel(); };
        return page;
    }
    void SaveUpdatePreferences()
    {
        try
        {
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "updates.json"), temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(new { automatic = automaticUpdates.Checked, lastCheckUtc = lastUpdateCheck }));
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
    async Task CheckUpdates(bool automatic)
    {
        if (!UpdateSource.Configured || updateBusy || updateStop.IsCancellationRequested ||
            (automatic && (!automaticUpdates.Checked || availableUpdate != null || DateTime.UtcNow - lastUpdateCheck < TimeSpan.FromDays(1)))) return;
        updateBusy = true; checkUpdate.Enabled = downloadUpdate.Enabled = installUpdate.Enabled = false;
        updateStatus.Text = "Проверяем GitHub…";
        try
        {
            using var client = new Updates(UpdateSource.Repository, includePrereleases: UpdateSource.IncludePrereleases);
            availableUpdate = await client.Check(Version.Parse(Application.ProductVersion.Split('+')[0]), updateStop.Token);
            downloadedUpdate = null;
            lastUpdateCheck = DateTime.UtcNow; SaveUpdatePreferences();
            updateStatus.Text = availableUpdate == null ? "Установлена актуальная версия." : "Доступна версия " + availableUpdate.Version + ". Можно скачать обновление.";
        }
        catch (Exception e) when (UpdateError(e)) { updateStatus.Text = e is UserFault ? e.Message : "Не удалось проверить обновления. Повторите после подключения к интернету."; }
        finally { updateBusy = false; if (!IsDisposed) { checkUpdate.Enabled = true; downloadUpdate.Enabled = availableUpdate != null; installUpdate.Enabled = downloadedUpdate != null; } }
    }
    async Task DownloadUpdate()
    {
        if (availableUpdate == null || updateBusy) return;
        updateBusy = true; checkUpdate.Enabled = downloadUpdate.Enabled = installUpdate.Enabled = false;
        try
        {
            updateStatus.Text = "Скачиваем и проверяем обновление…";
            using var client = new Updates(UpdateSource.Repository, includePrereleases: UpdateSource.IncludePrereleases);
            downloadedUpdate = await client.Download(availableUpdate, Path.Combine(directory, "Updates"), updateStop.Token);
            updateStatus.Text = "Обновление проверено. Отключите VPN в AmneziaVPN, затем мост Link и нажмите «Установить».";
        }
        catch (Exception e) when (UpdateError(e)) { downloadedUpdate = null; updateStatus.Text = e is UserFault ? e.Message : "Не удалось скачать обновление. Установленная версия не изменена."; }
        finally { updateBusy = false; if (!IsDisposed) { checkUpdate.Enabled = downloadUpdate.Enabled = true; installUpdate.Enabled = downloadedUpdate != null; } }
    }
    void InstallUpdate()
    {
        if (downloadedUpdate == null || availableUpdate == null || updateBusy) return;
        if (running != null || gatewayWork != null || strategyWork != null || NetworkInterface.GetAllNetworkInterfaces().Any(n => n.OperationalStatus == OperationalStatus.Up && n.Name.Contains("Amnezia", StringComparison.OrdinalIgnoreCase)))
        { updateStatus.Text = "Сначала отключите профиль AmneziaVPN и мост Link. Пакет уже скачан, интернет для установки не нужен."; return; }
        try
        {
            Updates.Verify(downloadedUpdate, availableUpdate);
            using var installer = Process.Start(new ProcessStartInfo(downloadedUpdate)
            { UseShellExecute = true, Verb = "runas", Arguments = "/SP- /SILENT /NORESTART /NORESTARTAPPLICATIONS" });
            if (installer == null) throw new IOException();
            allowClose = true; Close();
        }
        catch (Exception e) when (UpdateError(e) || e is System.ComponentModel.Win32Exception)
        { updateStatus.Text = e is UserFault ? e.Message : "Установка не запущена или отменена. Link остаётся доступен."; }
    }
    static bool UpdateError(Exception e) => e is UserFault or IOException or UnauthorizedAccessException or HttpRequestException or OperationCanceledException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException;
}
