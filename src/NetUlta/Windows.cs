using System.Diagnostics;

namespace NetUlta;

sealed partial class MainWindow : Form
{
    readonly string directory;
    readonly ProfileStore store;
    readonly ComboBox profiles = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 285, AccessibleName = "Профиль сервера" };
    readonly Button add = Button("Добавить сервер"), edit = Button("Изменить"), delete = Button("Удалить"),
        start = Button("Подключить"), stop = Button("Отключить"), export = Button("Сохранить профиль VPN…"),
        test = Button("Тестовый профиль…"), internet = Button("Проверить интернет"), copy = Button("Копировать адрес"),
        gateway = Button("Постоянный шлюз…");
    readonly LinkLabel warpInstall = new() { Text = "Установить Cloudflare WARP", AutoSize = true, Visible = false };
    readonly Label status = new() { AutoSize = true, Text = "Готово к подключению", Font = new Font("Segoe UI", 14, FontStyle.Bold) };
    readonly Label endpoint = new() { AutoSize = true, Text = "Локальный адрес появится после запуска." };
    readonly Label hint = new() { AutoSize = true, Text = "Добавьте свой сервер, чтобы начать." };
    readonly TextBox diagnostics = new() { ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical,
        Dock = DockStyle.Fill, MaxLength = 60000, Visible = false, AccessibleName = "Диагностика подключения" };
    readonly NotifyIcon tray;
    List<Profile> saved;
    CancellationTokenSource? running;
    CancellationTokenSource? gatewayWork;
    Task? run;
    int generation;
    int? readyPort;
    bool closing, allowClose, checkingInternet, writable = true;

    static Button Button(string text) => new() { Text = text, AutoSize = true, MinimumSize = new Size(0, 33) };
    static bool IsAdministrator()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
    static FlowLayoutPanel Row(params Control[] content)
    {
        var panel = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true, Margin = new Padding(0, 3, 0, 5) };
        panel.Controls.AddRange(content);
        return panel;
    }

    public MainWindow(string directory, bool startup = false, Guid? connectProfile = null)
    {
        this.directory = directory;
        store = new(directory);
        BuildShell();

        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => RestoreWindow());
        menu.Items.Add("Остановить мост", null, async (_, _) => await StopAsync());
        menu.Items.Add("Выйти", null, (_, _) => Close());
        tray = new NotifyIcon { Icon = Icon, Text = Text, ContextMenuStrip = menu };
        tray.DoubleClick += (_, _) => RestoreWindow();
        Resize += (_, _) => { if (WindowState == FormWindowState.Minimized && !closing) { tray.Visible = true; Hide(); } };
        try { saved = store.Load(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            saved = new();
            writable = false;
            status.Text = "Не удалось прочитать профили";
            hint.Text = "Файл настроек не изменён. Подробности и путь к нему — в «Диагностике».";
            Append("Хранилище профилей не читается. Добавление отключено, чтобы не перезаписать ваши настройки. " +
                "Сохраните копию файла перед восстановлением: " + Path.Combine(directory, "profiles.json") +
                ". Последняя резервная копия приложения: profiles.json.bak.");
        }
        profiles.SelectedIndexChanged += (_, _) => Buttons();
        add.Click += async (_, _) => await AddServer();
        edit.Click += (_, _) => { if (profiles.SelectedItem is Profile p) EditProfile(p); };
        delete.Click += (_, _) => Remove();
        start.Click += async (_, _) => { if (profiles.SelectedItem is Profile p) await StartAsync(p); };
        gateway.Click += async (_, _) => await ConfigureGateway();
        stop.Click += async (_, _) => await StopAsync();
        export.Click += (_, _) => Export(handshakeOnly: false);
        test.Click += (_, _) => Export(handshakeOnly: true);
        internet.Click += async (_, _) => await CheckInternet();
        copy.Click += (_, _) => { if (readyPort is int port) TryUi(() => Clipboard.SetText("127.0.0.1:" + port)); };
        FormClosing += HandleClosing;
        FormClosing += (_, _) => gatewayWork?.Cancel();
        RefreshProfiles(null);
        Shown += async (_, _) =>
        {
            if (startup) WindowState = FormWindowState.Minimized;
            if (saved.Any(p => p.StartWithWindows) && IsAdministrator()) TryUi(() => StartupRegistration.Set(true));
            var automatic = connectProfile.HasValue ? saved.FirstOrDefault(p => p.Id == connectProfile) : saved.FirstOrDefault(p => p.AutoConnect);
            if (automatic != null) { RefreshProfiles(automatic.Id); await StartAsync(automatic); }
        };
    }

    async Task AddServer()
    {
        if (running != null || gatewayWork != null || closing || !writable) return;
        var profile = EditProfile(null);
        if (profile != null) await StartAsync(profile);
    }
    void RestoreWindow()
    {
        Show();
        WindowState = FormWindowState.Normal;
        tray.Visible = false;
        Activate();
    }
    void Buttons()
    {
        bool busy = running != null || gatewayWork != null || closing;
        bool selected = profiles.SelectedItem is Profile;
        profiles.Enabled = !busy;
        add.Enabled = !busy && writable;
        edit.Enabled = delete.Enabled = start.Enabled = selected && !busy;
        gateway.Enabled = selected && gatewayWork == null && !closing;
        stop.Enabled = running != null && !closing;
        export.Enabled = test.Enabled = copy.Enabled = readyPort.HasValue && !closing;
        internet.Enabled = readyPort.HasValue && !closing && !checkingInternet &&
            profiles.SelectedItem is Profile { ProtectedVpnConfig.Length: > 0 };
        RefreshShell();
    }
    void RefreshProfiles(Guid? selected)
    {
        profiles.Items.Clear();
        foreach (var profile in saved) profiles.Items.Add(profile);
        int index = saved.FindIndex(p => p.Id == selected);
        profiles.SelectedIndex = index >= 0 ? index : saved.Count == 0 ? -1 : 0;
        Buttons();
    }
    Profile? EditProfile(Profile? existing)
    {
        Profile? result = null;
        TryUi(() =>
        {
            if (running != null) return;
            using var dialog = new ProfileWindow(existing);
            if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Result is not { } p) return;
            SaveProfile(p);
            result = p;
        });
        return result;
    }
    void SaveProfile(Profile p)
    {
        var next = saved.ToList();
        int index = next.FindIndex(i => i.Id == p.Id);
        if (index < 0) next.Add(p); else next[index] = p;
        if (p.AutoConnect) next = next.Select(item => item.Id == p.Id ? item : item with { AutoConnect = false, StartWithWindows = false }).ToList();
        bool wantedStartup = next.Any(item => item.StartWithWindows);
        bool startupChanged = wantedStartup != saved.Any(item => item.StartWithWindows);
        store.Save(next, startupChanged ? () => StartupRegistration.Set(wantedStartup) : null);
        saved = next;
        RefreshProfiles(p.Id);
    }
    async Task ConfigureGateway()
    {
        if (gatewayWork != null || profiles.SelectedItem is not Profile selected) return;
        using var dialog = new GatewayWindow(selected);
        if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Result is not { } options) return;
        bool reconnect = running != null;
        await StopAsync();
        using var cancel = new CancellationTokenSource(TimeSpan.FromMinutes(6));
        gatewayWork = cancel; Buttons();
        try
        {
            var result = await GatewaySetup.Run(selected, options,
                (profile, ct) => OnUi(() => { SaveProfile(profile); return true; }, ct),
                text => { status.Text = text; Append(text); }, cancel.Token);
            hint.Text = "Постоянный шлюз проверен и сохранён. Службы запускаются вместе с VPS.";
            status.Text = "Шлюз настроен";
            reconnect = true;
        }
        catch (UserFault e) { status.Text = "Настройка не завершена"; hint.Text = e.Message; Append(e.Message); }
        catch (OperationCanceledException)
        {
            string stage = status.Text;
            status.Text = cancel.IsCancellationRequested ? "Время настройки истекло или настройка отменена" : "Сервис не ответил вовремя";
            hint.Text = "Этап: " + stage + ". Прежний адрес сохранён; повторите настройку.";
            Append(hint.Text);
        }
        catch (Exception e) when (e is IOException or System.Net.Http.HttpRequestException or System.Text.Json.JsonException or System.Net.Sockets.SocketException)
        { status.Text = "Не удалось настроить шлюз"; hint.Text = "Проверьте доступ к Cloudflare и VPS. Прежнее подключение сохранено."; }
        finally { gatewayWork = null; if (!IsDisposed) Buttons(); }
        if (reconnect && !IsDisposed && !closing && saved.FirstOrDefault(p => p.Id == selected.Id) is { } current)
            await StartAsync(current);
    }
    void Remove() => TryUi(() =>
    {
        if (running != null || profiles.SelectedItem is not Profile p) return;
        var question = p.VpnSetup == VpnSetup.Create && (p.ProtectedVpnConfig.Length != 0 || p.ProtectedClientKey.Length != 0)
            ? "Удалить профиль с этого компьютера? Созданный клиент останется на VPS."
            : "Удалить сохранённый профиль и его данные SSH?";
        if (MessageBox.Show(this, question, Text, MessageBoxButtons.OKCancel,
            MessageBoxIcon.Question) != DialogResult.OK) return;
        var next = saved.Where(i => i.Id != p.Id).ToList();
        if (p.StartWithWindows) StartupRegistration.Set(false);
        store.Save(next);
        saved = next;
        RefreshProfiles(null);
    });
    async Task StartAsync(Profile p)
    {
        if (running != null || closing) return;
        if (p.UseWarpCore && !IsAdministrator())
        {
            try
            {
                Process.Start(new ProcessStartInfo(Environment.ProcessPath!) {
                    UseShellExecute = true, Verb = "runas",
                    Arguments = "--connect-profile " + p.Id + " " + Environment.ProcessId,
                    WorkingDirectory = AppContext.BaseDirectory
                });
                allowClose = true; Close();
            }
            catch (System.ComponentModel.Win32Exception)
            {
                status.Text = "Нужны права Windows";
                hint.Text = "Встроенному подключению нужны права администратора. Нажмите «Подключить» и подтвердите запрос Windows.";
            }
            return;
        }
        diagnostics.Clear();
        var cancel = new CancellationTokenSource();
        running = cancel;
        var own = ++generation;
        status.Text = "Запуск…";
        hint.Text = "Ищем доступный путь к серверу.";
        warpInstall.Visible = false;
        readyPort = null;
        vpnConfirmed = internetConfirmed = false;
        Buttons();
        try
        {
            if (p.UseWarpCore && !WarpCore.Registered)
            {
                var confirm = MessageBox.Show(this,
                    "Создать отдельное бесплатное устройство WARP и принять условия Cloudflare?\n\n" +
                    "https://www.cloudflare.com/application/terms/",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                if (confirm != DialogResult.Yes) { status.Text = "Регистрация отменена"; return; }
                status.Text = "Регистрируем ядро WARP…";
                await WarpCore.Register(cancel.Token);
            }
            var interaction = new SetupInteraction(
                (profile, pin, ct) => OnUi(() => ConfirmHost(profile, pin), ct),
                (options, ct) => OnUi(() => PickVpn(options), ct),
                (profile, ct) => OnUi(() => { SaveProfile(profile); return true; }, ct));
            bool openedClient = false;
            var supervisor = new Supervisor(directory, u =>
            {
                try { BeginInvoke(new Action(() =>
                {
                    if (generation != own || cancel.IsCancellationRequested) return;
                    Apply(u);
                    if (u.Ready && !openedClient && p.AmneziaServerIndex is int index)
                    {
                        openedClient = true;
                        TryUi(() => StartAmnezia(index));
                    }
                })); }
                catch (InvalidOperationException) { }
            }, interaction: interaction);
            run = Task.Run(() => supervisor.Run(p, cancel.Token));
            await run;
        }
        catch (UserFault e) { if (!cancel.IsCancellationRequested) Apply(new("Нужно действие", e.Message)); }
        catch (Exception)
        {
            if (!cancel.IsCancellationRequested) Apply(new("Не удалось запустить мост",
                "Проверьте данные профиля и повторите попытку. Если ошибка повторяется, запишите версию приложения и этап сбоя."));
        }
        finally
        {
            if (running == cancel)
            {
                running = null;
                run = null;
                readyPort = null;
                vpnConfirmed = internetConfirmed = false;
                endpoint.Text = "Локальный порт закрыт.";
                if (cancel.IsCancellationRequested) { status.Text = "Остановлено"; hint.Text = "Мост отключён."; }
                cancel.Dispose();
                Buttons();
            }
        }
    }
    static void StartAmnezia(int index)
    {
        var running = Process.GetProcessesByName("AmneziaVPN");
        try { if (running.Length != 0) return; }
        finally { foreach (var item in running) item.Dispose(); }
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AmneziaVPN", "AmneziaVPN.exe");
        if (!File.Exists(path)) throw new UserFault("Не найдена AmneziaVPN. Установите клиент и импортируйте профиль один раз.");
        var info = new ProcessStartInfo(path) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(path)! };
        info.ArgumentList.Add("--connect"); info.ArgumentList.Add(index.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var child = Process.Start(info);
    }
    async Task StopAsync()
    {
        var task = run;
        if (task == null) return;
        status.Text = "Останавливаем…";
        running?.Cancel();
        stop.Enabled = false;
        readyPort = null;
        export.Enabled = test.Enabled = internet.Enabled = copy.Enabled = false;
        try { await task; } catch (Exception) { }
    }
    async void HandleClosing(object? sender, FormClosingEventArgs e)
    {
        if (allowClose || running == null) { tray.Visible = false; tray.Dispose(); return; }
        e.Cancel = true;
        if (closing) return;
        closing = true;
        Buttons();
        await StopAsync();
        allowClose = true;
        Close();
    }
    void Apply(LinkUpdate u)
    {
        status.Text = u.Status == "AmneziaWG: рукопожатие и UDP" ? "VPN отвечает" : u.Ready ? "Сервер готов" : u.Status;
        readyPort = u.Ready ? u.Port : null;
        if (!u.Ready) vpnConfirmed = internetConfirmed = false;
        else if (u.Status == "AmneziaWG: рукопожатие и UDP") vpnConfirmed = true;
        endpoint.Text = u.Port is int port ? $"Локальный UDP: 127.0.0.1:{port}" : "Локальный порт закрыт.";
        if (u.Ready)
        {
            hint.Text = u.Status == "AmneziaWG: рукопожатие и UDP"
                ? "Соединение VPN подтверждено. Нажмите «Проверить интернет», чтобы проверить выход через сервер."
                : "Теперь включите профиль в AmneziaVPN. При первом запуске сохраните его в разделе «Серверы» и импортируйте в клиент.";
            warpInstall.Visible = false;
        }
        else if (u.Status is "Нужно действие" or "Ошибка запуска" or "Не удалось запустить мост" or
                 "Не удалось использовать WARP" or "Не удалось открыть локальный UDP")
        {
            hint.Text = u.Detail;
            warpInstall.Visible = u.Detail.Contains("Установите Cloudflare WARP", StringComparison.Ordinal);
        }
        if (!string.IsNullOrEmpty(u.Detail)) Append(u.Detail);
        Buttons();
    }
    void Append(string text)
    {
        string safe = new(text.Where(c => !char.IsControl(c) || c is '\n' or '\t').ToArray());
        if (diagnostics.TextLength + safe.Length > 48000)
            diagnostics.Text = diagnostics.Text[^Math.Min(diagnostics.TextLength, 28000)..];
        diagnostics.AppendText($"[{DateTime.Now:HH:mm:ss}] {safe.Replace("\n", Environment.NewLine)}" + Environment.NewLine + Environment.NewLine);
    }
    async Task CheckInternet()
    {
        if (running == null || profiles.SelectedItem is not Profile profile) return;
        var token = running.Token;
        checkingInternet = true;
        Buttons();
        string result;
        try { result = await InternetProbe.Run(profile, token); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return; }
        catch (UserFault e) { result = e.Message; }
        catch (System.Net.NetworkInformation.NetworkInformationException) { result = "Windows не вернула параметры сетевых адаптеров."; }
        finally { checkingInternet = false; if (!IsDisposed) Buttons(); }
        if (token.IsCancellationRequested || IsDisposed) return;
        internetConfirmed = result.StartsWith("HTTPS через ", StringComparison.Ordinal) && result.Contains(" работает. Адрес выхода: ", StringComparison.Ordinal);
        if (internetConfirmed) { status.Text = "Интернет работает"; hint.Text = result; }
        RefreshShell();
        Append(result);
        MessageBox.Show(this, result, Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    void Export(bool handshakeOnly) => TryUi(() =>
    {
        if (readyPort is not int port) return;
        var profile = profiles.SelectedItem as Profile;
        string? input = null;
        if (profile == null || profile.ProtectedVpnConfig.Length == 0)
        {
            using var open = new OpenFileDialog { Title = "Выберите конфигурацию AmneziaWG", Filter = "Конфигурация AmneziaWG|*.conf" };
            if (open.ShowDialog(this) != DialogResult.OK) return;
            input = open.FileName;
        }
        string name = profile == null ? "ThingsNotFun-Link" : $"Link-{profile.Id.ToString("N")[..8]}";
        if (handshakeOnly) name += "-WARP-test";
        using var save = new SaveFileDialog { Title = handshakeOnly ? "Сохранить тестовый профиль" : "Сохранить профиль для AmneziaWG",
            Filter = "Конфигурация AmneziaWG|*.conf", DefaultExt = "conf", FileName = name + ".conf",
            OverwritePrompt = true };
        if (save.ShowDialog(this) != DialogResult.OK) return;
        if (readyPort != port) throw new UserFault("Подождите, пока мост снова будет готов, и сохраните профиль ещё раз.");
        var outerEndpoint = profile?.UseWarpCore == true ? WarpCore.ReadEndpoint() : null;
        if (input != null) VpnConfig.Export(input, save.FileName, port, handshakeOnly, outerEndpoint);
        else VpnConfig.ExportText(Setup.Open(profile!, profile!.ProtectedVpnConfig, "vpn-config"), save.FileName, port, handshakeOnly, outerEndpoint);
        string instructions = handshakeOnly
            ? "Импортируйте файл в AmneziaWG, активируйте только тестовый профиль и нажмите «Проверить интернет». Через VPN пойдёт только трафик к 1.1.1.1."
            : "Импортируйте сохранённый файл в AmneziaVPN и нажмите «Подключиться».";
        var openVpn = MessageBox.Show(this, instructions + " В файле есть приватный ключ VPN.\n\nОткрыть VPN-клиент?",
            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information);
        if (openVpn == DialogResult.Yes)
        {
            string app = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AmneziaVPN", "AmneziaVPN.exe");
            if (!File.Exists(app)) app = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AmneziaWG", "amneziawg.exe");
            if (File.Exists(app)) Process.Start(new ProcessStartInfo(app) { UseShellExecute = true });
            else OpenUrl("https://docs.amnezia.org/documentation/instructions/use-amneziawg-app/");
        }
    });

    static void OpenUrl(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

    async Task<T> OnUi<T>(Func<T> action, CancellationToken ct)
    {
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancel = ct.Register(() => completion.TrySetCanceled(ct));
        BeginInvoke(new Action(() =>
        {
            if (ct.IsCancellationRequested) return;
            try { completion.TrySetResult(action()); }
            catch (Exception ex) { completion.TrySetException(ex); }
        }));
        return await completion.Task;
    }

    bool ConfirmHost(Profile profile, string pin)
    {
        return MessageBox.Show(this,
            $"Первый вход на {profile.Host}:{profile.SshPort}.\n\n{pin}\n\nСверьте отпечаток ED25519 в панели хостера. Он совпадает?",
            "Подтверждение ключа сервера", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2) == DialogResult.Yes;
    }

    VpnOption? PickVpn(IReadOnlyList<VpnOption> options)
    {
        using var dialog = new Form { Text = "Выберите AmneziaWG", StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog, ClientSize = new Size(500, 145), ShowInTaskbar = false,
            MinimizeBox = false, MaximizeBox = false, Font = Font };
        var list = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top,
            AccessibleName = "AmneziaWG на VPS" };
        list.Items.AddRange(options.Cast<object>().ToArray());
        list.SelectedIndex = 0;
        var confirm = Button("Настроить");
        confirm.DialogResult = DialogResult.OK;
        var cancel = Button("Отмена");
        cancel.DialogResult = DialogResult.Cancel;
        var layout = new Panel { Dock = DockStyle.Fill, Padding = new Padding(15) };
        layout.Controls.Add(Row(confirm, cancel));
        layout.Controls.Add(list);
        var prompt = new Label { Text = "На VPS несколько VPN. Выберите нужный.", AutoSize = true, Dock = DockStyle.Top };
        layout.Controls.Add(prompt);
        dialog.Controls.Add(layout);
        Theme.Apply(dialog);
        dialog.AcceptButton = confirm;
        dialog.CancelButton = cancel;
        return dialog.ShowDialog(this) == DialogResult.OK ? list.SelectedItem as VpnOption : null;
    }
    void TryUi(Action action)
    {
        try { action(); }
        catch (UserFault e) { MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Information); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Runtime.InteropServices.ExternalException)
        { MessageBox.Show(this, "Не удалось прочитать, записать или скопировать данные. Проверьте права и выберите новое имя файла.", Text); }
    }
}

