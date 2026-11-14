using System.Security.Cryptography;
using System.Text;

namespace NetUlta;

sealed class ProfileWindow : Form
{
    readonly Profile original;
    public Profile? Result { get; private set; }
    readonly TextBox name = Input(), host = Input(), user = Input(), fingerprint = Input(),
        secret = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true }, key = Input(),
        proxyHost = Input(), peer = Input(), source = Input(), remoteIp = Input(), httpsRelay = Input(),
        relayToken = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true };
    readonly NumericUpDown sshPort = Port(1), proxyPort = Port(1), remotePort = Port(0), localPort = Port(0);
    readonly ComboBox auth = Choice(), proxy = Choice(), adapter = Choice(), mode = Choice();
    readonly CheckBox startWarp = new() { Text = "Подключать Cloudflare WARP при необходимости", AutoSize = true };
    readonly CheckBox useWarpCore = new() { Text = "Подключаться через встроенное ядро WARP", AutoSize = true };
    readonly CheckBox autoConnect = new() { Text = "Подключать этот сервер при запуске Link", AutoSize = true };
    readonly CheckBox startWindows = new() { Text = "Запускать Link при входе в Windows", AutoSize = true };
    readonly CheckBox startAmnezia = new() { Text = "Запускать AmneziaVPN после готовности моста", AutoSize = true };
    readonly NumericUpDown amneziaIndex = new() { Minimum = 1, Maximum = 1000, Width = 130 };
    readonly Button chooseZapret = new() { Text = "Выбрать winws.exe…", AutoSize = true };
    string zapretPath = "";
    readonly Button chooseConfig = new() { Text = "Выбрать файл .conf…", AutoSize = true };
    readonly Button save = new() { Text = "Сохранить", AutoSize = true, MinimumSize = new Size(120, 34) };
    string? configPath;
    CancellationTokenSource? processing;
    readonly CheckBox system = new() { Text = "Разрешить системный маршрут", AutoSize = true };
    readonly CheckBox warp = new() { Text = "Пробовать активный адаптер Cloudflare WARP", AutoSize = true };
    static TextBox Input() => new() { Dock = DockStyle.Fill };
    static ComboBox Choice() => new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    static NumericUpDown Port(int min) => new() { Minimum = min, Maximum = 65535, Width = 130 };
    static TableLayoutPanel Grid()
    {
        var table = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Top, ColumnCount = 2, Padding = new Padding(13, 10, 13, 8) };
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        return table;
    }
    static void Row(TableLayoutPanel table, string caption, Control control)
    {
        int row = table.RowCount++;
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var label = new Label { Text = caption, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(2, 6, 5, 6) };
        control.AccessibleName = caption;
        table.Controls.Add(label, 0, row);
        table.Controls.Add(control, 1, row);
    }
    static void Note(TableLayoutPanel table, string text)
    {
        int row = table.RowCount++;
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var label = new Label { Text = text, AutoSize = true, MaximumSize = new Size(560, 0), ForeColor = SystemColors.GrayText,
            Margin = new Padding(3, 11, 3, 5) };
        table.Controls.Add(label, 0, row);
        table.SetColumnSpan(label, 2);
    }
    public ProfileWindow(Profile? value)
    {
        original = value ?? new Profile { VpnSetup = VpnSetup.Create, StartWarp = true, UseWarpCore = WarpCore.Installed };
        Text = value == null ? "Подключение к серверу" : "Изменить сервер";
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(740, 610);
        MinimumSize = new Size(700, 540);
        ShowInTaskbar = false;
        MinimizeBox = MaximizeBox = false;
        var tabs = new DarkTabControl { Dock = DockStyle.Fill };
        var basic = new TabPage("Сервер") { AutoScroll = true };
        var connection = new TabPage("Дополнительные параметры") { AutoScroll = true };
        var transport = new TabPage("Путь до VPS") { AutoScroll = true };
        var vpn = new TabPage("VPN и UDP") { AutoScroll = true };
        basic.ToolTipText = "Данные вашего VPS и способ создания VPN-профиля. Заполните при первом подключении или смене сервера.";
        connection.ToolTipText = "Название сервера, ключ SSH и необязательный автозапуск. Для обычного подключения менять эти настройки не нужно.";
        transport.ToolTipText = "Путь к заблокированному VPS: WARP, HTTPS-шлюз или свой прокси. Меняйте, если обычное подключение недоступно.";
        vpn.ToolTipText = "Технические параметры VPN и локального моста. Обычно определяются автоматически; нужны при нескольких VPN на сервере или для диагностики.";
        tabs.TabPages.Add(basic);
        var main = Grid(); var advanced = Grid(); var route = Grid(); var tunnel = Grid();
        basic.Controls.Add(main); connection.Controls.Add(advanced); transport.Controls.Add(route); vpn.Controls.Add(tunnel);

        name.Text = original.Name; host.Text = original.Host; sshPort.Value = original.SshPort;
        user.Text = original.User; fingerprint.Text = original.Fingerprint;
        auth.Items.AddRange(new object[] { "Пароль SSH", "Приватный SSH-ключ" }); auth.SelectedIndex = (int)original.Auth;
        host.PlaceholderText = "Адрес из панели VPS";
        user.PlaceholderText = "Например, root или ubuntu";
        Row(main, "Адрес сервера", host);
        Row(main, "Логин", user);
        Row(advanced, "Название профиля", name);
        Row(advanced, "Порт SSH", sshPort);
        Row(advanced, "Отпечаток SSH ED25519", fingerprint);
        autoConnect.Checked = original.AutoConnect;
        Row(advanced, "Повторное подключение", autoConnect);
        startWindows.Checked = original.StartWithWindows;
        startAmnezia.Checked = original.AmneziaServerIndex.HasValue;
        amneziaIndex.Value = (original.AmneziaServerIndex ?? 0) + 1;
        Row(advanced, "Автозапуск Windows", startWindows);
        Row(advanced, "VPN-клиент", startAmnezia);
        Row(advanced, "Номер сервера в AmneziaVPN", amneziaIndex);
        startWindows.CheckedChanged += (_, _) => { if (startWindows.Checked) autoConnect.Checked = true; };
        Note(advanced, "Номер сервера считается с 1 по списку AmneziaVPN. Для запуска без ручных действий отключите отдельный автозапуск AmneziaVPN: Link откроет клиент после готовности моста. Уже запущенный клиент Link не закрывает.");
        Row(main, "Способ входа", auth);
        Row(main, "Пароль / фраза ключа", secret);
        var browse = new Button { Text = "Обзор…", AutoSize = true, Dock = DockStyle.Right };
        var keyWrap = new Panel { Height = 34, Dock = DockStyle.Fill };
        keyWrap.Controls.Add(key);
        keyWrap.Controls.Add(browse);
        key.AccessibleName = "Файл приватного SSH-ключа";
        browse.Click += (_, _) =>
        {
            using var open = new OpenFileDialog { Title = "Файл приватного SSH-ключа", Filter = "Все файлы|*.*" };
            if (open.ShowDialog(this) == DialogResult.OK) key.Text = open.FileName;
        };
        Row(main, "Файл ключа", keyWrap);
        Note(advanced, "При первом подключении приложение покажет отпечаток. Сверьте его с данными в панели хостера.");
        void AuthChanged()
        {
            bool usingKey = auth.SelectedIndex == 1;
            keyWrap.Visible = usingKey;
            var label = main.GetControlFromPosition(0, main.GetRow(keyWrap));
            if (label != null) label.Visible = usingKey;
        }
        auth.SelectedIndexChanged += (_, _) => AuthChanged();
        AuthChanged();
        mode.Items.AddRange(new object[] { "Ручные параметры", "Создать профиль на VPS", "Импортировать файл .conf" });
        mode.SelectedIndex = (int)original.VpnSetup;
        Row(main, "Профиль AmneziaWG", mode);
        Row(main, "Файл VPN", chooseConfig);
        if (original.VpnSetup == VpnSetup.Import && original.ProtectedVpnConfig.Length != 0)
            chooseConfig.Text = "Выбрать другой файл…";
        chooseConfig.Click += (_, _) =>
        {
            using var open = new OpenFileDialog { Title = "Профиль AmneziaWG", Filter = "Конфигурация AmneziaWG|*.conf" };
            if (open.ShowDialog(this) != DialogResult.OK) return;
            configPath = open.FileName;
            chooseConfig.Text = Path.GetFileName(configPath);
        };
        void ModeChanged()
        {
            bool importing = mode.SelectedIndex == (int)VpnSetup.Import;
            chooseConfig.Visible = importing;
            var label = main.GetControlFromPosition(0, main.GetRow(chooseConfig));
            if (label != null) label.Visible = importing;
        }
        mode.SelectedIndexChanged += (_, _) => ModeChanged();
        ModeChanged();
        startWarp.Checked = original.StartWarp;
        useWarpCore.Checked = original.UseWarpCore;
        useWarpCore.Enabled = WarpCore.Installed || original.UseWarpCore;
        Row(main, "Путь до VPS", useWarpCore);
        Row(main, "Резервное подключение", startWarp);
        Note(main, "При автоматической настройке приложение добавит отдельного клиента на уже работающий AmneziaWG.");
        var showAdvanced = new CheckBox { Text = "Показать дополнительные настройки", AutoSize = true };
        Row(main, "", showAdvanced);
        showAdvanced.CheckedChanged += (_, _) =>
        {
            if (showAdvanced.Checked) tabs.TabPages.AddRange(new[] { connection, transport, vpn });
            else { tabs.TabPages.Remove(connection); tabs.TabPages.Remove(transport); tabs.TabPages.Remove(vpn); }
        };

        proxy.Items.AddRange(new object[] { "Не использовать", "SOCKS5", "HTTP CONNECT" });
        proxy.SelectedIndex = (int)original.Proxy;
        proxyHost.Text = original.ProxyHost; proxyPort.Value = original.ProxyPort;
        adapter.Items.Add(new InterfaceChoice("", "Не выбирать вручную"));
        foreach (var item in Model.Interfaces()) adapter.Items.Add(item);
        if (original.AdapterId.Length > 0 && !adapter.Items.Cast<InterfaceChoice>().Any(i => i.Id == original.AdapterId))
            adapter.Items.Add(new InterfaceChoice(original.AdapterId, "Сохранённый адаптер сейчас недоступен"));
        adapter.SelectedItem = adapter.Items.Cast<InterfaceChoice>().First(i => i.Id == original.AdapterId);
        system.Checked = original.UseSystemRoute;
        warp.Checked = original.AutoWarp;
        httpsRelay.Text = original.HttpsRelay;
        httpsRelay.PlaceholderText = "https://example.com/link-ssh";
        if (original.ProtectedRelayToken.Length != 0) relayToken.PlaceholderText = "Токен сохранён";
        Row(route, "HTTPS-шлюз SSH", httpsRelay); Row(route, "Токен шлюза", relayToken);
        Row(route, "Настроенный прокси", proxy); Row(route, "Адрес прокси", proxyHost); Row(route, "Порт прокси", proxyPort);
        Row(route, "Адаптер для SSH", adapter); Row(route, "Автоопределение", warp); Row(route, "Резервный путь", system);
        zapretPath = original.ZapretPath;
        if (zapretPath.Length != 0) chooseZapret.Text = Path.GetFileName(zapretPath);
        Row(route, "Zapret для ядра WARP", chooseZapret);
        chooseZapret.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog { Filter = "Zapret для Windows|winws.exe", CheckFileExists = true };
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            zapretPath = dialog.FileName;
            chooseZapret.Text = Path.GetFileName(zapretPath);
        };
        void ProxyChanged() { proxyHost.Enabled = proxyPort.Enabled = proxy.SelectedIndex > 0; }
        proxy.SelectedIndexChanged += (_, _) => ProxyChanged(); ProxyChanged();
        Note(route, "При разрешении на основной вкладке приложение может подключить установленный WARP. Для другого прокси укажите адрес вручную.");

        remoteIp.Text = original.RemoteIp; remotePort.Value = original.RemotePort; localPort.Value = original.LocalPort;
        peer.Text = original.ClientPublicKey; source.Text = original.SourceId;
        Row(tunnel, "IP назначения на VPS", remoteIp); Row(tunnel, "UDP-порт VPS (0 = авто)", remotePort);
        Row(tunnel, "Локальный порт (0 = авто)", localPort); Row(tunnel, "Открытый ключ VPN-клиента", peer);
        Row(tunnel, "Интерфейс VPN (необязательно)", source);
        Note(tunnel, "Оставьте адрес и порт пустыми или автоматическими, если на VPS один опубликованный VPN. Задайте постоянный локальный порт, чтобы повторно использовать импортированную конфигурацию после выхода из приложения.");
        Note(tunnel, "Для подтверждения handshake нужен открытый ключ именно клиента (Public key в разделе интерфейса AmneziaWG), а не ключ сервера из [Peer].");

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(9, 3, 9, 3) };
        save.Text = value == null ? "Подключить" : "Сохранить";
        var cancel = new Button { Text = "Отмена", DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(100, 32) };
        buttons.Controls.AddRange(new Control[] { cancel, save });
        Controls.Add(tabs); Controls.Add(buttons);
        Theme.Apply(this);
        foreach (var page in new[] { connection, transport, vpn }) Theme.Apply(page);
        Theme.Tabs(tabs);
        CancelButton = cancel;
        AcceptButton = save;
        save.Click += async (_, _) => await Save();
        FormClosing += (_, _) => processing?.Cancel();
    }
    async Task Save()
    {
        if (processing != null) return;
        using var cancel = new CancellationTokenSource();
        processing = cancel;
        save.Enabled = false;
        byte[]? bytes = null;
        try
        {
            var kind = (AuthKind)auth.SelectedIndex;
            string credentials = original.Auth == kind ? original.ProtectedCredential : "";
            string entered = secret.Text;
            if (entered.Contains('\n') || entered.Contains('\r') || entered.Contains('\0') || Encoding.UTF8.GetByteCount(entered) > 1000)
                throw new UserFault("В пароле не должно быть переносов строк или больше 1000 байт.");
            if (kind == AuthKind.Password && entered.Length != 0)
                credentials = ProfileStore.Protect(original.Id, new(entered, null));
            if (kind == AuthKind.Key && key.Text.Trim().Length != 0)
            {
                var info = new FileInfo(key.Text.Trim());
                if (!info.Exists || info.Length is < 30 or > 65536)
                    throw new UserFault("Выберите файл приватного ключа OpenSSH (до 64 КБ).");
                bytes = File.ReadAllBytes(info.FullName);
                if (!bytes.AsSpan(0, Math.Min(bytes.Length, 64)).StartsWith(Encoding.ASCII.GetBytes("-----BEGIN ")))
                    throw new UserFault("Файл не похож на приватный ключ OpenSSH/PEM.");
                credentials = ProfileStore.Protect(original.Id, new(entered, bytes));
            }
            else if (kind == AuthKind.Key && entered.Length != 0)
            {
                if (credentials.Length == 0) throw new UserFault("Выберите файл приватного ключа.");
                bytes = ProfileStore.Open(original).Key;
                if (bytes == null) throw new UserFault("Выберите файл приватного ключа.");
                credentials = ProfileStore.Protect(original.Id, new(entered, bytes));
            }
            var address = host.Text.Trim();
            var pin = fingerprint.Text.Trim();
            bool sameServer = address.Equals(original.Host, StringComparison.OrdinalIgnoreCase) &&
                (int)sshPort.Value == original.SshPort;
            if (!sameServer && pin == original.Fingerprint) pin = "";
            var selectedMode = (VpnSetup)mode.SelectedIndex;
            bool retain = selectedMode == original.VpnSetup && configPath == null && sameServer;
            string relayUrl = httpsRelay.Text.Trim(), enteredToken = relayToken.Text.Trim();
            if (enteredToken.Length != 0 && !HttpsTransport.IsToken(enteredToken))
                throw new UserFault("Токен HTTPS-шлюза должен содержать 43 символа Base64URL.");
            string protectedToken = relayUrl.Length == 0 ? "" : enteredToken.Length != 0
                ? Setup.Protect(original, enteredToken, "https-relay")
                : relayUrl.Equals(original.HttpsRelay, StringComparison.Ordinal) && sameServer
                    ? original.ProtectedRelayToken : "";
            var p = original with
            {
                Name = name.Text.Trim().Length == 0 ? address : name.Text.Trim(), Host = address, User = user.Text.Trim(), Fingerprint = pin,
                SshPort = (int)sshPort.Value, Auth = kind, ProtectedCredential = credentials,
                Proxy = (ProxyKind)proxy.SelectedIndex, ProxyHost = proxyHost.Text.Trim(), ProxyPort = (int)proxyPort.Value,
                HttpsRelay = relayUrl, ProtectedRelayToken = protectedToken,
                AutoConnect = autoConnect.Checked || startWindows.Checked,
                StartWithWindows = startWindows.Checked,
                AmneziaServerIndex = startAmnezia.Checked ? (int)amneziaIndex.Value - 1 : null,
                GatewayHostname = sameServer ? original.GatewayHostname : "",
                GatewayTunnelId = sameServer ? original.GatewayTunnelId : "",
                GatewayAccountId = sameServer ? original.GatewayAccountId : "",
                ProtectedGatewayToken = sameServer ? original.ProtectedGatewayToken : "",
                AdapterId = ((InterfaceChoice)adapter.SelectedItem!).Id, UseSystemRoute = system.Checked, AutoWarp = warp.Checked,
                StartWarp = startWarp.Checked, UseWarpCore = useWarpCore.Checked, ZapretPath = zapretPath, VpnSetup = selectedMode,
                RemoteIp = remoteIp.Text.Trim(), RemotePort = (int)remotePort.Value, LocalPort = (int)localPort.Value,
                ClientPublicKey = retain || selectedMode == VpnSetup.Manual ? peer.Text.Trim() : "",
                SourceId = retain || selectedMode == VpnSetup.Manual ? source.Text.Trim() : "",
                ServerPublicKey = retain ? original.ServerPublicKey : "",
                ConfigEndpointPort = retain ? original.ConfigEndpointPort : 0,
                ProtectedClientKey = retain ? original.ProtectedClientKey : "",
                ProtectedVpnConfig = retain ? original.ProtectedVpnConfig : ""
            };
            Model.Validate(p, allowUnpinned: true);
            if (selectedMode == VpnSetup.Import)
            {
                if (configPath != null) p = await Setup.Import(p, Setup.ReadConfig(configPath), cancel.Token);
                if (p.ProtectedVpnConfig.Length == 0) throw new UserFault("Выберите файл .conf для этого сервера.");
            }
            cancel.Token.ThrowIfCancellationRequested();
            Result = p;
            secret.Clear();
            DialogResult = DialogResult.OK;
        }
        catch (OperationCanceledException) { }
        catch (UserFault e) { MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Information); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
        { MessageBox.Show(this, "Не удалось прочитать ключ или зашифровать учётные данные средствами Windows.", Text); }
        finally
        {
            if (bytes != null) CryptographicOperations.ZeroMemory(bytes);
            processing = null;
            if (!IsDisposed) save.Enabled = true;
        }
    }
}

