using System.Diagnostics;

namespace NetUlta;

sealed partial class MainWindow
{
    readonly ToolTip tips = Theme.Tips();
    readonly ConnectButton power = new();
    readonly Label serverStage = new(), vpnStage = new(), internetStage = new();
    readonly Label profileSummary = new(), routeSummary = new();
    readonly Panel pages = new() { Dock = DockStyle.Fill };
    readonly List<(Button Nav, Control Page)> navigation = new();
    bool vpnConfirmed, internetConfirmed;
    string activeDataPath = "";

    void BuildShell()
    {
        Text = "VPSLink";
        Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? SystemIcons.Application;
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1000, 710);
        MinimumSize = new Size(920, 690);
        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 194));
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var sidebar = new Panel { Dock = DockStyle.Fill, Padding = new Padding(16, 26, 16, 18) };
        var brand = new Label { Text = "VPSLINK", Font = new Font("Segoe UI Semibold", 23), Dock = DockStyle.Top, Height = 48 };
        var brandDetail = new Label { Text = "Свой сервер", Dock = DockStyle.Top, Height = 34, ForeColor = Theme.Muted };
        var nav = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(0, 30, 0, 0) };
        var version = new Label { Text = "VPSLink\nВерсия " + Application.ProductVersion.Split('+')[0], Dock = DockStyle.Bottom, Height = 48, ForeColor = Theme.Muted };
        sidebar.Controls.Add(nav); sidebar.Controls.Add(version); sidebar.Controls.Add(brandDetail); sidebar.Controls.Add(brand);

        var main = new Panel { Dock = DockStyle.Fill, Padding = new Padding(32, 24, 32, 20) };
        var header = new TableLayoutPanel { Dock = DockStyle.Top, Height = 65, ColumnCount = 2, RowCount = 2 };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Controls.Add(new Label { Text = "ВАШ СЕРВЕР", AutoSize = true, Font = new Font("Segoe UI Semibold", 8), ForeColor = Theme.Muted }, 0, 0);
        profiles.Dock = DockStyle.Fill; profiles.Margin = new Padding(0, 3, 16, 0);
        header.Controls.Add(profiles, 0, 1);
        var quickAdd = Button("+  Добавить"); quickAdd.Click += async (_, _) => await AddServer();
        add.EnabledChanged += (_, _) => quickAdd.Enabled = add.Enabled;
        header.Controls.Add(quickAdd, 1, 1);
        tips.SetToolTip(profiles, "Выберите свой VPS. Каждый сервер хранит собственные настройки подключения и VPN-профиль.");
        main.Controls.Add(pages); main.Controls.Add(header);
        shell.Controls.Add(sidebar, 0, 0); shell.Controls.Add(main, 1, 0); Controls.Add(shell);

        var home = Page();
        var center = new TableLayoutPanel { Dock = DockStyle.Top, Height = 490, ColumnCount = 1, RowCount = 5 };
        center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        center.RowStyles.Add(new RowStyle(SizeType.Absolute, 254));
        center.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        center.RowStyles.Add(new RowStyle(SizeType.Absolute, 65));
        center.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));
        center.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        power.Anchor = AnchorStyles.None;
        power.Click += async (_, _) =>
        {
            if (running != null) await StopAsync();
            else if (profiles.SelectedItem is Profile p) await StartAsync(p);
            else await AddServer();
        };
        tips.SetToolTip(power, "Link открывает путь к вашему серверу. После готовности включите сохранённый профиль в AmneziaVPN. Нажмите ещё раз, чтобы остановить Link.");
        status.Font = new Font("Segoe UI Semibold", 21); status.AutoSize = false; status.Dock = DockStyle.Fill; status.TextAlign = ContentAlignment.MiddleCenter;
        hint.AutoSize = false; hint.Dock = DockStyle.Fill; hint.TextAlign = ContentAlignment.TopCenter; hint.Padding = new Padding(22, 7, 22, 0);
        var stages = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Padding = new Padding(8, 7, 8, 7) };
        foreach (var label in new[] { serverStage, vpnStage, internetStage })
        {
            stages.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            label.AutoSize = false; label.Dock = DockStyle.Fill; label.TextAlign = ContentAlignment.MiddleCenter; label.Margin = new Padding(5);
            stages.Controls.Add(label);
        }
        tips.SetToolTip(serverStage, "Связь с VPS. Готово означает, что Link создал мост до сервера. Это ещё не проверка VPN.");
        tips.SetToolTip(vpnStage, "Ответ VPN. Подтверждается после рукопожатия AmneziaVPN и обмена данными с сервером.");
        tips.SetToolTip(internetStage, "Выход в интернет. Нажмите «Проверить интернет», чтобы выполнить запрос через включённый VPN и узнать внешний IP.");
        var verify = Button("Проверить интернет"); verify.Anchor = AnchorStyles.None;
        verify.Click += async (_, _) => await CheckInternet();
        internet.EnabledChanged += (_, _) => verify.Enabled = internet.Enabled;
        verify.Enabled = false;
        center.Controls.Add(power, 0, 0); center.Controls.Add(status, 0, 1); center.Controls.Add(hint, 0, 2); center.Controls.Add(stages, 0, 3); center.Controls.Add(verify, 0, 4);
        home.Controls.Add(center);

        var servers = Page();
        var serverContent = Stack();
        serverContent.Controls.Add(Heading("Мои серверы", "Добавьте VPS один раз. Link сохранит данные и подготовит профиль для AmneziaVPN."));
        profileSummary.AutoSize = true; profileSummary.MaximumSize = new Size(630, 0); profileSummary.Margin = new Padding(0, 20, 0, 20);
        serverContent.Controls.Add(profileSummary); serverContent.Controls.Add(Row(add, edit, delete));
        serverContent.Controls.Add(Heading("Профиль для AmneziaVPN", "После подключения сохраните файл и один раз импортируйте его в AmneziaVPN. При следующих запусках используйте тот же профиль."));
        serverContent.Controls.Add(Row(export));
        serverContent.Controls.Add(HelpText("При следующем запуске нажмите «Подключить» в Link, дождитесь готовности моста и включите сохранённый профиль в AmneziaVPN. Для отключения сначала выключите VPN, затем Link."));
        servers.Controls.Add(serverContent);

        var connection = Page();
        var connectionContent = Stack();
        connectionContent.Controls.Add(Heading("Подключение", "Здесь выбирается путь к VPS, если обычное соединение недоступно."));
        routeSummary.AutoSize = true; routeSummary.MaximumSize = new Size(630, 0); routeSummary.Margin = new Padding(0, 16, 0, 16);
        connectionContent.Controls.Add(routeSummary);
        AddDataRouteControls(connectionContent);
        connectionContent.Controls.Add(Row(start, stop));
        connectionContent.Controls.Add(Heading("Постоянный адрес", "Настройте собственный адрес шлюза в Cloudflare. Он сохранится после перезапуска VPS."));
        connectionContent.Controls.Add(Row(gateway));
        connectionContent.Controls.Add(HelpText("Для первой настройки нужны активный домен Cloudflare, API-токен и уже работающий путь входа на VPS. Токен запрашивается только во время настройки."));
        connectionContent.Controls.Add(warpInstall);
        connection.Controls.Add(connectionContent);

        var diagnosticPage = Page();
        var diagLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        diagLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 92)); diagLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        diagLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54)); diagLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        diagLayout.Controls.Add(Heading("Диагностика", "Если VPN подключился, но сайты не открываются, проверьте интернет и посмотрите, на каком этапе остановилось подключение."), 0, 0);
        endpoint.Visible = true; endpoint.Dock = DockStyle.Fill; diagnostics.Visible = true; diagnostics.Font = new Font("Consolas", 9);
        diagLayout.Controls.Add(endpoint, 0, 1); diagLayout.Controls.Add(Row(internet, copy, test), 0, 2); diagLayout.Controls.Add(diagnostics, 0, 3);
        diagnosticPage.Controls.Add(diagLayout);

        var guide = new DarkTabControl { Dock = DockStyle.Fill };
        var ownerGuide = new TabPage("Свой сервер") { AutoScroll = true, ToolTipText = "Настройка вашего VPS и первый запуск VPN." };
        var invitationGuide = new TabPage("По приглашению") { AutoScroll = true, ToolTipText = "Подключение, если вам прислали файл .vpslink и пароль." };
        guide.TabPages.AddRange(new[] { ownerGuide, invitationGuide });
        Theme.Tabs(guide);
        var guideContent = Stack();
        guideContent.Controls.Add(Heading("Как пользоваться Link", "Сначала подготовьте VPS с AmneziaWG, данные SSH и AmneziaVPN на компьютере. Для постоянного шлюза также нужны домен и аккаунт Cloudflare. Где всё это взять — в полной инструкции для браузера."));
        guideContent.Controls.Add(Heading("01   Добавьте свой сервер", "Введите адрес VPS и данные SSH. При первом входе сверьте отпечаток ключа с панелью хостера."));
        guideContent.Controls.Add(Heading("02   Подключите Link", "Дождитесь готовности сервера. При необходимости настройте постоянный шлюз в разделе «Подключение»."));
        guideContent.Controls.Add(Heading("03   Включите AmneziaVPN", "Сохраните VPN-профиль, импортируйте его один раз и подключитесь. Затем проверьте интернет на главном экране."));
        var openGuide = Button("Открыть полную инструкцию  ↗");
        openGuide.Click += (_, _) => TryUi(() => UserGuide.Open(directory));
        guideContent.Controls.Add(Row(openGuide));
        guideContent.Controls.Add(HelpText("В инструкции: что нужно заранее и где получить VPS, домен и приложения; первое подключение, постоянный шлюз, автозапуск и решение проблем. Справка работает без интернета, внешние ссылки требуют подключения."));
        ownerGuide.Controls.Add(guideContent);

        var invitationContent = Stack();
        invitationContent.Controls.Add(Heading("Если вам прислали приглашение", "Подготовьте файл .vpslink, пароль к нему и AmneziaVPN с поддержкой версии AmneziaWG на сервере."));
        invitationContent.Controls.Add(Heading("Импортируйте приглашение", "В разделе «Приглашения» нажмите «Импортировать приглашение…», выберите файл и введите пароль. Сверьте адрес и отпечаток SSH с владельцем перед подтверждением."));
        invitationContent.Controls.Add(Heading("Подключите VPSLink", "Выберите добавленный сервер и нажмите «Подключить». Если VPSLink предложит зарегистрировать ваше устройство WARP, следуйте подсказкам. Дождитесь готовности моста."));
        invitationContent.Controls.Add(Heading("Включите VPN в AmneziaVPN", "Откройте «Серверы» и сохраните VPN-профиль. Импортируйте .conf в AmneziaVPN и подключитесь. В следующий раз включайте мост VPSLink, затем этот же VPN-профиль."));
        var openInvitationGuide = Button("Открыть инструкцию по приглашению  ↗");
        openInvitationGuide.Click += (_, _) => TryUi(() => UserGuide.Open(directory, invitation: true));
        invitationContent.Controls.Add(Row(openInvitationGuide));
        invitationGuide.Controls.Add(invitationContent);

        AddPage(nav, "Главная", home, "Главный экран подключения. Показывает связь с сервером, VPN и интернетом. Открывайте для подключения и проверки состояния.");
        AddPage(nav, "Серверы", servers, "Ваши VPS и профили VPN. Здесь добавляют сервер, меняют его данные и сохраняют файл для AmneziaVPN. Нужно при первом запуске или смене сервера.");
        AddPage(nav, "Подключение", connection, "Путь к серверу и постоянный шлюз. Нужен, если прямое соединение заблокировано или требуется постоянный адрес после перезапуска VPS.");
        AddPage(nav, "Стратегии", BuildStrategiesPage(), "Варианты winws для встроенного WARP. Здесь можно обновить каталог zapret, проверить путь до VPS и выбрать рабочую стратегию без редактирования конфигурации.");
        AddPage(nav, "Диагностика", diagnosticPage, "Проверка интернета и журнал подключения. Откройте, если VPN не подключается, сайты не открываются или нужно понять причину ошибки.");
        AddPage(nav, "Обновления", BuildUpdatesPage(), "Новые версии Link из GitHub. Проверка и загрузка не прерывают VPN; установка выполняется по вашему нажатию с сохранением профилей.");
        AddPage(nav, "Приглашения", BuildSharingPage(), "Передача доступа к вашему VPS другим людям. Владелец создаёт отдельный VPN-профиль; получатель импортирует защищённый паролем файл без административных данных владельца.");
        AddPage(nav, "Напрямую", BuildDirectPage(), "Steam, игры и выбранные приложения идут к провайдеру, остальные сохраняют маршрут через VPN. Нужно, если отдельным приложениям требуется прямой выход.");
        AddPage(nav, "Инструкция", guide, "Выберите инструкцию для своего VPS или подключитесь по приглашению. Полную версию можно открыть в браузере.");
        Theme.Apply(this);
        sidebar.BackColor = nav.BackColor = brand.BackColor = brandDetail.BackColor = version.BackColor = Theme.Sidebar;
        brand.ForeColor = Theme.Accent; brandDetail.ForeColor = version.ForeColor = Theme.Muted;
        hint.ForeColor = Theme.Muted;
        foreach (var stage in new[] { serverStage, vpnStage, internetStage }) stage.BackColor = Theme.Surface;
        diagnostics.BackColor = Theme.Sidebar;
        SelectPage(0);
        FormClosed += (_, _) => tips.Dispose();
        warpInstall.LinkClicked += (_, _) => TryUi(() => OpenUrl(WarpClient.InstallUrl));
        tips.SetToolTip(export, "Создаёт файл для импорта в AmneziaVPN. Файл содержит приватный ключ — не пересылайте его вместе с диагностикой.");
        tips.SetToolTip(gateway, "Создаёт постоянный HTTPS-вход к VPS через ваш домен Cloudflare. Используйте, если временный адрес меняется после перезапуска.");
        tips.SetToolTip(test, "Дополнительный профиль только для проверки 1.1.1.1. Нужен при поиске конфликтов маршрутов; для обычной работы используйте основной VPN-профиль.");
    }
    static Panel Page() => new() { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(0, 18, 0, 0) };
    static FlowLayoutPanel Stack() => new() { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(0, 5, 8, 8) };
    static Control Heading(string title, string description)
    {
        var box = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Width = 640, Margin = new Padding(0, 10, 0, 16) };
        box.Controls.Add(new Label { Text = title, Font = new Font("Segoe UI Semibold", 17), AutoSize = true, MaximumSize = new Size(630, 0), Margin = new Padding(0, 0, 0, 10) });
        box.Controls.Add(HelpText(description)); return box;
    }
    static Label HelpText(string text) => new() { Text = text, AutoSize = true, MaximumSize = new Size(620, 0), ForeColor = Theme.Muted, Margin = new Padding(0, 5, 0, 14) };
    void AddPage(FlowLayoutPanel nav, string title, Control page, string explanation)
    {
        var button = new Button { Text = title, Width = 162, Height = 42, TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(0, 0, 0, 5), AccessibleDescription = explanation };
        int index = navigation.Count;
        button.Click += (_, _) => SelectPage(index);
        tips.SetToolTip(button, explanation);
        navigation.Add((button, page)); nav.Controls.Add(button); pages.Controls.Add(page);
    }
    internal void SelectPage(int index)
    {
        for (int i = 0; i < navigation.Count; i++)
        {
            var (button, page) = navigation[i]; page.Visible = i == index;
            button.BackColor = i == index ? Theme.Surface : Theme.Sidebar;
            button.ForeColor = i == index ? Theme.Accent : Theme.Text;
            button.FlatAppearance.BorderSize = 0;
        }
    }
    void RefreshShell()
    {
        RefreshDataRoute();
        bool busy = running != null;
        power.Enabled = !closing && gatewayWork == null && strategyWork == null && writable;
        power.Active = readyPort.HasValue; power.Waiting = busy && !readyPort.HasValue;
        power.Text = busy ? "Отключить" : profiles.SelectedItem is Profile ? "Подключить" : "Добавить сервер";
        power.AccessibleName = power.Text; power.Invalidate();
        serverStage.Text = readyPort.HasValue ? "●  Сервер доступен" : busy ? "◌  Поиск сервера" : "○  Сервер";
        vpnStage.Text = vpnConfirmed ? "●  VPN отвечает" : "○  VPN не проверен";
        internetStage.Text = internetConfirmed ? "●  Интернет проверен" : "○  Интернет не проверен";
        serverStage.ForeColor = readyPort.HasValue ? Theme.Success : Theme.Muted;
        vpnStage.ForeColor = vpnConfirmed ? Theme.Success : Theme.Muted;
        internetStage.ForeColor = internetConfirmed ? Theme.Success : Theme.Muted;
        if (profiles.SelectedItem is Profile p)
        {
            profileSummary.Text = p.Name + "\n" + p.Host + "\n\n" + (p.ProtectedVpnConfig.Length > 0 ? "VPN-профиль уже создан. Можно сохранить его для AmneziaVPN." : "VPN-профиль будет подготовлен при подключении.");
            routeSummary.Text = (p.DataRoute switch
                {
                    DataRoute.Automatic => "Авто · прямой QUIC с резервом WARP + HTTPS",
                    DataRoute.DirectQuic => "Только прямой QUIC DATAGRAM",
                    DataRoute.WarpHttps => "Только WARP + HTTPS",
                    _ => p.UseWarpCore ? "Встроенное подключение WARP" : "Путь из настроек сервера",
                }) +
                (readyPort.HasValue && activeDataPath.Length != 0 ? "\nСейчас: " + activeDataPath : "") +
                (p.GatewayHostname.Length > 0 ? "\nПостоянный адрес: " + p.GatewayHostname : p.HttpsRelay.Length > 0 ? "\nИспользуется сохранённый HTTPS-шлюз" : "\nПостоянный шлюз ещё не настроен");
        }
        else { profileSummary.Text = "Серверов пока нет. Нажмите «Добавить сервер», чтобы начать."; routeSummary.Text = "Сначала добавьте свой сервер в разделе «Серверы»."; }
    }
}
