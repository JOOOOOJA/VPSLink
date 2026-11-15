namespace NetUlta;

sealed partial class MainWindow
{
    readonly Label directSummary = HelpText(""), directStatus = HelpText(""), directCoreStatus = HelpText("");
    readonly Button editDirect = Button("Настроить список…"), chooseDirectCore = Button("Выбрать ZIP…"), retryDirect = Button("Повторить запуск");
    CancellationTokenSource? directWork;
    Task? directTask;
    bool directAttempted, importingDirect;

    Control BuildDirectPage()
    {
        var page = Page();
        var content = Stack();
        content.Controls.Add(Heading("Приложения напрямую", "Выбранные приложения выходят через провайдера при включённой AmneziaVPN. Правила сохраняются для выбранного сервера."));
        content.Controls.Add(directSummary);
        content.Controls.Add(Row(editDirect, retryDirect));
        content.Controls.Add(directStatus);
        content.Controls.Add(Heading("Компонент маршрутизации", "Один раз скачайте официальный архив sing-box 1.14.4 для Windows amd64 и выберите его здесь. VPSLink проверит контрольную сумму ZIP."));
        var download = Button("Открыть загрузку sing-box ↗");
        download.Click += (_, _) => TryUi(() => OpenUrl(DirectRouting.Packages));
        content.Controls.Add(Row(download, chooseDirectCore));
        content.Controls.Add(directCoreStatus);
        content.Controls.Add(HelpText("Поддерживается полный профиль IPv4. Перед подключением выключите в AmneziaVPN разделение по приложениям и сайтам, а также KillSwitch. С сохранённым списком Amnezia можно работать при выключенном разделении."));
        content.Controls.Add(HelpText("С выключенным KillSwitch приложения могут выйти в интернет при отключении VPN. VPSLink остановит свой адаптер при изменении маршрутов. После включения режима перезапустите уже открытые приложения."));
        editDirect.Click += (_, _) => TryUi(EditDirectOptions);
        chooseDirectCore.Click += async (_, _) => await ChooseDirectArchive();
        retryDirect.Click += (_, _) => { directAttempted = false; RefreshDirect(); };
        page.Controls.Add(content);
        return page;
    }

    async Task ChooseDirectArchive()
    {
        if (importingDirect || running != null) return;
        using var file = new OpenFileDialog { Filter = "Архив sing-box (*.zip)|*.zip", CheckFileExists = true };
        if (file.ShowDialog(this) != DialogResult.OK) return;
        importingDirect = true;
        Buttons();
        try
        {
            await DirectRouting.ImportArchive(file.FileName, directory);
        }
        catch (Exception e) when (e is UserFault or IOException or UnauthorizedAccessException)
        {
            if (!IsDisposed) MessageBox.Show(this, e is UserFault ? e.Message : "Не удалось сохранить архив sing-box.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { importingDirect = false; if (!IsDisposed) Buttons(); }
    }

    void EditDirectOptions()
    {
        if (profiles.SelectedItem is not Profile profile || running != null || directTask != null) return;
        var options = profile.Direct ?? new();
        using var dialog = new Form { Text = "Приложения напрямую · " + profile.Name, Font = Font, StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(650, 430), MinimumSize = new Size(600, 430), MinimizeBox = false, MaximizeBox = false };
        var panel = Stack();
        panel.Padding = new Padding(16);
        var active = new CheckBox { Text = "Включать прямой маршрут для этого сервера", Checked = options.Enabled, AutoSize = true };
        var steam = new CheckBox { Text = "Steam и игры из подключённых библиотек", Checked = options.Steam, AutoSize = true };
        var amnezia = new CheckBox { Text = "Подхватывать список исключений AmneziaVPN при подключении", Checked = options.Amnezia, AutoSize = true };
        var list = new ListBox { Width = 594, Height = 154, HorizontalScrollbar = true, SelectionMode = SelectionMode.MultiExtended,
            AccessibleName = "Пути к исполняемым файлам" };
        list.Items.AddRange((options.Executables ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries));
        var addExe = Button("Добавить .exe…");
        var removeExe = Button("Удалить выбранные");
        var save = Button("Сохранить");
        var cancel = Button("Отмена"); cancel.DialogResult = DialogResult.Cancel;
        addExe.Click += (_, _) =>
        {
            using var files = new OpenFileDialog { Filter = "Приложения Windows (*.exe)|*.exe", Multiselect = true, CheckFileExists = true };
            if (files.ShowDialog(dialog) != DialogResult.OK) return;
            foreach (string path in files.FileNames)
            {
                if (DirectRules.NormalizeExe(path) is { } exe && !list.Items.Cast<string>().Contains(exe, StringComparer.OrdinalIgnoreCase)) list.Items.Add(exe);
            }
        };
        removeExe.Click += (_, _) => { foreach (var item in list.SelectedItems.Cast<string>().ToArray()) list.Items.Remove(item); };
        save.Click += (_, _) =>
        {
            if (active.Checked && !steam.Checked && !amnezia.Checked && list.Items.Count == 0)
            {
                MessageBox.Show(dialog, "Добавьте приложение или включите один из списков.", dialog.Text);
                return;
            }
            dialog.DialogResult = DialogResult.OK;
        };
        panel.Controls.AddRange(new Control[] { active, steam, amnezia, HelpText("Отдельные приложения Windows"), list,
            Row(addExe, removeExe), Row(save, cancel) });
        dialog.Controls.Add(panel);
        dialog.AcceptButton = save; dialog.CancelButton = cancel;
        Theme.Apply(dialog);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        SaveProfile(profile with { Direct = new(active.Checked, steam.Checked, amnezia.Checked, string.Join('\n', list.Items.Cast<string>())) });
    }

    void RefreshDirect()
    {
        var profile = profiles.SelectedItem as Profile;
        var options = profile?.Direct ?? new();
        bool ready = running is { IsCancellationRequested: false } && readyPort.HasValue && vpnConfirmed && !closing;
        bool editable = running == null && directTask == null && gatewayWork == null && strategyWork == null && !closing && !importingDirect;
        editDirect.Enabled = editable && writable && profiles.SelectedItem is Profile;
        chooseDirectCore.Enabled = editable;
        directCoreStatus.Text = importingDirect ? "Проверяем архив…" : File.Exists(DirectRouting.ArchivePath(directory))
            ? "Архив сохранён. При запуске VPSLink заново проверит его контрольную сумму."
            : "Архив пока не выбран.";
        retryDirect.Enabled = ready && options.Enabled && directTask == null && directAttempted;
        string summary = options.Enabled ? "Обход включён в профиле." : "Обход выключен в профиле.";
        if (options.Steam) summary += " Steam и его библиотеки.";
        if (options.Amnezia) summary += " Сохранённые исключения AmneziaVPN.";
        if (!string.IsNullOrEmpty(options.Executables)) summary += $" Выбранных .exe: {options.Executables.Split('\n').Length}.";
        directSummary.Text = summary;
        if (!ready || !options.Enabled || profile == null)
        {
            directWork?.Cancel();
            directAttempted = false;
            directStatus.Text = options.Enabled ? "Ждём подтверждённое подключение AmneziaVPN через этот сервер." : "";
            return;
        }
        if (directAttempted || directTask != null) return;
        directAttempted = true;
        retryDirect.Enabled = false;
        var work = CancellationTokenSource.CreateLinkedTokenSource(running!.Token);
        directWork = work;
        directStatus.Text = "Проверяем настройки AmneziaVPN и запускаем прямой маршрут…";
        directTask = RunDirectAsync(profile, options, work);
    }

    async Task RunDirectAsync(Profile profile, DirectOptions options, CancellationTokenSource work)
    {
        try
        {
            await Task.Run(() => DirectRouting.Run(profile, options, directory, message =>
            {
                if (work.IsCancellationRequested || IsDisposed) return;
                BeginInvoke(new Action(() => { if (directWork == work && !work.IsCancellationRequested) directStatus.Text = message; }));
            }, work.Token));
        }
        catch (OperationCanceledException) when (work.IsCancellationRequested) { }
        catch (Exception e) when (e is UserFault or IOException or UnauthorizedAccessException or InvalidOperationException or
                                  System.ComponentModel.Win32Exception or System.Xml.XmlException or System.Text.Json.JsonException or
                                  System.Net.NetworkInformation.NetworkInformationException)
        {
            if (!work.IsCancellationRequested && !IsDisposed)
            {
                directStatus.Text = e is UserFault ? e.Message : "Не удалось включить прямой маршрут. Проверьте права Windows и конфликтующие туннели.";
                Append(directStatus.Text);
            }
        }
        finally
        {
            directTask = null;
            directWork = null;
            work.Dispose();
            if (!IsDisposed) RefreshDirect();
        }
    }
}
