using System.Text.Json;

namespace NetUlta;

sealed partial class MainWindow
{
    readonly Button shareCreate = Button("Создать приглашение…"), shareImport = Button("Импортировать приглашение…"),
        shareList = Button("Обновить список"), shareRevoke = Button("Отозвать выбранное…");
    readonly ListBox invitations = new() { Width = 610, Height = 180, DisplayMember = "Display" };
    readonly Label sharingStatus = HelpText("Для получателя: импортируйте файл .vpslink от владельца сервера.");

    Control BuildSharingPage()
    {
        var page = Page(); var stack = Stack(); page.Controls.Add(stack);
        stack.Controls.Add(Heading("Доступ для других людей", "Каждому человеку — отдельное приглашение и VPN-ключ. Пароль владельца и API-токен Cloudflare не передаются."));
        stack.Controls.Add(Row(shareImport));
        stack.Controls.Add(HelpText("Владельцу: выберите настроенный сервер. Для управления приглашениями сначала самостоятельно отключите AmneziaVPN и мост. Это прервёт VPN; программа не отключает его за вас."));
        stack.Controls.Add(Row(shareCreate, shareList)); stack.Controls.Add(invitations);
        stack.Controls.Add(Row(shareRevoke)); stack.Controls.Add(sharingStatus);
        shareCreate.Click += async (_, _) => await CreateInvitation();
        shareImport.Click += async (_, _) => await ImportInvitation();
        shareList.Click += async (_, _) => await ManageInvitations(false);
        shareRevoke.Click += async (_, _) => await ManageInvitations(true);
        tips.SetToolTip(shareCreate, "Создаёт нового клиента AmneziaWG и ограниченный SSH-ключ. Нужен владелец VPS с root-доступом. Готовый файл защищён вашим паролем.");
        tips.SetToolTip(shareRevoke, "Удаляет доступ к мосту и VPN-ключ только выбранного получателя. Его сохранённый файл после отзыва перестанет работать.");
        return page;
    }
    void RefreshSharing()
    {
        bool idle = running == null && gatewayWork == null && strategyWork == null && !closing && writable;
        shareImport.Enabled = idle;
        shareCreate.Enabled = shareList.Enabled = shareRevoke.Enabled = idle && profiles.SelectedItem is Profile { SharedAccess: false, User: "root" };
    }
    static (string Name, string Password)? InvitationPrompt(IWin32Window parent, bool create)
    {
        using var form = new Form { Text = create ? "Новое приглашение" : "Пароль приглашения", ClientSize = new Size(620, 310),
            StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false };
        var box = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(18) };
        var name = new TextBox { Width = 560, MaxLength = 80, PlaceholderText = "Имя получателя / устройства" };
        var password = new TextBox { Width = 560, UseSystemPasswordChar = true, MaxLength = 256 };
        var repeat = new TextBox { Width = 560, UseSystemPasswordChar = true, MaxLength = 256 };
        box.Controls.Add(HelpText(create ? "Назовите получателя. Придумайте отдельный пароль от 12 символов и передайте его отдельно от файла." : "Введите пароль, который сообщил владелец. Импорт не подключает VPN автоматически."));
        if (create) box.Controls.Add(name);
        box.Controls.Add(password);
        if (create) { box.Controls.Add(new Label { Text = "Повторите пароль", AutoSize = true }); box.Controls.Add(repeat); }
        var ok = Button(create ? "Создать" : "Импортировать"); var cancel = Button("Отмена"); cancel.DialogResult = DialogResult.Cancel;
        box.Controls.Add(Row(ok, cancel)); form.Controls.Add(box); Theme.Apply(form); form.AcceptButton = ok; form.CancelButton = cancel;
        ok.Click += (_, _) =>
        {
            if (password.Text.Length < 12 || (create && (password.Text != repeat.Text || string.IsNullOrWhiteSpace(name.Text))))
            { MessageBox.Show(form, "Укажите имя и совпадающий пароль от 12 символов."); return; }
            form.DialogResult = DialogResult.OK;
        };
        return form.ShowDialog(parent) == DialogResult.OK ? (name.Text.Trim(), password.Text) : null;
    }
    async Task SharingWork(Func<CancellationToken, Task> action, bool needsNetwork)
    {
        if (running != null || gatewayWork != null || strategyWork != null || closing || !writable) return;
        using var cancel = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        gatewayWork = cancel; Buttons();
        try
        {
            if (needsNetwork)
            {
                StrategyProbe.RequireIsolation();
                if (profiles.SelectedItem is Profile { UseWarpCore: true } && !IsAdministrator())
                    throw new UserFault("Для встроенного WARP откройте VPSLink от имени администратора. Подключение останется ручным.");
            }
            sharingStatus.Text = "Выполняем…";
            await action(cancel.Token);
        }
        catch (UserFault e) { sharingStatus.Text = e.Message; }
        catch (OperationCanceledException) { sharingStatus.Text = "Действие прервано. Обновите список перед повтором: сервер мог успеть создать приглашение."; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or System.Net.Sockets.SocketException or System.ComponentModel.Win32Exception)
        { sharingStatus.Text = "Не удалось завершить действие. Проверьте путь до VPS и обновите список приглашений перед повтором."; }
        finally { gatewayWork = null; if (!IsDisposed) Buttons(); }
    }
    async Task CreateInvitation()
    {
        if (profiles.SelectedItem is not Profile owner || owner.SharedAccess) return;
        var answer = InvitationPrompt(this, true); if (answer == null) return;
        using var dialog = new SaveFileDialog { Filter = "Приглашение VPSLink|*.vpslink", DefaultExt = "vpslink", FileName = "Invitation.vpslink" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        await SharingWork(async ct =>
        {
            var invitation = await Sharing.Create(owner, answer.Value.Name, directory, ct);
            var encrypted = InvitationFile.Encrypt(invitation, answer.Value.Password);
            var temp = dialog.FileName + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { await File.WriteAllBytesAsync(temp, encrypted, ct); File.Move(temp, dialog.FileName, true); }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            sharingStatus.Text = "Приглашение создано, ограниченный SSH проверен. Передайте файл и пароль разными способами. Получателю нужен VPSLink 0.4.0+ и AmneziaVPN с поддержкой вашей версии AWG.";
        }, true);
    }
    async Task ImportInvitation()
    {
        using var open = new OpenFileDialog { Filter = "Приглашение VPSLink|*.vpslink" };
        if (open.ShowDialog(this) != DialogResult.OK) return;
        var answer = InvitationPrompt(this, false); if (answer == null) return;
        await SharingWork(async ct =>
        {
            if (new FileInfo(open.FileName).Length > 256 * 1024) throw new UserFault("Слишком большой файл приглашения.");
            var invitation = InvitationFile.Decrypt(await File.ReadAllBytesAsync(open.FileName, ct), answer.Value.Password);
            if (saved.Any(p => p.SharedAccess && p.InvitationId == invitation.Id)) throw new UserFault("Это приглашение уже импортировано.");
            var p = await InvitationFile.Import(invitation, ct);
            if (MessageBox.Show(this, $"Добавить сервер {p.Host}?\nКлюч SSH: {p.Fingerprint}\nСверьте адрес и отпечаток с владельцем по доверенному каналу.",
                Text, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            SaveProfile(p);
            sharingStatus.Text = "Сервер добавлен. Нажмите «Подключить»: при необходимости Link предложит зарегистрировать ваше устройство WARP. Затем сохраните профиль VPN и импортируйте .conf в AmneziaVPN.";
        }, false);
    }
    async Task ManageInvitations(bool revoke)
    {
        if (profiles.SelectedItem is not Profile owner || owner.SharedAccess) return;
        var selected = invitations.SelectedItem as SharedEntry;
        if (revoke && (selected == null || MessageBox.Show(this, "Отозвать доступ «" + selected.Name + "»? Его VPN перестанет работать.",
            Text, MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK)) return;
        await SharingWork(async ct =>
        {
            await Sharing.Session(owner, directory, async (ssh, _, token) =>
            {
                if (revoke) Sharing.Check(await Sharing.Exchange<SharedReply>(ssh, 'J', new { Action = "Revoke", ShareId = selected!.Id }, token));
                var reply = await Sharing.Exchange<SharedReply>(ssh, 'J', new { Action = "List" }, token); Sharing.Check(reply);
                invitations.Items.Clear(); invitations.Items.AddRange((reply.Invitations ?? Array.Empty<SharedEntry>()).Cast<object>().ToArray());
                sharingStatus.Text = revoke ? "Выбранный доступ к мосту и VPN отозван." : "Список получен. Отозванные записи сохраняются для учёта.";
                return true;
            }, ct);
        }, true);
    }
}
