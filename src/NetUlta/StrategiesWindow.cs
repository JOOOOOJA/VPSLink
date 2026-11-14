using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;

namespace NetUlta;

sealed partial class MainWindow
{
    readonly ComboBox strategyChoice = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 580, AccessibleName = "Стратегия winws" };
    readonly Label strategyDescription = HelpText(""), strategyCurrent = HelpText(""), catalogStatus = HelpText(""), strategyStatus = HelpText("");
    readonly Button applyStrategy = Button("Использовать для сервера"), resetStrategy = Button("Вернуть базовую"),
        checkStrategy = Button("Проверить выбранную"), findStrategy = Button("Подобрать автоматически"), cancelStrategy = Button("Отменить проверку"),
        updateStrategies = Button("Обновить с GitHub"), rollbackStrategies = Button("Предыдущий каталог"), elevateStrategies = Button("Открыть для проверки от администратора");
    readonly TextBox strategyResults = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Width = 640, Height = 150, AccessibleName = "Результаты проверки стратегий" };
    StrategyCatalogStore catalogStore = null!;
    StrategyCatalog? strategyCatalog;
    Guid? strategyProfile;
    CancellationTokenSource? strategyWork, catalogWork;
    Task? strategyTask;
    bool catalogBusy;

    Control BuildStrategiesPage()
    {
        catalogStore = new(directory);
        var page = Page(); var content = Stack();
        content.Controls.Add(Heading("Стратегии winws", "Если встроенный WARP не соединяется, попробуйте другой способ обработки его TLS-запросов. Стратегия действует только на соединение WARP, а не на весь трафик Windows."));
        content.Controls.Add(strategyCurrent);
        content.Controls.Add(Row(strategyChoice)); content.Controls.Add(strategyDescription);
        content.Controls.Add(Row(applyStrategy, resetStrategy));
        content.Controls.Add(Heading("Подобрать рабочий вариант", "Сначала отключите профиль AmneziaVPN, затем мост Link. Для независимого теста также должны быть остановлены системный WARP и другие winws/usque. Программа сама их не отключает."));
        content.Controls.Add(Row(elevateStrategies));
        content.Controls.Add(Row(checkStrategy, findStrategy, cancelStrategy));
        content.Controls.Add(strategyStatus); content.Controls.Add(strategyResults);
        content.Controls.Add(Heading("Каталог zapret", "Источник: bol-van/zapret-win-bundle на GitHub. Загружаются только совместимые параметры из официального примера winws. Обновление каталога не меняет выбранную стратегию и не прерывает VPN."));
        content.Controls.Add(catalogStatus); content.Controls.Add(Row(updateStrategies, rollbackStrategies));
        var source = Button("Открыть источник ↗"); source.Click += (_, _) => TryUi(() => OpenUrl("https://github.com/" + WinwsStrategies.Repository + "/blob/master/" + WinwsStrategies.PresetPath));
        content.Controls.Add(Row(source)); page.Controls.Add(content);
        strategyChoice.SelectedIndexChanged += (_, _) => DescribeStrategy();
        applyStrategy.Click += (_, _) => TryUi(SaveStrategy);
        resetStrategy.Click += (_, _) => TryUi(() =>
        {
            if (StrategyBusy || profiles.SelectedItem is not Profile) return;
            strategyChoice.SelectedItem = strategyChoice.Items.Cast<WinwsStrategy>().First(s => s.Id == WinwsStrategies.Default.Id);
            SaveStrategy();
        });
        checkStrategy.Click += async (_, _) => await RunStrategyChecks(false);
        findStrategy.Click += async (_, _) => await RunStrategyChecks(true);
        cancelStrategy.Click += (_, _) => strategyWork?.Cancel();
        updateStrategies.Click += async (_, _) => await RefreshCatalog();
        rollbackStrategies.Click += (_, _) => TryUi(() => { if (catalogBusy) return; strategyCatalog = catalogStore.Rollback(); ShowCatalog(); RefreshStrategies(true); });
        elevateStrategies.Click += (_, _) => ElevateStrategies();
        tips.SetToolTip(strategyChoice, "Варианты для WARP MASQUE через TCP 443. Выбор в списке ничего не запускает и не меняет действующий мост.");
        tips.SetToolTip(applyStrategy, "Сохраняет выбранный вариант только для этого сервера. Затем подключите Link и включите профиль AmneziaVPN вручную.");
        tips.SetToolTip(findStrategy, "Проверяет варианты по очереди до первого успешного ответа вашего VPS, до 25 секунд на вариант. Результат нужно сохранить кнопкой «Использовать для сервера».");
        tips.SetToolTip(updateStrategies, "Обновляет каталог параметров через GitHub. Скачанные CMD-файлы не исполняются; winws и драйверы этой кнопкой не обновляются.");
        tips.SetToolTip(rollbackStrategies, "Возвращает предыдущую успешно сохранённую версию каталога. Сохранённая в профиле стратегия остаётся прежней.");
        try { strategyCatalog = catalogStore.Load(); ShowCatalog(); }
        catch (Exception e) when (CatalogError(e)) { catalogStatus.Text = "Сохранённый каталог не удалось прочитать. Встроенные стратегии доступны. Нажмите «Обновить с GitHub» или верните предыдущий каталог."; }
        FormClosing += (_, _) => catalogWork?.Cancel();
        return page;
    }
    bool StrategyBusy => running != null || gatewayWork != null || strategyWork != null || closing;
    void ShowCatalog()
    {
        catalogStatus.Text = strategyCatalog == null ? "Встроенные варианты доступны без интернета. Нажмите «Обновить с GitHub», чтобы добавить варианты zapret." :
            $"Добавлено из zapret: {strategyCatalog.Strategies.Length}. Проверено: {strategyCatalog.FetchedUtc.ToLocalTime():g}. Версия: {strategyCatalog.Revision[..8]}." +
            (strategyCatalog.Skipped == 0 ? "" : $" Несовместимых TLS-вариантов пропущено: {strategyCatalog.Skipped}.");
    }
    void RefreshStrategies(bool force = false)
    {
        if (catalogStore == null) return;
        var profile = profiles.SelectedItem as Profile;
        if (force || strategyChoice.Items.Count == 0 || strategyProfile != profile?.Id)
        {
            string wanted = strategyProfile == profile?.Id ? (strategyChoice.SelectedItem as WinwsStrategy)?.Id ?? "" : "";
            strategyProfile = profile?.Id;
            var all = WinwsStrategies.Builtins().Concat(strategyCatalog?.Strategies ?? Array.Empty<WinwsStrategy>()).ToList();
            if (profile?.WinwsStrategy is { } stored)
            {
                try { WinwsStrategies.Validate(stored); if (!all.Any(s => s.Id == stored.Id)) all.Add(stored); }
                catch (UserFault) { strategyStatus.Text = "Сохранённая стратегия повреждена. Выберите и сохраните базовую."; }
            }
            strategyChoice.Items.Clear(); strategyChoice.Items.AddRange(all.ToArray());
            strategyChoice.SelectedItem = all.FirstOrDefault(s => s.Id == wanted) ?? all.FirstOrDefault(s => s.Id == profile?.WinwsStrategy?.Id) ?? all[0];
        }
        strategyCurrent.Text = profile == null ? "Сначала выберите сервер." : "Для сервера сохранена: " + (profile.WinwsStrategy?.Name ?? WinwsStrategies.Default.Name) +
            (profile.UseWarpCore ? "" : "\nВстроенный WARP выключен: эти стратегии сейчас не используются.");
        bool available = profile is { UseWarpCore: true } && !StrategyBusy;
        applyStrategy.Enabled = resetStrategy.Enabled = available && writable && !catalogBusy;
        checkStrategy.Enabled = findStrategy.Enabled = available && !catalogBusy && IsAdministrator();
        cancelStrategy.Enabled = strategyWork != null && !strategyWork.IsCancellationRequested;
        strategyChoice.Enabled = strategyWork == null && !closing;
        elevateStrategies.Visible = !IsAdministrator(); elevateStrategies.Enabled = available;
        updateStrategies.Enabled = !catalogBusy && strategyWork == null && !closing;
        rollbackStrategies.Enabled = !catalogBusy && strategyWork == null && !closing && catalogStore.CanRollback;
    }
    void DescribeStrategy()
    {
        if (strategyChoice.SelectedItem is WinwsStrategy chosen) strategyDescription.Text = chosen.Description +
            (chosen.Revision == "builtin" ? "\nВстроенный вариант VPSLink." : "\nИсточник: zapret, версия " + chosen.Revision[..8] + ".");
    }
    void SaveStrategy()
    {
        if (StrategyBusy || catalogBusy || !writable || profiles.SelectedItem is not Profile { UseWarpCore: true } profile || strategyChoice.SelectedItem is not WinwsStrategy chosen) return;
        var snapshot = WinwsStrategies.Snapshot(chosen);
        SaveProfile(profile with { WinwsStrategy = snapshot.Id == WinwsStrategies.Default.Id ? null : snapshot });
        strategyStatus.Text = "Сохранено. Теперь подключите Link и включите профиль AmneziaVPN вручную.";
    }
    async Task RefreshCatalog()
    {
        if (catalogBusy || strategyWork != null || closing) return;
        using var cancel = new CancellationTokenSource(); catalogWork = cancel; catalogBusy = true; RefreshStrategies();
        catalogStatus.Text = "Получаем совместимые параметры с GitHub…";
        try
        {
            using var client = new StrategyCatalogClient();
            var fetched = await client.Fetch(cancel.Token);
            cancel.Token.ThrowIfCancellationRequested();
            catalogStore.Save(fetched); strategyCatalog = fetched;
            ShowCatalog(); RefreshStrategies(true);
        }
        catch (Exception e) when (CatalogError(e))
        { if (!IsDisposed) catalogStatus.Text = (e is UserFault ? e.Message : "Не удалось обновить каталог. Проверьте интернет и повторите позже.") + " Сохранённые стратегии не изменены."; }
        finally { catalogWork = null; catalogBusy = false; if (!IsDisposed) RefreshStrategies(); }
    }
    static bool CatalogError(Exception e) => e is UserFault or HttpRequestException or IOException or UnauthorizedAccessException or JsonException or
        OperationCanceledException or InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException or OverflowException;

    async Task RunStrategyChecks(bool automatic)
    {
        if (StrategyBusy || catalogBusy || profiles.SelectedItem is not Profile profile || strategyChoice.SelectedItem is not WinwsStrategy chosen) return;
        try { if (!IsAdministrator()) throw new UserFault("Откройте VPSLink от администратора кнопкой выше."); StrategyProbe.RequireReady(profile); }
        catch (UserFault e) { strategyStatus.Text = e.Message; return; }
        var choices = automatic ? strategyChoice.Items.Cast<WinwsStrategy>().ToArray() : new[] { chosen };
        using var cancel = new CancellationTokenSource(); strategyWork = cancel; Buttons();
        strategyResults.Clear(); strategyStatus.Text = "Проверяем путь до VPS. Подключение AmneziaVPN пока оставьте выключенным.";
        var progress = new Progress<StrategyAttempt>(attempt =>
        {
            if (IsDisposed || strategyWork != cancel) return;
            strategyResults.AppendText($"{attempt.Strategy.Name}: {(attempt.Success ? "доступен" : "не подтверждён")} ({attempt.Milliseconds / 1000.0:F1} с). {attempt.Message}\r\n");
        });
        var work = Task.Run(() => StrategyProbe.Select(choices, (candidate, token) => StrategyProbe.Probe(profile, candidate, token),
            attempt => ((IProgress<StrategyAttempt>)progress).Report(attempt), cancel.Token));
        strategyTask = work;
        try
        {
            var found = await work;
            if (found != null)
            {
                strategyChoice.SelectedItem = strategyChoice.Items.Cast<WinwsStrategy>().First(s => s.Id == found.Id);
                strategyStatus.Text = "Рабочий путь найден. Нажмите «Использовать для сервера», затем подключите Link и AmneziaVPN. Это ещё не проверка всего VPN-трафика.";
            }
            else strategyStatus.Text = "Рабочий путь не найден. Прежняя настройка сохранена. Обновите каталог или проверьте адрес шлюза, SSH и доступность интернета.";
        }
        catch (OperationCanceledException) { if (!IsDisposed) strategyStatus.Text = "Проверка отменена. Созданные проверкой процессы остановлены; настройки сервера не изменены."; }
        catch (Exception) { if (!IsDisposed) strategyStatus.Text = "Проверка не завершилась. Настройки сервера не изменены."; }
        finally { strategyTask = null; strategyWork = null; if (!IsDisposed) Buttons(); }
    }
    void ElevateStrategies()
    {
        if (StrategyBusy || profiles.SelectedItem is not Profile profile) return;
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas",
                Arguments = "--strategies " + profile.Id + " " + Environment.ProcessId, WorkingDirectory = AppContext.BaseDirectory });
            allowClose = true; Close();
        }
        catch (System.ComponentModel.Win32Exception) { strategyStatus.Text = "Запрос Windows отменён. Каталог можно просматривать без прав администратора."; }
    }
}
