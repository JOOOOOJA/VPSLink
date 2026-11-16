namespace NetUlta;

sealed partial class MainWindow
{
    readonly ComboBox dataRoute = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList, Width = 340, AccessibleName = "Транспорт VPN до VPS",
    };

    void AddDataRouteControls(FlowLayoutPanel page)
    {
        dataRoute.Items.AddRange(new object[] { "Из настроек сервера", "Авто · QUIC с резервом", "Только прямой QUIC", "Только WARP + HTTPS" });
        dataRoute.SelectionChangeCommitted += (_, _) =>
        {
            if (running != null || !writable || profiles.SelectedItem is not Profile profile) return;
            TryUi(() =>
            {
                var updated = profile with { DataRoute = (DataRoute)dataRoute.SelectedIndex };
                Model.ValidateDataRoute(updated);
                SaveProfile(updated);
            });
            RefreshDataRoute();
        };
        tips.SetToolTip(dataRoute, "Авто сначала проверяет прямой QUIC. Если пакеты не проходят, Link переключается на WARP и ваш HTTPS-шлюз. Ручной режим фиксирует путь до отключения.");
        page.Controls.Add(Row(dataRoute));
        var table = new TableLayoutPanel
        {
            AutoSize = true, Width = 622, ColumnCount = 4, CellBorderStyle = TableLayoutPanelCellBorderStyle.Single,
            Margin = new Padding(0, 8, 0, 4),
        };
        foreach (int width in new[] { 133, 128, 126, 228 }) table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, width));
        AddRow(true, "Путь", "Скорость", "Пинг", "Шифрование и видимость");
        AddRow(false, "Прямой QUIC", "Зависит от\nUDP-маршрута", "Обычно ниже\nпод нагрузкой", "AmneziaWG + QUIC/TLS.\nПровайдер видит IP VPS.");
        AddRow(false, "WARP + HTTPS", "Зависит от\nрезервного пути", "Может расти\nпод нагрузкой", "AmneziaWG + SSH/HTTPS.\nПуть с ПК через Cloudflare.");
        page.Controls.Add(table);
        page.Controls.Add(HelpText("В обоих режимах сервер проверяется по ключу SSH. Авто использует QUIC, пока он отвечает. Чтобы снова проверить QUIC после перехода, переподключите Link."));

        void AddRow(bool header, params string[] values)
        {
            int row = table.RowCount++;
            table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            for (int col = 0; col < values.Length; col++)
            {
                var label = new Label { Text = values[col], AutoSize = true, Margin = new Padding(7, 6, 7, 6) };
                if (header) label.Font = new Font("Segoe UI Semibold", 9);
                table.Controls.Add(label, col, row);
            }
        }
    }

    void RefreshDataRoute()
    {
        var selected = profiles.SelectedItem as Profile;
        dataRoute.SelectedIndex = selected != null && Enum.IsDefined(typeof(DataRoute), selected.DataRoute)
            ? (int)selected.DataRoute : -1;
        dataRoute.Enabled = selected is { SharedAccess: false } && writable && running == null &&
            strategyWork == null && gatewayWork == null && !closing;
    }
}
