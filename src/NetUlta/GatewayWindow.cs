namespace NetUlta;

sealed class GatewayWindow : Form
{
    readonly TextBox zone = new() { Dock = DockStyle.Top }, hostname = new() { Dock = DockStyle.Top },
        token = new() { Dock = DockStyle.Top, UseSystemPasswordChar = true };
    public GatewayOptions? Result { get; private set; }
    public GatewayWindow(Profile profile)
    {
        Text = "Постоянный шлюз Cloudflare";
        Font = new Font("Segoe UI", 10);
        ClientSize = new Size(650, 520);
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false;
        var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown,
            WrapContents = false, Padding = new Padding(18), AutoScroll = true };
        void Label(string text) => layout.Controls.Add(new Label { Text = text, AutoSize = true, MaximumSize = new Size(570, 0), Margin = new Padding(0, 6, 0, 5) });
        Label("Link создаст туннель и отдельную DNS-запись, установит cloudflared и службы шлюза на VPS. Нужны активный домен в Cloudflare и действующий доступ SSH с правами root.");
        Label("Домен в Cloudflare"); zone.Width = 570; zone.PlaceholderText = "example.com"; layout.Controls.Add(zone);
        Label("Новый поддомен шлюза"); hostname.Width = 570; hostname.Text = profile.GatewayHostname;
        hostname.PlaceholderText = "link.example.com"; layout.Controls.Add(hostname);
        Label("API-токен: Tunnel Edit, DNS Edit, Zone Read (только нужный аккаунт и домен)");
        token.Width = 570; layout.Controls.Add(token);
        Label("API-токен используется только во время настройки и не сохраняется. На VPS останется токен только этого туннеля. Другие DNS-записи и службы не изменяются.");
        var buttons = new FlowLayoutPanel { Width = 570, Height = 42, FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = "Отмена", AutoSize = true, DialogResult = DialogResult.Cancel };
        var install = new Button { Text = "Настроить шлюз", AutoSize = true };
        buttons.Controls.AddRange(new Control[] { cancel, install }); layout.Controls.Add(buttons);
        Controls.Add(layout); CancelButton = cancel; AcceptButton = install;
        Theme.Apply(this);
        install.Click += (_, _) =>
        {
            try
            {
                var options = new GatewayOptions(zone.Text.Trim().ToLowerInvariant(), hostname.Text.Trim().ToLowerInvariant(), token.Text.Trim());
                CloudflareGateway.Validate(options);
                Result = options; token.Clear(); DialogResult = DialogResult.OK;
            }
            catch (UserFault e) { MessageBox.Show(this, e.Message, Text); }
        };
        FormClosed += (_, _) => token.Clear();
    }
}
