using System.Security.Principal;

namespace NetUlta;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if (args.FirstOrDefault() == "--known-host") return SshSession.KnownHost(args);
        if (AskPass.IsHelper) return AskPass.Run(args);
        bool startup = args.SequenceEqual(new[] { "--startup" });
        bool preview = args.SequenceEqual(new[] { "--preview-ui" });
        bool configureStartup = args.Length == 3 && args[0] == "--configure-autostart";
        bool manualStart = args.SequenceEqual(new[] { "--configure-manual-start" });
        Guid? connectProfile = null;
        Guid? strategiesProfile = null;
        if (args.Length == 3 && args[0] is ("--connect-profile" or "--strategies") && Guid.TryParse(args[1], out var profileId) && int.TryParse(args[2], out int previousPid))
        {
            if (args[0] == "--strategies") strategiesProfile = profileId; else connectProfile = profileId;
            try { using var previous = System.Diagnostics.Process.GetProcessById(previousPid); if (!previous.WaitForExit(15000)) return 3; }
            catch (ArgumentException) { }
        }
        if (args.Length > 0 && !startup && !preview && !configureStartup && !manualStart && connectProfile == null && strategiesProfile == null && !args.SequenceEqual(new[] { "--smoke-ui" })) return 2;
        ApplicationConfiguration.Initialize();
        if (preview)
        {
            using var previewWindow = new MainWindow(Path.Combine(Path.GetTempPath(), "tfl-preview-" + Guid.NewGuid().ToString("N")));
            Application.Run(previewWindow);
            return 0;
        }
        if (args.SequenceEqual(new[] { "--smoke-ui" }))
        {
            string tmp = Path.Combine(Path.GetTempPath(), "tfl-ui-" + Guid.NewGuid().ToString("N"));
            using var app = new MainWindow(tmp) { Opacity = 0, ShowInTaskbar = false };
            using var wizard = new ProfileWindow(null) { Opacity = 0 };
            using var timer = new System.Windows.Forms.Timer { Interval = 350 };
            timer.Tick += (_, _) => { timer.Stop(); wizard.Close(); app.Close(); };
            app.Shown += (_, _) => { wizard.Show(app); timer.Start(); };
            Application.Run(app);
            return 0;
        }
        using var mutex = new Mutex(true, @"Local\ThingsNotFun-Link-" + WindowsIdentity.GetCurrent().User?.Value, out bool unique);
        if (!unique)
        {
            if (configureStartup || manualStart) return 3;
            MessageBox.Show("VPSLink уже работает. Проверьте значок в области уведомлений.", "VPSLink");
            return 0;
        }
        var directory = ProfileStore.DefaultDirectory;
        if (configureStartup || manualStart)
        {
            Guid id = default;
            int index = 0;
            if (configureStartup && (!Guid.TryParse(args[1], out id) || !int.TryParse(args[2], out index) || index is < 0 or > 999)) return 2;
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 4;
            try
            {
                if (manualStart) StartupConfiguration.UseManualStart(new ProfileStore(directory), StartupRegistration.Set);
                else StartupConfiguration.Configure(new ProfileStore(directory), id, index, StartupRegistration.Set);
                return 0;
            }
            catch (Exception e) when (e is UserFault or IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
            { return 5; }
        }
        try { SshFiles.ClearOrphans(directory); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        using var main = new MainWindow(directory, startup, connectProfile, strategiesProfile);
        Application.Run(main);
        return 0;
    }
}


