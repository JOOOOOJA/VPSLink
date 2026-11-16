using System.Diagnostics;
using System.Reflection;

namespace NetUlta;

static class UserGuide
{
    public static string Save(string directory)
    {
        string help = Path.Combine(directory, "Help");
        Directory.CreateDirectory(help);
        string file = Path.Combine(help, "thingsnotfun-link-guide.html");
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetUlta.Guide.html")
            ?? throw new IOException("В сборке отсутствует инструкция.");
        using var output = File.Create(file);
        resource.CopyTo(output);
        return file;
    }
    public static void Open(string directory, bool invitation = false)
    {
        string file = Save(directory);
        string target = invitation
            ? new UriBuilder(new Uri(file)) { Fragment = "received-invitation" }.Uri.AbsoluteUri
            : file;
        Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
    }
}
