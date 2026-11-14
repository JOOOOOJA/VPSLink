using System.Runtime.InteropServices;
using System.Security.Principal;

namespace NetUlta;

static class StartupRegistration
{
    public static void Set(bool enabled)
    {
        using var identity = WindowsIdentity.GetCurrent();
        string sid = identity.User?.Value ?? throw new UserFault("Не определена учётная запись Windows.");
        string name = "ThingsNotFun-Link-" + sid;
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new UserFault("Недоступен планировщик Windows.");
        dynamic service = Activator.CreateInstance(type)!;
        try
        {
            service.Connect();
            dynamic folder = service.GetFolder("\\");
            if (!enabled)
            {
                try { folder.DeleteTask(name, 0); }
                catch (COMException e) when (e.HResult == unchecked((int)0x80070002)) { }
                return;
            }
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UserFault("Для автозапуска с ядром WARP запустите Link от администратора один раз.");
            dynamic task = service.NewTask(0);
            task.RegistrationInfo.Description = "Запуск VPSLink после входа текущего пользователя Windows.";
            task.Principal.UserId = sid;
            task.Principal.LogonType = 3; // InteractiveToken: no Windows password is stored.
            task.Principal.RunLevel = 1;
            task.Settings.Enabled = true;
            task.Settings.StartWhenAvailable = true;
            task.Settings.DisallowStartIfOnBatteries = false;
            task.Settings.StopIfGoingOnBatteries = false;
            task.Settings.ExecutionTimeLimit = "PT0S";
            task.Settings.MultipleInstances = 2; // IgnoreNew
            task.Settings.RestartCount = 3;
            task.Settings.RestartInterval = "PT1M";
            dynamic trigger = task.Triggers.Create(9); // Logon
            trigger.UserId = sid;
            trigger.Delay = "PT10S";
            dynamic action = task.Actions.Create(0); // Exec
            action.Path = Environment.ProcessPath!;
            action.Arguments = "--startup";
            action.WorkingDirectory = AppContext.BaseDirectory;
            folder.RegisterTaskDefinition(name, task, 6, sid, null, 3, null);
        }
        catch (COMException) { throw new UserFault("Не удалось сохранить автозапуск. Проверьте права администратора и планировщик Windows."); }
        finally { Marshal.FinalReleaseComObject(service); }
    }
}
