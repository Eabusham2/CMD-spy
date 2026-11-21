using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading;
using CmdSpy.Core;

namespace CmdSpy.App;

/// <summary>
/// Makes CMD-spy start with Windows, in more than one way so it is reliably
/// there first:
///   1. the boot service (<see cref="ServiceControl"/>) — captures from boot,
///      before anyone logs in;
///   2. a logon task (<see cref="StartupTaskDefinition"/>) — opens CMD-spy in
///      the notification area the moment you log in, elevated and at high
///      priority, and brings it back on unlock/reconnect or after a crash.
/// Only one copy ever runs (see <see cref="SingleInstance"/>).
/// </summary>
internal static class StartupManager
{
    private static string TaskFile =>
        Path.Combine(Environment.SystemDirectory, "Tasks", "CmdSpy", "CmdSpy at logon");

    public static bool IsLogonTaskInstalled
    {
        get
        {
            try
            {
                if (File.Exists(TaskFile)) return true;
            }
            catch
            {
            }
            return Schtasks($"/Query /TN \"{StartupTaskDefinition.TaskName}\"").ExitCode == 0;
        }
    }

    public static bool IsServiceInstalled => ServiceControl.GetStatus() is not null;

    /// <summary>Registers the logon task for the current user (CMD-spy is copied to Program Files first).</summary>
    public static List<string> EnableLogonTask(bool copyFiles = true)
    {
        var log = new List<string>();
        var exe = copyFiles ? ServiceControl.InstallFiles(log) : ServiceControl.InstalledAppPath;
        if (exe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Run CMD-spy from CmdSpy.exe (not through 'dotnet') to set it to start with Windows.");

        string user;
        using (var identity = WindowsIdentity.GetCurrent())
            user = identity.Name;

        var xmlPath = Path.Combine(Path.GetTempPath(), $"cmdspy-logon-task-{Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(xmlPath, StartupTaskDefinition.BuildXml(exe, user), Encoding.Unicode);
            var (code, output) = Schtasks($"/Create /TN \"{StartupTaskDefinition.TaskName}\" /XML \"{xmlPath}\" /F");
            if (code != 0) throw new InvalidOperationException($"Creating the logon task failed: {output.Trim()}");
        }
        finally
        {
            try { File.Delete(xmlPath); } catch { }
        }

        log.Add("✓ CMD-spy opens in the notification area as soon as you log in — elevated, at high priority, with no delay.");
        log.Add("✓ If it is closed or crashes, it comes back when you unlock or reconnect (never more than one copy).");
        return log;
    }

    public static List<string> DisableLogonTask()
    {
        var log = new List<string>();
        if (!IsLogonTaskInstalled)
        {
            log.Add("CMD-spy wasn't set to open at log on.");
            return log;
        }
        var (code, output) = Schtasks($"/Delete /TN \"{StartupTaskDefinition.TaskName}\" /F");
        if (code != 0) throw new InvalidOperationException($"Removing the logon task failed: {output.Trim()}");
        log.Add("✓ CMD-spy no longer opens at log on.");
        return log;
    }

    /// <summary>Every start-up method: boot service + logon tray task.</summary>
    public static List<string> EnableAll()
    {
        var log = ServiceControl.Install();               // copies CMD-spy to Program Files
        log.AddRange(EnableLogonTask(copyFiles: false));   // and points the logon task at that copy
        return log;
    }

    public static List<string> DisableAll()
    {
        var log = DisableLogonTask();
        if (IsServiceInstalled) log.AddRange(ServiceControl.Uninstall());
        return log;
    }

    private static (int ExitCode, string Output) Schtasks(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "schtasks.exe"),
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(30_000);
            return (p.ExitCode, output);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }
}

/// <summary>Runs the process at high priority for a while after start-up, then back to normal.</summary>
internal static class StartupPriority
{
    private static System.Threading.Timer? _restore;

    public static void Boost(TimeSpan duration)
    {
        try
        {
            using var me = Process.GetCurrentProcess();
            me.PriorityClass = ProcessPriorityClass.High;
        }
        catch
        {
            return;
        }
        _restore = new System.Threading.Timer(_ =>
        {
            try
            {
                using var me = Process.GetCurrentProcess();
                me.PriorityClass = ProcessPriorityClass.Normal;
            }
            catch
            {
            }
        }, null, duration, Timeout.InfiniteTimeSpan);
    }
}

/// <summary>Per-user GUI preferences (%LocalAppData%\CmdSpy\settings.json).</summary>
internal sealed class AppSettings
{
    /// <summary>Closing the window keeps CMD-spy monitoring in the notification area.</summary>
    public bool KeepRunningInTray { get; set; } = true;

    /// <summary>Show a notification when a popup is analysed as High risk or Suspicious.</summary>
    public bool AlertOnSuspicious { get; set; } = true;

    public bool TrayHintShown { get; set; }

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CmdSpy", "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return System.Text.Json.JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch
        {
        }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, System.Text.Json.JsonSerializer.Serialize(this));
        }
        catch
        {
        }
    }
}
