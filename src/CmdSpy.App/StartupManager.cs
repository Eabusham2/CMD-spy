using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
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
    private const string TaskFolderName = "CmdSpy";
    private const string TaskRegistrationName = "CmdSpy at logon";
    private const int TaskCreateOrUpdate = 6;
    private const int TaskLogonInteractiveToken = 3;
    private const int HResultFileNotFound = unchecked((int)0x80070002);
    private const int HResultPathNotFound = unchecked((int)0x80070003);
    private static readonly Guid TaskSchedulerClassId = new("0F87369F-A4E5-4CFC-BD3E-73E6154572DD");

    private static string TaskFile =>
        Path.Combine(Environment.SystemDirectory, "Tasks", TaskFolderName, TaskRegistrationName);

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

        try
        {
            RegisterTask(StartupTaskDefinition.BuildXml(exe, user), user);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Creating the logon task failed: {ex.Message}", ex);
        }

        log.Add("✓ CMD-spy opens in the notification area as soon as you log in — elevated, at high priority, with no delay.");
        log.Add("✓ If it is closed or crashes, it comes back when you unlock or reconnect (never more than one copy).");
        return log;
    }

    /// <summary>
    /// Registers the definition directly with the Task Scheduler service. Keeping
    /// the XML in memory prevents another process from replacing it between
    /// generation and the privileged service consuming it.
    /// </summary>
    private static void RegisterTask(string taskXml, string user)
    {
        object? service = null;
        object? rootFolder = null;
        object? taskFolder = null;
        object? registeredTask = null;

        try
        {
            var serviceType = Type.GetTypeFromCLSID(TaskSchedulerClassId)
                ?? throw new InvalidOperationException("Windows Task Scheduler is unavailable.");
            service = Activator.CreateInstance(serviceType)
                ?? throw new InvalidOperationException("Windows Task Scheduler could not be started.");

            dynamic scheduler = service;
            scheduler.Connect();
            rootFolder = scheduler.GetFolder(@"\");
            taskFolder = GetOrCreateTaskFolder(rootFolder);

            dynamic folder = taskFolder;
            registeredTask = folder.RegisterTask(
                TaskRegistrationName,
                taskXml,
                TaskCreateOrUpdate,
                user,
                null,
                TaskLogonInteractiveToken,
                null);
        }
        finally
        {
            ReleaseComObject(registeredTask);
            ReleaseComObject(taskFolder);
            ReleaseComObject(rootFolder);
            ReleaseComObject(service);
        }
    }

    private static object GetOrCreateTaskFolder(object rootFolder)
    {
        dynamic root = rootFolder;
        try
        {
            return root.GetFolder(TaskFolderName);
        }
        catch (COMException ex) when (ex.HResult == HResultFileNotFound || ex.HResult == HResultPathNotFound)
        {
            return root.CreateFolder(TaskFolderName, null);
        }
    }

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
            Marshal.FinalReleaseComObject(value);
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
