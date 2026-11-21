using System;
using System.Xml.Linq;

namespace CmdSpy.Core;

/// <summary>
/// The Task Scheduler definition that starts CMD-spy in the notification area
/// when the user logs on — elevated without a UAC prompt ("run with highest
/// privileges"), at high priority and with no delay, so it is monitoring before
/// the usual start-up programs. The same task brings it back on unlock or
/// reconnect, and after a crash, if it isn't running; only one copy ever runs.
/// (A plain Run-key or Startup-folder entry can't do this: Windows refuses to
/// auto-start programs that need Administrator rights from those.)
/// </summary>
public static class StartupTaskDefinition
{
    public const string TaskName = @"\CmdSpy\CmdSpy at logon";

    /// <summary>Arguments the task passes: start hidden in the tray, in start-up mode.</summary>
    public const string Arguments = "--tray --startup";

    /// <summary>Task Scheduler priority 1 = HIGH_PRIORITY_CLASS (the default, 7, is below normal).</summary>
    public const int Priority = 1;

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <param name="executablePath">The installed CmdSpy.exe (in Program Files, not a user-writable folder).</param>
    /// <param name="userId">The account it runs for, e.g. "PC\\alice" or a SID.</param>
    public static string BuildXml(string executablePath, string userId)
    {
        if (string.IsNullOrWhiteSpace(executablePath)) throw new ArgumentException("Executable path required.", nameof(executablePath));
        if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException("User required.", nameof(userId));

        XElement E(string name, params object[] content) => new(Ns + name, content);
        XElement SessionTrigger(string change) =>
            E("SessionStateChangeTrigger", E("Enabled", "true"), E("StateChange", change), E("UserId", userId));

        var task = E("Task", new XAttribute("version", "1.2"),
            E("RegistrationInfo",
                E("Author", "CMD-spy"),
                E("Description",
                    "Starts CMD-spy in the notification area at log on (elevated, high priority, no delay) so it is monitoring " +
                    "command-prompt popups before other start-up programs. Brings it back on unlock/reconnect if it was closed."),
                E("URI", TaskName)),
            E("Triggers",
                E("LogonTrigger", E("Enabled", "true"), E("UserId", userId)),
                SessionTrigger("SessionUnlock"),
                SessionTrigger("ConsoleConnect"),
                SessionTrigger("RemoteConnect")),
            E("Principals",
                E("Principal", new XAttribute("id", "Author"),
                    E("UserId", userId),
                    E("LogonType", "InteractiveToken"),
                    E("RunLevel", "HighestAvailable"))),
            E("Settings",
                E("MultipleInstancesPolicy", "IgnoreNew"),
                E("DisallowStartIfOnBatteries", "false"),
                E("StopIfGoingOnBatteries", "false"),
                E("AllowHardTerminate", "true"),
                E("StartWhenAvailable", "true"),
                E("RunOnlyIfNetworkAvailable", "false"),
                E("IdleSettings", E("StopOnIdleEnd", "false"), E("RestartOnIdle", "false")),
                E("AllowStartOnDemand", "true"),
                E("Enabled", "true"),
                E("Hidden", "false"),
                E("RunOnlyIfIdle", "false"),
                E("WakeToRun", "false"),
                E("ExecutionTimeLimit", "PT0S"),
                E("Priority", Priority.ToString()),
                E("RestartOnFailure", E("Interval", "PT1M"), E("Count", "10"))),
            E("Actions", new XAttribute("Context", "Author"),
                E("Exec", E("Command", executablePath), E("Arguments", Arguments))));

        // schtasks /XML expects UTF-16; the caller writes the file with Encoding.Unicode.
        return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" + Environment.NewLine + task;
    }
}
