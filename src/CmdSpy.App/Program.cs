using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;
using CmdSpy.Core;

namespace CmdSpy.App;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        // Started by the Service Control Manager (see ServiceControl): capture
        // from boot with no window. Services already run as LocalSystem.
        if (args.Any(a => a.Equals("--service", StringComparison.OrdinalIgnoreCase)))
        {
            System.ServiceProcess.ServiceBase.Run(new CmdSpyService());
            return;
        }

        // --tray: start hidden in the notification area. --startup: started with
        // Windows (by the logon task) — get going at high priority, quietly.
        bool startInTray = HasArg(args, "--tray");
        bool atStartup = HasArg(args, "--startup");

        // CMD-spy needs Administrator rights for ETW / WMI process tracing. The
        // app manifest already requests elevation for the CmdSpy.exe host, but if
        // the app is launched another way (e.g. `dotnet CmdSpy.dll`, which ignores
        // the exe manifest) we self-elevate here so it always runs with the rights
        // it needs.
        if (!IsElevated())
        {
            if (RelaunchElevated())
                return;   // an elevated instance is starting; this one exits

            MessageBox.Show(
                "CMD-spy could not obtain Administrator rights.\n\n" +
                "It will keep running with reduced fidelity (WMI fallback); " +
                "restart it as Administrator for full ETW capture.",
                "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        // Only one CMD-spy at a time: starting it again brings the running one forward.
        using var instance = new SingleInstance();
        if (!instance.IsFirst)
        {
            if (!atStartup)
            {
                AllowSetForegroundWindow(-1);   // ASFW_ANY: let the running copy take the foreground
                if (!instance.ActivateFirst())
                    MessageBox.Show("CMD-spy is already running (possibly in another user's session).",
                        "CMD-spy", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            return;
        }

        if (atStartup)
            StartupPriority.Boost(TimeSpan.FromSeconds(90));   // be up and monitoring first, then back to normal

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(startInTray, instance));
    }

    private static bool HasArg(string[] args, string name) =>
        args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(int processId);

    /// <summary>True if the current process is running with Administrator rights.</summary>
    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Relaunches CMD-spy behind a UAC elevation prompt. Returns true if a new
    /// elevated instance was started (so this one should exit), or false if the
    /// user declined the prompt or relaunch was not possible.
    /// </summary>
    private static bool RelaunchElevated()
    {
        try
        {
            var host = Environment.ProcessPath;   // CmdSpy.exe, or the dotnet host
            if (string.IsNullOrEmpty(host)) return false;

            var psi = new ProcessStartInfo
            {
                UseShellExecute = true,
                Verb = "runas",                   // triggers the UAC prompt
                FileName = host,
                WorkingDirectory = AppContext.BaseDirectory
            };

            // When started through the dotnet host, the managed dll is argv[0] and
            // must be forwarded; otherwise just carry any real arguments across.
            var argv = Environment.GetCommandLineArgs();
            var passthrough = IsDotnetHost(host) ? argv : argv.Skip(1);
            psi.Arguments = string.Join(" ", passthrough.Select(Quote));

            Process.Start(psi);
            return true;
        }
        catch
        {
            // ERROR_CANCELLED (user declined) or any other failure.
            return false;
        }
    }

    private static bool IsDotnetHost(string host) =>
        host.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("dotnet", StringComparison.OrdinalIgnoreCase);

    private static string Quote(string arg) =>
        string.IsNullOrEmpty(arg) || arg.Contains(' ') ? $"\"{arg}\"" : arg;
}
