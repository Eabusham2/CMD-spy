using System;
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

        // CMD-spy needs Administrator rights for ETW process tracing. CmdSpy.exe
        // requests them in its manifest. Do not self-elevate a launch that bypassed
        // the manifest (for example, `dotnet CmdSpy.dll`): handing UAC a pathname
        // would let a writable managed bundle be replaced before the elevated
        // process opens it. Keep the current process on the WMI fallback instead.
        if (!IsElevated())
        {
            MessageBox.Show(
                "CMD-spy is not running with Administrator rights.\n\n" +
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

}
