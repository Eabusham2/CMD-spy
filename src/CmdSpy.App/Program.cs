using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Windows.Forms;

namespace CmdSpy.App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
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

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

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
