using System;
using System.IO;
using System.ServiceProcess;
using CmdSpy.Core;

namespace CmdSpy.App;

/// <summary>
/// CMD-spy as a Windows service: starts automatically at boot — before anyone
/// logs in — and captures every popup into the same log files the GUI reads.
/// While it runs, the GUI follows its log instead of capturing on its own.
/// </summary>
internal sealed class CmdSpyService : ServiceBase
{
    /// <summary>Kernel trace sessions distinct from the GUI's, so both can coexist briefly during a switch-over.</summary>
    public const string ProcessSessionName = "CmdSpy-Service-KernelProcessSession";
    public const string NetworkSessionName = "CmdSpy-Service-KernelNetworkSession";

    private CmdSpyEngine? _engine;
    private readonly object _statusLock = new();

    public CmdSpyService()
    {
        ServiceName = ServiceControl.ServiceName;
        CanStop = true;
        CanShutdown = true;
        AutoLog = true;   // start/stop/failure also land in the Application event log
    }

    protected override void OnStart(string[] args)
    {
        // Snapshotting every running process can take a few seconds on a busy machine.
        RequestAdditionalTime(30_000);

        // Boot is when the most is starting at once: run at high priority for
        // the first minutes so capture keeps up, then go back to normal.
        StartupPriority.Boost(TimeSpan.FromMinutes(2));

        var options = new CmdSpyOptions
        {
            EtwSessionName = ProcessSessionName,
            EtwNetworkSessionName = NetworkSessionName
        };
        _engine = new CmdSpyEngine(options);
        _engine.Status += (_, message) => WriteStatus(options.LogDirectory, message);
        WriteStatus(options.LogDirectory, $"Service starting ({Core.Monitoring.SystemTimings.Uptime.TotalSeconds:0} s after boot).");
        _engine.Start();
    }

    protected override void OnStop()
    {
        RequestAdditionalTime(10_000);
        var engine = _engine;
        _engine = null;
        engine?.Dispose();
    }

    protected override void OnShutdown() => OnStop();

    /// <summary>Appends a status line to <c>cmdspy-service.log</c> (kept under ~1 MB) for the GUI and for troubleshooting.</summary>
    private void WriteStatus(string directory, string message)
    {
        try
        {
            lock (_statusLock)
            {
                Directory.CreateDirectory(directory);
                var path = ServiceControl.StatusLogPath(directory);
                if (File.Exists(path) && new FileInfo(path).Length > 1_000_000)
                    File.Move(path, path + ".old", overwrite: true);
                using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                using var w = new StreamWriter(fs);
                w.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {message}");
            }
        }
        catch
        {
            // Status logging must never take the service down.
        }
    }
}
