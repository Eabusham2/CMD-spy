using System;
using System.Management;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Fallback detector used when an ETW kernel session cannot be created. It
/// subscribes to Win32_ProcessStartTrace / Win32_ProcessStopTrace, which fire on
/// every process start/stop from a kernel notification (not polling), so even a
/// very short-lived process is seen. The trade-off is that these events do not
/// carry the command line, so the engine recovers it best-effort via WMI.
/// </summary>
public sealed class WmiProcessWatcher : IProcessWatcher
{
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;

    public string Name => "WMI process-start trace";
    public bool SupportsCommandLine => false;
    public bool SupportsExitEvents => true;

    public event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
    public event EventHandler<ProcessStoppedEventArgs>? ProcessStopped;

    public void Start()
    {
        _startWatcher = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        _startWatcher.EventArrived += OnStartArrived;
        _startWatcher.Start();

        _stopWatcher = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
        _stopWatcher.EventArrived += OnStopArrived;
        _stopWatcher.Start();
    }

    private void OnStartArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var ev = e.NewEvent;
            int pid = ToInt(ev["ProcessID"]);
            int ppid = ToInt(ev["ParentProcessID"]);
            string name = ev["ProcessName"] as string ?? "";

            ProcessStarted?.Invoke(this, new ProcessStartedEventArgs
            {
                ProcessId = pid,
                ParentProcessId = ppid,
                ProcessName = name,
                ImagePath = null,
                CommandLine = null,
                TimestampUtc = DateTimeOffset.UtcNow,
                Source = "WMI"
            });
        }
        catch
        {
            // Ignore malformed events.
        }
    }

    private void OnStopArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var ev = e.NewEvent;
            int pid = ToInt(ev["ProcessID"]);
            int? exit = null;
            try { exit = ToInt(ev["ExitStatus"]); } catch { }

            ProcessStopped?.Invoke(this, new ProcessStoppedEventArgs
            {
                ProcessId = pid,
                ExitCode = exit,
                TimestampUtc = DateTimeOffset.UtcNow
            });
        }
        catch
        {
            // Ignore malformed events.
        }
    }

    private static int ToInt(object? value) => value is null ? 0 : Convert.ToInt32(value);

    public void Stop()
    {
        try { _startWatcher?.Stop(); } catch { }
        try { _stopWatcher?.Stop(); } catch { }
    }

    public void Dispose()
    {
        Stop();
        try { _startWatcher?.Dispose(); } catch { }
        try { _stopWatcher?.Dispose(); } catch { }
        _startWatcher = null;
        _stopWatcher = null;
    }
}
