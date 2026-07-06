using System;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Primary detector. Opens an ETW kernel-process trace session — the same
/// mechanism Sysmon and Process Monitor use. The kernel hands us the full
/// command line and parent id at the moment of creation, so a cmd window that
/// flashes for a single millisecond is captured in full before it can vanish.
///
/// Requires administrator privileges. Constructing the session throws if the
/// caller is not elevated; the engine catches that and falls back to WMI.
/// </summary>
public sealed class EtwProcessWatcher : IProcessWatcher
{
    private const string SessionName = "CmdSpy-KernelProcessSession";

    private TraceEventSession? _session;
    private Thread? _pumpThread;

    public string Name => "ETW kernel process trace";
    public bool SupportsCommandLine => true;
    public bool SupportsExitEvents => true;

    public event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
    public event EventHandler<ProcessStoppedEventArgs>? ProcessStopped;

    public void Start()
    {
        // A stale session with the same name may survive a hard crash — recreating
        // with the same name reuses/replaces it cleanly.
        _session = new TraceEventSession(SessionName)
        {
            StopOnDispose = true
        };

        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
        _session.Source.Kernel.ProcessStart += OnProcessStart;
        _session.Source.Kernel.ProcessStop += OnProcessStop;

        _pumpThread = new Thread(PumpEvents)
        {
            IsBackground = true,
            Name = "CmdSpy-ETW-Pump"
        };
        _pumpThread.Start();
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process(); // blocks until StopProcessing / Dispose
        }
        catch
        {
            // Session torn down — pump exits quietly.
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        var handler = ProcessStarted;
        if (handler is null) return;

        handler(this, new ProcessStartedEventArgs
        {
            ProcessId = data.ProcessID,
            ParentProcessId = data.ParentID,
            ProcessName = string.IsNullOrEmpty(data.ProcessName) ? data.ImageFileName : data.ProcessName,
            ImagePath = string.IsNullOrEmpty(data.ImageFileName) ? null : data.ImageFileName,
            CommandLine = string.IsNullOrEmpty(data.CommandLine) ? null : data.CommandLine,
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
            Source = "ETW"
        });
    }

    private void OnProcessStop(ProcessTraceData data)
    {
        ProcessStopped?.Invoke(this, new ProcessStoppedEventArgs
        {
            ProcessId = data.ProcessID,
            ExitCode = data.ExitStatus,
            TimestampUtc = data.TimeStamp.ToUniversalTime()
        });
    }

    public void Stop()
    {
        try { _session?.Source.StopProcessing(); } catch { }
    }

    public void Dispose()
    {
        Stop();
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
