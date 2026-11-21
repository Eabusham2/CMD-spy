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
    public const string DefaultSessionName = "CmdSpy-KernelProcessSession";

    private readonly string _sessionName;
    private TraceEventSession? _session;
    private Thread? _pumpThread;

    public EtwProcessWatcher() : this(DefaultSessionName) { }

    /// <param name="sessionName">ETW session name; distinct per host so the GUI and the boot service never collide.</param>
    public EtwProcessWatcher(string sessionName)
    {
        _sessionName = string.IsNullOrWhiteSpace(sessionName) ? DefaultSessionName : sessionName;
    }

    /// <summary>Events the kernel had to drop because they arrived faster than they were read.</summary>
    public int EventsLost
    {
        get
        {
            try { return _session?.EventsLost ?? 0; }
            catch { return 0; }
        }
    }

    public string Name => "ETW kernel process trace";
    public bool SupportsCommandLine => true;
    public bool SupportsExitEvents => true;

    public event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
    public event EventHandler<ProcessStoppedEventArgs>? ProcessStopped;

    public void Start()
    {
        // A stale session with the same name may survive a hard crash — recreating
        // with the same name reuses/replaces it cleanly.
        _session = new TraceEventSession(_sessionName)
        {
            StopOnDispose = true
        };

        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
        _session.Source.Kernel.ProcessStart += OnProcessStart;
        _session.Source.Kernel.ProcessStop += OnProcessStop;

        _pumpThread = new Thread(PumpEvents)
        {
            IsBackground = true,
            Name = "CmdSpy-ETW-Pump",
            Priority = ThreadPriority.AboveNormal   // keep up with bursts of process starts
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

        // Prefer the kernel's full image path (captured at creation, so it is
        // known even for a process that lives a millisecond), normalised from
        // \Device\HarddiskVolumeN\... to C:\...
        string? image = null;
        try
        {
            var kernelPath = data.KernelImageFileName;
            image = kernelPath is not null && kernelPath.Contains('\\')
                ? ProcessImageResolver.NormalizeKernelPath(kernelPath)
                : null;
        }
        catch
        {
        }
        if (string.IsNullOrEmpty(image)) image = string.IsNullOrEmpty(data.ImageFileName) ? null : data.ImageFileName;

        int session = -1;
        try { session = data.SessionID; } catch { }

        // The kernel's short name drops ".exe" and is cut at 15 characters
        // ("asus_framework."); the file name from the full path is exact.
        var name = string.IsNullOrEmpty(data.ProcessName) ? data.ImageFileName : data.ProcessName;
        var shortName = data.ImageFileName;
        if (!string.IsNullOrEmpty(shortName) && shortName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name = shortName;   // e.g. "powershell.exe" (complete, not cut off)
        if (image is not null && image.Contains('\\'))
            name = image[(image.LastIndexOf('\\') + 1)..];

        handler(this, new ProcessStartedEventArgs
        {
            ProcessId = data.ProcessID,
            ParentProcessId = data.ParentID,
            ProcessName = name,
            ImagePath = image,
            CommandLine = string.IsNullOrEmpty(data.CommandLine) ? null : data.CommandLine,
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
            Source = "ETW",
            SessionId = session
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
