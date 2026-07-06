using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using CmdSpy.Core.Logging;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;

namespace CmdSpy.Core;

/// <summary>
/// The heart of CMD-spy. It attaches to a real-time process watcher, filters for
/// the configured "cmd popup" executables, enriches each sighting (cause,
/// networking, user), persists it, and keeps tracking it so that child processes
/// ("actions") and the eventual exit/lifetime are recorded too.
///
/// It picks the best available watcher automatically: ETW first (captures the
/// command line even for millisecond-lived windows), falling back to WMI.
/// </summary>
public sealed class CmdSpyEngine : IDisposable
{
    private readonly CmdSpyOptions _options;
    private readonly EventStore _store;
    private IProcessWatcher? _watcher;

    private HashSet<string> _targetStems;
    private long _sequence;

    // PIDs of cmd popups currently alive, mapped to their captured event so we
    // can attribute children and compute lifetime on exit.
    private readonly ConcurrentDictionary<int, CmdEvent> _active = new();

    public CmdSpyEngine(CmdSpyOptions? options = null)
    {
        _options = options ?? new CmdSpyOptions();
        _store = new EventStore(_options.LogDirectory);
        _targetStems = _options.TargetStems();
    }

    public bool IsRunning { get; private set; }
    public string? WatcherName => _watcher?.Name;
    public EventStore Store => _store;
    public CmdSpyOptions Options => _options;

    /// <summary>Raised when a new cmd popup is captured (creation).</summary>
    public event EventHandler<CmdEvent>? EventCaptured;

    /// <summary>Raised when an existing event gains detail (child, network, exit).</summary>
    public event EventHandler<CmdEvent>? EventUpdated;

    /// <summary>Raised with a human-readable status/diagnostic message.</summary>
    public event EventHandler<string>? Status;

    /// <summary>Refresh the target set after the caller mutates options.</summary>
    public void RefreshTargets() => _targetStems = _options.TargetStems();

    public void Start()
    {
        if (IsRunning) return;

        _watcher = StartBestWatcher();
        IsRunning = true;
        Status?.Invoke(this, $"Monitoring started via {_watcher.Name}. Logs: {_store.Directory}");
    }

    /// <summary>
    /// Prefers ETW (the only source that reliably carries the command line for a
    /// process that exits in a millisecond) and falls back to WMI if the ETW
    /// kernel session cannot be opened — typically because CMD-spy is not running
    /// elevated.
    /// </summary>
    private IProcessWatcher StartBestWatcher()
    {
        var etw = new EtwProcessWatcher();
        try
        {
            etw.ProcessStarted += OnProcessStarted;
            etw.ProcessStopped += OnProcessStopped;
            etw.Start();          // throws immediately if not elevated / unavailable
            return etw;
        }
        catch (Exception ex)
        {
            try { etw.Dispose(); } catch { }
            Status?.Invoke(this,
                $"ETW unavailable ({ex.GetType().Name}: {ex.Message}). Falling back to WMI. " +
                "Command lines for very short-lived processes may be missed. " +
                "Run CMD-spy as Administrator for full fidelity.");

            var wmi = new WmiProcessWatcher();
            wmi.ProcessStarted += OnProcessStarted;
            wmi.ProcessStopped += OnProcessStopped;
            wmi.Start();
            return wmi;
        }
    }

    private void OnProcessStarted(object? sender, ProcessStartedEventArgs e)
    {
        try
        {
            var stem = CmdSpyOptions.Stem(e.ImagePath ?? e.ProcessName);
            bool isTarget = _targetStems.Contains(stem);

            if (isTarget)
                CaptureCmdPopup(e);

            // Independently, if this new process is a child of a cmd popup we are
            // already tracking, record it as one of that popup's "actions".
            if (_options.CaptureChildren &&
                e.ParentProcessId > 0 &&
                _active.TryGetValue(e.ParentProcessId, out var parentEvent))
            {
                AttachChild(parentEvent, e);
            }
        }
        catch (Exception ex)
        {
            Status?.Invoke(this, $"Error handling process start: {ex.Message}");
        }
    }

    private void CaptureCmdPopup(ProcessStartedEventArgs e)
    {
        var boot = SystemTimings.BootTimeLocal;
        var uptime = SystemTimings.Uptime;
        var localTime = e.TimestampUtc.ToLocalTime();

        var ev = new CmdEvent
        {
            SequenceNumber = System.Threading.Interlocked.Increment(ref _sequence),
            TimestampUtc = e.TimestampUtc,
            TimestampLocal = localTime,
            SystemBootTimeLocal = boot,
            TimeSinceBoot = localTime - boot,
            SystemUptimeSeconds = uptime.TotalSeconds,
            ProcessId = e.ProcessId,
            ProcessName = e.ProcessName,
            ImagePath = e.ImagePath,
            CommandLine = e.CommandLine,
            ParentProcessId = e.ParentProcessId,
            CaptureSource = e.Source
        };

        // Recover the command line if the detector didn't provide one (WMI path).
        if (string.IsNullOrWhiteSpace(ev.CommandLine))
        {
            var self = ProcessSnapshot.TryGet(e.ProcessId);
            if (self is not null)
            {
                ev.CommandLine ??= self.CommandLine;
                ev.ImagePath ??= self.ImagePath;
            }
        }

        // Owner / session.
        var (user, session) = ProcessSnapshot.TryGetOwner(e.ProcessId);
        ev.UserName = user;
        ev.SessionId = session;

        // Cause: enrich the parent process.
        if (_options.CaptureParentDetails && e.ParentProcessId > 0)
        {
            var parent = ProcessSnapshot.TryGet(e.ParentProcessId);
            if (parent is not null)
            {
                ev.ParentProcessName = parent.ProcessName;
                ev.ParentImagePath = parent.ImagePath;
                ev.ParentCommandLine = parent.CommandLine;
            }
        }

        // Networking snapshot.
        if (_options.CaptureNetwork)
            ev.NetworkConnections = NetworkInspector.GetConnectionsForPid(e.ProcessId);

        _active[e.ProcessId] = ev;
        _store.Append(ev);
        EventCaptured?.Invoke(this, ev);
    }

    private void AttachChild(CmdEvent parentEvent, ProcessStartedEventArgs child)
    {
        var info = new ProcessInfo
        {
            ProcessId = child.ProcessId,
            ProcessName = child.ProcessName,
            ImagePath = child.ImagePath,
            CommandLine = child.CommandLine,
            ObservedAtUtc = child.TimestampUtc
        };

        // Fill in the command line if the detector didn't hand us one.
        if (string.IsNullOrWhiteSpace(info.CommandLine))
        {
            var snap = ProcessSnapshot.TryGet(child.ProcessId);
            if (snap is not null)
            {
                info.CommandLine = snap.CommandLine;
                info.ImagePath ??= snap.ImagePath;
            }
        }

        lock (parentEvent)
        {
            parentEvent.ChildProcesses.Add(info);

            // A cmd popup that opened a socket is worth re-snapshotting.
            if (_options.CaptureNetwork)
            {
                var conns = NetworkInspector.GetConnectionsForPid(parentEvent.ProcessId);
                if (conns.Count > parentEvent.NetworkConnections.Count)
                    parentEvent.NetworkConnections = conns;
            }
        }

        _store.AppendUpdate(parentEvent, "child-process");
        EventUpdated?.Invoke(this, parentEvent);
    }

    private void OnProcessStopped(object? sender, ProcessStoppedEventArgs e)
    {
        if (!_active.TryRemove(e.ProcessId, out var ev)) return;

        lock (ev)
        {
            ev.ExitedAtUtc = e.TimestampUtc;
            ev.LifetimeMilliseconds = (e.TimestampUtc - ev.TimestampUtc).TotalMilliseconds;
            ev.ExitCode = e.ExitCode;
        }

        _store.AppendUpdate(ev, "exit");
        EventUpdated?.Invoke(this, ev);
    }

    public void Stop()
    {
        if (!IsRunning) return;
        try { _watcher?.Stop(); } catch { }
        try { _watcher?.Dispose(); } catch { }
        _watcher = null;
        IsRunning = false;
        _active.Clear();
        Status?.Invoke(this, "Monitoring stopped.");
    }

    public void Dispose() => Stop();
}
