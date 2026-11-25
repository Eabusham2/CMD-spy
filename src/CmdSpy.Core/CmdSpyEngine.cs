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
public sealed class CmdSpyEngine : IDisposable, ICaptureFeed
{
    private readonly CmdSpyOptions _options;
    private readonly EventStore _store;
    private IProcessWatcher? _watcher;

    private HashSet<string> _targetStems;
    private long _sequence;

    // PIDs of cmd popups currently alive, mapped to their captured event so we
    // can attribute children and compute lifetime on exit.
    private readonly ConcurrentDictionary<int, CmdEvent> _active = new();

    // Boot time is fixed for the life of the machine, so resolve it once instead
    // of recomputing (and re-deriving a slightly different value) per event.
    private readonly DateTimeOffset _bootTimeLocal = SystemTimings.BootTimeLocal;

    // ---- Investigation & deeper tracking -----------------------------------
    // Every process seen starting (plus a snapshot taken at start-up), kept after
    // it exits, so parents, launch chains and referenced PIDs can always be named.
    private readonly ProcessCache _processes;
    private readonly Func<IProcessWatcher>? _watcherFactory;
    private Investigator? _investigator;
    private EtwNetworkWatcher? _network;

    // Children, grandchildren... of tracked popups, mapped to the outermost
    // popup they belong to, so their actions and connections are attributed.
    private readonly ConcurrentDictionary<int, DescendantLink> _descendants = new();
    private readonly object _descendantLimitLock = new();
    private int _trackedDescendantCount;

    // Popups that exited before their analysis finished: the human-readable
    // final record waits for the analysis so it can include it.
    private readonly ConcurrentDictionary<Guid, CmdEvent> _exitPendingAnalysis = new();
    private readonly ConcurrentDictionary<Guid, byte> _finalWritten = new();
    private readonly ConcurrentDictionary<Guid, byte> _reanalysisRequested = new();

    // Connections reported before the matching process-start event was handled
    // (network and process events come from separate ETW sessions).
    private readonly ConcurrentDictionary<int, List<NetworkConnectionInfo>> _pendingConnections = new();
    private readonly object _pendingConnectionLimitLock = new();
    private DateTimeOffset _pendingConnectionsPrunedAt;

    // Admission is counted before expensive capture enrichment or persistence.
    // The dictionary is reset every minute, so attacker-controlled event volume
    // cannot create unbounded limiter state.
    private readonly object _captureRateLock = new();
    private readonly Dictionary<int, int> _capturesBySession = new();
    private DateTimeOffset _captureWindowStart;
    private int _capturesThisWindow;
    private bool _captureLimitReported;
    private int _investigationLimitReported;
    private int _descendantLimitReported;

    private sealed record DescendantLink(CmdEvent Root, int Depth, DateTimeOffset StartUtc);

    // Popups and actions that exited a moment ago. Kernel network events come
    // through their own trace session and can be delivered after the exit was
    // handled; these let a late connection still reach the right popup.
    private readonly ConcurrentDictionary<int, ExitedLink> _recentlyExited = new();
    private readonly ConcurrentDictionary<int, ExitedLink> _recentlyExitedDescendants = new();
    private static readonly TimeSpan RecentExitWindow = TimeSpan.FromSeconds(60);

    private sealed record ExitedLink(CmdEvent Event, DateTimeOffset StartUtc, DateTimeOffset ExitUtc);

    public CmdSpyEngine(CmdSpyOptions? options = null)
    {
        _options = options ?? new CmdSpyOptions();
        _store = new EventStore(_options.LogDirectory, _options.MaxLogFileBytes,
            _options.LogRetentionDays, _options.MinLogVolumeFreeBytes, _options.MaxLogDirectoryBytes,
            _options.MaxLogRecordBytes);
        _store.WriteRejected += message => Status?.Invoke(this, message);
        _targetStems = _options.TargetStems();
        _processes = new ProcessCache(_options.ProcessHistoryRetention);
    }

    /// <param name="watcherFactory">Supplies the process watcher instead of ETW/WMI (used by tests).</param>
    public CmdSpyEngine(CmdSpyOptions? options, Func<IProcessWatcher> watcherFactory) : this(options)
    {
        _watcherFactory = watcherFactory;
    }

    public bool IsRunning { get; private set; }
    public string? WatcherName => _watcher?.Name;
    public EventStore Store => _store;
    public CmdSpyOptions Options => _options;

    /// <summary>History of every process seen (launch chains, referenced PIDs).</summary>
    public ProcessCache Processes => _processes;

    /// <summary>The background investigator while monitoring (null if investigation is off).</summary>
    public Investigator? Investigator => _investigator;

    /// <summary>Name of the event-based network source, if it is running.</summary>
    public string? NetworkWatcherName => _network?.Name;

    /// <summary>Process events the kernel dropped (ETW only). Zero means nothing was missed.</summary>
    public int? EventsLost => (_watcher as EtwProcessWatcher)?.EventsLost;

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

        // Remember everything already running, so parents and referenced PIDs
        // that predate monitoring can still be identified. This runs in the
        // background so capture starts at once (the snapshot can take a few
        // seconds at boot); analyses wait for it before they begin.
        System.Threading.Tasks.Task? warmUp = null;
        if (_options.SeedProcessCache)
        {
            warmUp = System.Threading.Tasks.Task.Run(() =>
            {
                try { _processes.Seed(ProcessSnapshot.SnapshotAll()); } catch { }
            });
        }

        if (_options.InvestigateEvents)
        {
            System.Threading.Interlocked.Exchange(ref _investigationLimitReported, 0);
            _investigator = new Investigator(_processes, _options);
            _investigator.Completed += OnInvestigationCompleted;
            _investigator.Start(warmUp);
        }
        System.Threading.Interlocked.Exchange(ref _descendantLimitReported, 0);

        _watcher = _watcherFactory is null ? StartBestWatcher() : StartWatcher(_watcherFactory());
        IsRunning = true;

        if (_options.CaptureNetworkEvents && _watcher is EtwProcessWatcher)
            StartNetworkWatcher();

        Status?.Invoke(this, $"Monitoring started via {_watcher.Name}. Logs: {_store.Directory}");
    }

    private IProcessWatcher StartWatcher(IProcessWatcher watcher)
    {
        watcher.ProcessStarted += OnProcessStarted;
        watcher.ProcessStopped += OnProcessStopped;
        watcher.Start();
        return watcher;
    }

    private void StartNetworkWatcher()
    {
        var network = new EtwNetworkWatcher(_options.EtwNetworkSessionName);
        try
        {
            network.ConnectionObserved += OnConnectionObserved;
            network.Start();
            _network = network;
        }
        catch (Exception ex)
        {
            try { network.Dispose(); } catch { }
            Status?.Invoke(this, $"Event-based network capture unavailable ({ex.Message}); using connection snapshots only.");
        }
    }

    /// <summary>
    /// Prefers ETW (the only source that reliably carries the command line for a
    /// process that exits in a millisecond) and falls back to WMI if the ETW
    /// kernel session cannot be opened — typically because CMD-spy is not running
    /// elevated.
    /// </summary>
    private IProcessWatcher StartBestWatcher()
    {
        var etw = new EtwProcessWatcher(_options.EtwSessionName);
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
            // Remember every process, so its details survive after it exits.
            _processes.RecordStart(e);

            var stem = CmdSpyOptions.Stem(e.ImagePath ?? e.ProcessName);
            bool isTarget = _targetStems.Contains(stem);

            if (isTarget)
            {
                if (TryAdmitCapture(e.SessionId, e.TimestampUtc, out var reportLimit))
                    CaptureCmdPopup(e);
                else if (reportLimit)
                    Status?.Invoke(this, "Capture rate limit reached; additional target launches are being dropped for this minute.");
            }

            // Independently, if this new process is a child of a cmd popup we are
            // already tracking, record it as one of that popup's "actions" —
            // and if it descends from one further up (a grandchild...), record it
            // there too. Each link is checked against start times, so a recycled
            // PID can't attach a process to the wrong popup.
            if (_options.CaptureChildren && e.ParentProcessId > 0)
            {
                CmdEvent? direct = null;
                if (_active.TryGetValue(e.ParentProcessId, out var parentEvent))
                {
                    if (IsSameIncarnation(e.ParentProcessId, parentEvent.TimestampUtc, e.TimestampUtc))
                        direct = parentEvent;
                    else
                        _active.TryRemove(new KeyValuePair<int, CmdEvent>(e.ParentProcessId, parentEvent));
                }

                DescendantLink? outer = null;
                if (_descendants.TryGetValue(e.ParentProcessId, out var link) &&
                    IsSameIncarnation(e.ParentProcessId, link.StartUtc, e.TimestampUtc))
                    outer = link;
                else if (link is not null)
                    TryRemoveDescendant(e.ParentProcessId, out _);

                bool directAttached = direct is not null && AttachChild(direct, e);
                bool outerAttached = outer is not null &&
                    (ReferenceEquals(outer.Root, direct)
                        ? directAttached
                        : AttachChild(outer.Root, e, outer.Depth + 1));

                if (outer is not null && outerAttached)
                    TrackDescendant(e.ProcessId, new DescendantLink(outer.Root, outer.Depth + 1, e.TimestampUtc));
                else if (direct is not null && directAttached)
                    TrackDescendant(e.ProcessId, new DescendantLink(direct, 1, e.TimestampUtc));
            }
        }
        catch (Exception ex)
        {
            Status?.Invoke(this, $"Error handling process start: {ex.Message}");
        }
    }

    private bool TryAdmitCapture(int sessionId, DateTimeOffset timestampUtc, out bool reportLimit)
    {
        lock (_captureRateLock)
        {
            if (_captureWindowStart == default || timestampUtc < _captureWindowStart ||
                timestampUtc - _captureWindowStart >= TimeSpan.FromMinutes(1))
            {
                _captureWindowStart = timestampUtc;
                _capturesThisWindow = 0;
                _capturesBySession.Clear();
                _captureLimitReported = false;
            }

            int globalLimit = Math.Max(1, _options.MaxCapturedEventsPerMinute);
            int sessionLimit = Math.Max(1, _options.MaxCapturedEventsPerSessionPerMinute);
            _capturesBySession.TryGetValue(sessionId, out var sessionCount);
            if (_capturesThisWindow >= globalLimit || sessionCount >= sessionLimit)
            {
                reportLimit = !_captureLimitReported;
                _captureLimitReported = true;
                return false;
            }

            _capturesThisWindow++;
            _capturesBySession[sessionId] = sessionCount + 1;
            reportLimit = false;
            return true;
        }
    }

    /// <summary>
    /// True when the process with <paramref name="pid"/> that was alive at
    /// <paramref name="asOfUtc"/> is the one that started at
    /// <paramref name="expectedStartUtc"/> — i.e. the PID wasn't recycled.
    /// </summary>
    private bool IsSameIncarnation(int pid, DateTimeOffset expectedStartUtc, DateTimeOffset asOfUtc)
    {
        var record = _processes.TryGet(pid, asOfUtc);
        if (record is null || record.StartTimeUtc == DateTimeOffset.MinValue) return true;
        return (record.StartTimeUtc - expectedStartUtc).Duration() <= ProcessCache.Skew;
    }

    private void CaptureCmdPopup(ProcessStartedEventArgs e)
    {
        var boot = _bootTimeLocal;
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

        // ETW usually reports only the short image name. Ask Windows for the full
        // path while the process is (normally) still running — a trusted source,
        // unlike the command line, which a program can fake.
        if (!ProcessImageResolver.IsRooted(ev.ImagePath))
        {
            var (livePath, liveStart) = ProcessImageResolver.TryQueryLive(e.ProcessId);
            if (livePath is not null && (liveStart is null || (liveStart.Value - e.TimestampUtc).Duration() <= ProcessCache.Skew))
            {
                ev.ImagePath = ProcessImageResolver.NormalizeKernelPath(livePath);
                var file = ev.ImagePath?[(ev.ImagePath.LastIndexOfAny(new[] { '\\', '/' }) + 1)..];
                if (!string.IsNullOrEmpty(file) && CmdSpyOptions.Stem(file).Equals(CmdSpyOptions.Stem(ev.ProcessName), StringComparison.OrdinalIgnoreCase))
                    ev.ProcessName = file;
            }
        }

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
        if (ev.SessionId < 0 && e.SessionId >= 0) ev.SessionId = e.SessionId;   // gone too fast for WMI: use ETW's

        // Cause: enrich the parent process — from the process history first, so
        // the details survive even if the parent has already exited, and a newer
        // process that reused the PID can't be mistaken for it.
        if (_options.CaptureParentDetails && e.ParentProcessId > 0)
        {
            var parent = _processes.TryGet(e.ParentProcessId, e.TimestampUtc, requireAlive: true);
            if (parent is null || string.IsNullOrEmpty(parent.CommandLine))
            {
                var live = ProcessSnapshot.TryGetRecord(e.ParentProcessId);
                if (live is not null && (live.StartTimeUtc == DateTimeOffset.MinValue || live.StartTimeUtc <= e.TimestampUtc + ProcessCache.Skew))
                    parent = live;
            }
            if (parent is not null)
            {
                ev.ParentProcessName = parent.Name;
                ev.ParentImagePath = ProcessImageResolver.IsRooted(parent.ImagePath)
                    ? parent.ImagePath
                    : ProcessImageResolver.Resolve(parent.ProcessId, parent.ImagePath, parent.Name, parent.CommandLine, parent.StartTimeUtc) ?? parent.ImagePath;
                ev.ParentCommandLine = parent.CommandLine;
            }
        }

        // Networking snapshot.
        if (_options.CaptureNetwork)
            ev.NetworkConnections = NetworkInspector.GetConnectionsForPid(
                e.ProcessId, Math.Max(1, _options.MaxNetworkConnectionsPerEvent));

        _active[e.ProcessId] = ev;
        EvictStaleTracking(e.TimestampUtc);
        _store.Append(ev);
        EventCaptured?.Invoke(this, ev);

        DrainPendingConnections(e.ProcessId, ev, e.TimestampUtc);
        QueueInvestigation(ev);
    }

    /// <summary>
    /// Drops tracked popups whose exit we never observed and that are older than
    /// the configured window. Without this the active map grows for the life of
    /// the session, and a recycled PID could attach children to a stale event.
    /// </summary>
    private void EvictStaleTracking(DateTimeOffset nowUtc)
    {
        var window = _options.ActiveTrackingWindow;
        if (window <= TimeSpan.Zero) return;

        foreach (var pair in _active)
        {
            if (nowUtc - pair.Value.TimestampUtc > window)
                _active.TryRemove(pair.Key, out _);
        }
        foreach (var pair in _descendants)
        {
            if (nowUtc - pair.Value.StartUtc > window)
                TryRemoveDescendant(pair.Key, out _);
        }
        PruneRecentlyExited(nowUtc);
        if (_finalWritten.Count > 20_000) _finalWritten.Clear();
    }

    private bool AttachChild(CmdEvent parentEvent, ProcessStartedEventArgs child, int depth = 1)
    {
        int detailLimit = Math.Max(1, _options.MaxDescendantsPerEvent);
        int childCount;
        lock (parentEvent)
            if (parentEvent.ChildProcesses.Count >= detailLimit) return false;

        var info = new ProcessInfo
        {
            ProcessId = child.ProcessId,
            ProcessName = child.ProcessName,
            ImagePath = child.ImagePath,
            CommandLine = child.CommandLine,
            ObservedAtUtc = child.TimestampUtc,
            ParentProcessId = child.ParentProcessId,
            Depth = depth,
            StartTimeUtc = child.TimestampUtc,
            Source = child.Source
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
            // A popup that spawns hundreds of processes (a build script...) is
            // capped so one event can't grow without bound.
            if (parentEvent.ChildProcesses.Count >= detailLimit)
                return false;

            parentEvent.ChildProcesses.Add(info);
            childCount = parentEvent.ChildProcesses.Count;

            // A cmd popup that opened a socket is worth re-snapshotting.
            if (_options.CaptureNetwork)
            {
                var conns = NetworkInspector.GetConnectionsForPid(parentEvent.ProcessId,
                    Math.Max(1, _options.MaxNetworkConnectionsPerEvent));
                if (conns.Count > parentEvent.NetworkConnections.Count)
                    parentEvent.NetworkConnections = conns;
            }
        }

        if (ShouldPersistDetail(childCount, detailLimit))
            _store.AppendUpdate(parentEvent, "child-process");
        EventUpdated?.Invoke(this, parentEvent);

        DrainPendingConnections(child.ProcessId, parentEvent, child.TimestampUtc);
        QueueInvestigation(parentEvent);   // re-analyse with the new action
        return true;
    }

    private void TrackDescendant(int processId, DescendantLink link)
    {
        bool reportLimit = false;
        lock (_descendantLimitLock)
        {
            if (_descendants.ContainsKey(processId))
            {
                _descendants[processId] = link;
                return;
            }
            if (_trackedDescendantCount >= Math.Max(1, _options.MaxTrackedDescendantProcesses))
            {
                reportLimit = true;
            }
            else
            {
                if (_descendants.TryAdd(processId, link)) _trackedDescendantCount++;
            }
        }
        if (reportLimit && System.Threading.Interlocked.Exchange(ref _descendantLimitReported, 1) == 0)
            Status?.Invoke(this, "Descendant tracking limit reached; additional process relationships are being skipped.");
    }

    private bool TryRemoveDescendant(int processId, out DescendantLink? link)
    {
        lock (_descendantLimitLock)
        {
            if (!_descendants.TryRemove(processId, out link)) return false;
            _trackedDescendantCount--;
            return true;
        }
    }

    private void OnProcessStopped(object? sender, ProcessStoppedEventArgs e)
    {
        _processes.RecordStop(e);
        RecordDescendantExit(e);

        if (!_active.TryRemove(e.ProcessId, out var ev)) return;
        _recentlyExited[e.ProcessId] = new ExitedLink(ev, ev.TimestampUtc, e.TimestampUtc);

        bool analysisPending;
        lock (ev)
        {
            ev.ExitedAtUtc = e.TimestampUtc;
            ev.LifetimeMilliseconds = (e.TimestampUtc - ev.TimestampUtc).TotalMilliseconds;
            ev.ExitCode = e.ExitCode;

            // A fast popup often exits before its analysis lands; the finalized
            // log block then waits for the analysis so it can include it.
            analysisPending = _investigator is { IsRunning: true } investigator &&
                investigator.IsPending(ev.Id) && ev.Investigation is null;
            if (analysisPending) _exitPendingAnalysis[ev.Id] = ev;
        }

        if (analysisPending)
            _store.AppendUpdate(ev, "exit-pending-analysis");
        else
            WriteExit(ev);
        EventUpdated?.Invoke(this, ev);
    }

    /// <summary>Writes the exit snapshot; the first one also writes the finalized human-readable block.</summary>
    private void WriteExit(CmdEvent ev) =>
        _store.AppendUpdate(ev, _finalWritten.TryAdd(ev.Id, 0) ? "exit" : "exit-update");

    /// <summary>Marks a descendant's exit in the popup(s) it belongs to (persisted with the next snapshot).</summary>
    private void RecordDescendantExit(ProcessStoppedEventArgs e)
    {
        var owners = new List<CmdEvent>(2);
        if (TryRemoveDescendant(e.ProcessId, out var link) && link is not null)
        {
            owners.Add(link.Root);
            RememberExitedDescendant(e.ProcessId, new ExitedLink(link.Root, link.StartUtc, e.TimestampUtc));
        }
        var record = _processes.TryGet(e.ProcessId, e.TimestampUtc);
        if (record is not null && _active.TryGetValue(record.ParentProcessId, out var directParent) && !owners.Contains(directParent))
            owners.Add(directParent);

        foreach (var owner in owners)
        {
            lock (owner)
            {
                for (int i = owner.ChildProcesses.Count - 1; i >= 0; i--)
                {
                    var child = owner.ChildProcesses[i];
                    if (child.ProcessId == e.ProcessId && child.ExitedAtUtc is null)
                    {
                        child.ExitedAtUtc = e.TimestampUtc;
                        child.ExitCode = e.ExitCode;
                        break;
                    }
                }
            }
        }
    }

    private void RememberExitedDescendant(int processId, ExitedLink link)
    {
        lock (_descendantLimitLock)
        {
            int limit = Math.Max(1, _options.MaxTrackedDescendantProcesses);
            if (_recentlyExitedDescendants.Count >= limit) PruneRecentlyExited(link.ExitUtc);
            if (_recentlyExitedDescendants.Count < limit)
                _recentlyExitedDescendants[processId] = link;
        }
    }

    private void OnInvestigationCompleted(CmdEvent ev, Investigation investigation)
    {
        bool writeFinal;
        lock (ev)
        {
            ev.Investigation = investigation;
            // If a newer pass is already queued (a late action arrived), the
            // finalized block waits for that one instead.
            writeFinal = !(_investigator?.IsQueued(ev.Id) ?? false) && _exitPendingAnalysis.TryRemove(ev.Id, out _);
        }

        if (writeFinal) WriteExit(ev);
        else if (_reanalysisRequested.TryRemove(ev.Id, out _))
            _store.AppendUpdate(ev, "reanalysis");   // asked for by the user: add the new report to the .log as well
        else _store.AppendUpdate(ev, "analysis");
        EventUpdated?.Invoke(this, ev);
    }

    /// <summary>Queues a capture (live or loaded from today's log) for a fresh analysis.</summary>
    public bool Reanalyze(CmdEvent ev)
    {
        if (_investigator is null) return false;
        _reanalysisRequested[ev.Id] = 0;
        if (QueueInvestigation(ev)) return true;
        _reanalysisRequested.TryRemove(ev.Id, out _);
        return false;
    }

    /// <summary>
    /// Imports launches of the target programs recorded in the Windows event
    /// logs since <paramref name="sinceUtc"/> (popups from before monitoring
    /// started), logs them, and queues each for the full investigation — its
    /// finalized log block is written once the analysis is done.
    /// </summary>
    public IReadOnlyList<CmdEvent> ImportHistory(DateTimeOffset sinceUtc, IEnumerable<CmdEvent>? alreadyKnown = null, int max = 500)
    {
        var history = _investigator?.History ?? new WindowsEventHistory();
        List<CmdEvent> known;
        try { known = (alreadyKnown ?? _store.ReadToday()).ToList(); }
        catch { known = new List<CmdEvent>(); }

        var imported = HistoryImporter.Read(history, _options, sinceUtc, known, max);
        foreach (var ev in imported)
        {
            ev.SequenceNumber = System.Threading.Interlocked.Increment(ref _sequence);
            _store.Append(ev);
            EventCaptured?.Invoke(this, ev);
            if (_investigator is { IsRunning: true })
            {
                _exitPendingAnalysis[ev.Id] = ev;   // final block once analysed
                if (!QueueInvestigation(ev))
                {
                    _exitPendingAnalysis.TryRemove(ev.Id, out _);
                    WriteExit(ev);
                }
            }
        }
        return imported;
    }

    // ------------------------------------------------------------- network --

    /// <summary>A live connection reported by the ETW network session.</summary>
    internal void OnConnectionObserved(int pid, NetworkConnectionInfo connection)
    {
        if (!_options.CaptureNetwork || !_options.CaptureNetworkEvents) return;

        var targets = new List<CmdEvent>(2);
        if (_active.TryGetValue(pid, out var own)) targets.Add(own);
        else if (_recentlyExited.TryGetValue(pid, out var gone) && Within(connection, gone)) targets.Add(gone.Event);

        if (_descendants.TryGetValue(pid, out var link))
        {
            if (!targets.Contains(link.Root)) targets.Add(link.Root);
        }
        else if (_recentlyExitedDescendants.TryGetValue(pid, out var goneChild) && Within(connection, goneChild) &&
                 !targets.Contains(goneChild.Event))
        {
            targets.Add(goneChild.Event);
        }

        if (targets.Count == 0)
        {
            // The process-start event may simply not have been handled yet.
            BufferConnection(pid, connection);
            return;
        }
        foreach (var target in targets) AddConnection(target, connection);
    }

    private void AddConnection(CmdEvent target, NetworkConnectionInfo connection)
    {
        bool added;
        int count;
        int detailLimit = Math.Max(1, _options.MaxNetworkConnectionsPerEvent);
        lock (target)
        {
            added = target.NetworkConnections.Count < detailLimit &&
                !target.NetworkConnections.Any(c => SameEndpoint(c, connection));
            if (added) target.NetworkConnections.Add(connection);
            count = target.NetworkConnections.Count;
        }
        if (!added) return;
        if (ShouldPersistDetail(count, detailLimit))
            _store.AppendUpdate(target, "network");
        EventUpdated?.Invoke(this, target);
    }

    /// <summary>
    /// Persists exponentially spaced detail snapshots plus the configured cap.
    /// Ordinary events keep every early update; exit and analysis paths still
    /// force a final full snapshot.
    /// </summary>
    private static bool ShouldPersistDetail(int count, int limit) =>
        count <= 16 || count == limit || (count > 0 && (count & (count - 1)) == 0);

    /// <summary>True if the connection happened while that (now exited) process was alive.</summary>
    private static bool Within(NetworkConnectionInfo connection, ExitedLink link) =>
        connection.ObservedAtUtc is not { } at ||
        (at >= link.StartUtc - ProcessCache.Skew && at <= link.ExitUtc + ProcessCache.Skew);

    private void PruneRecentlyExited(DateTimeOffset nowUtc)
    {
        foreach (var map in new[] { _recentlyExited, _recentlyExitedDescendants })
            foreach (var pair in map)
                if (nowUtc - pair.Value.ExitUtc > RecentExitWindow)
                    map.TryRemove(pair.Key, out _);
    }

    private static bool SameEndpoint(NetworkConnectionInfo a, NetworkConnectionInfo b) =>
        a.OwningPid == b.OwningPid &&
        string.Equals(a.Protocol, b.Protocol, StringComparison.OrdinalIgnoreCase) &&
        a.LocalPort == b.LocalPort &&
        a.RemoteAddress == b.RemoteAddress &&
        a.RemotePort == b.RemotePort;

    private void BufferConnection(int pid, NetworkConnectionInfo connection)
    {
        if (!_pendingConnections.TryGetValue(pid, out var list))
        {
            lock (_pendingConnectionLimitLock)
            {
                if (!_pendingConnections.TryGetValue(pid, out list))
                {
                    var now = connection.ObservedAtUtc ?? DateTimeOffset.UtcNow;
                    if (_pendingConnections.Count >= 1_000 &&
                        now - _pendingConnectionsPrunedAt >= TimeSpan.FromSeconds(15))
                    {
                        PrunePendingConnections();
                        _pendingConnectionsPrunedAt = now;
                    }
                    if (_pendingConnections.Count >= 1_000) return;
                    list = _pendingConnections.GetOrAdd(pid, _ => new List<NetworkConnectionInfo>());
                }
            }
        }
        lock (list)
        {
            if (list.Count < 20) list.Add(connection);
        }
    }

    private void DrainPendingConnections(int pid, CmdEvent target, DateTimeOffset startUtc)
    {
        if (!_pendingConnections.TryRemove(pid, out var list)) return;
        List<NetworkConnectionInfo> buffered;
        lock (list) buffered = list.ToList();
        foreach (var c in buffered)
            if (c.ObservedAtUtc is null || c.ObservedAtUtc >= startUtc - ProcessCache.Skew)
                AddConnection(target, c);
    }

    private void PrunePendingConnections()
    {
        var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(15);
        foreach (var pair in _pendingConnections)
        {
            bool stale;
            lock (pair.Value) stale = pair.Value.All(c => c.ObservedAtUtc is null || c.ObservedAtUtc < cutoff);
            if (stale) _pendingConnections.TryRemove(pair.Key, out _);
        }
    }

    private bool QueueInvestigation(CmdEvent ev)
    {
        var investigator = _investigator;
        if (investigator is null || !investigator.IsRunning) return false;
        if (investigator.Enqueue(ev)) return true;
        if (System.Threading.Interlocked.Exchange(ref _investigationLimitReported, 1) == 0)
            Status?.Invoke(this, "Investigation queue is full; new analyses are being skipped until capacity is available.");
        return false;
    }

    public void Stop()
    {
        if (!IsRunning) return;
        try { _watcher?.Stop(); } catch { }
        try { _watcher?.Dispose(); } catch { }
        _watcher = null;

        try { _network?.Dispose(); } catch { }
        _network = null;

        // Let queued analyses finish briefly, then write any final records still waiting.
        _investigator?.Stop(TimeSpan.FromSeconds(3));
        _investigator = null;
        foreach (var pending in _exitPendingAnalysis.Values) WriteExit(pending);
        _exitPendingAnalysis.Clear();

        IsRunning = false;
        _active.Clear();
        lock (_descendantLimitLock)
        {
            _descendants.Clear();
            _trackedDescendantCount = 0;
        }
        _pendingConnections.Clear();
        _reanalysisRequested.Clear();
        _recentlyExited.Clear();
        _recentlyExitedDescendants.Clear();
        Status?.Invoke(this, "Monitoring stopped.");
    }

    public void Dispose() => Stop();
}
