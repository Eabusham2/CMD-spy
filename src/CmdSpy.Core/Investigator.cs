using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;

namespace CmdSpy.Core;

/// <summary>
/// Builds the <see cref="Investigation"/> for a captured popup on a background
/// thread, so the capture path stays fast enough to catch millisecond-lived
/// windows. For each capture it works out the launch chain, the processes the
/// command refers to, what the command does, signatures and hashes of every
/// program involved, the scheduled task behind it, related Windows event-log
/// history, suspicious indicators and an evidence-based risk verdict.
/// </summary>
public sealed class Investigator : IDisposable
{
    private readonly ProcessCache _processes;
    private readonly CmdSpyOptions _options;
    private readonly SignatureVerifier _signatures;
    private readonly ScheduledTaskCatalog _taskCatalog;
    private readonly WindowsEventHistory _history;
    private readonly ScheduledTaskCorrelator _tasks;
    private readonly ConcurrentDictionary<Guid, WorkItem> _queued = new();
    private readonly ConcurrentQueue<WorkItem> _backlog = new();
    private BlockingCollection<WorkItem>? _queue;
    private Thread? _worker;
    private CancellationTokenSource? _cancel;

    private sealed class WorkItem(CmdEvent ev, bool isBacklog, Action<CmdEvent, Investigation>? completed = null)
    {
        public CmdEvent Event { get; } = ev;
        public bool IsBacklog { get; } = isBacklog;
        public Action<CmdEvent, Investigation>? Completed { get; } = completed;
    }

    public Investigator(ProcessCache processes, CmdSpyOptions options, SignatureVerifier? signatures = null,
        ScheduledTaskCatalog? taskCatalog = null, WindowsEventHistory? history = null)
    {
        _processes = processes;
        _options = options;
        _signatures = signatures ?? new SignatureVerifier
        {
            ComputeHashes = options.ComputeFileHashes,
            AlwaysRecheck = options.AlwaysRecheckFileSignatures
        };
        _taskCatalog = taskCatalog ?? new ScheduledTaskCatalog();
        _history = history ?? new WindowsEventHistory();
        _tasks = new ScheduledTaskCorrelator(_taskCatalog, _history);
    }

    public ProcessCache Processes => _processes;
    public WindowsEventHistory History => _history;
    public ScheduledTaskCatalog TaskCatalog => _taskCatalog;
    public SignatureVerifier Signatures => _signatures;

    /// <summary>Raised on the investigator thread when an analysis finishes.</summary>
    public event Action<CmdEvent, Investigation>? Completed;

    // Promoting a backlog item leaves an obsolete token in that queue; count
    // only the current work items, not those tokens or an analysis in flight.
    public int Pending => _queued.Count;
    public bool IsRunning => _worker is not null;

    /// <summary>True while another analysis pass for this event is waiting in the queue.</summary>
    public bool IsQueued(Guid eventId) => _queued.ContainsKey(eventId);

    /// <param name="warmUp">Work to finish before the first analysis (e.g. the start-up process snapshot); capture is not held up by it.</param>
    public void Start(System.Threading.Tasks.Task? warmUp = null)
    {
        if (_worker is not null) return;
        _queue = new BlockingCollection<WorkItem>(new ConcurrentQueue<WorkItem>());
        _cancel = new CancellationTokenSource();
        var queue = _queue;
        var token = _cancel.Token;
        _worker = new Thread(() =>
        {
            try { warmUp?.Wait(TimeSpan.FromSeconds(30)); } catch { }
            Run(queue, token);
        })
        {
            IsBackground = true,
            Name = "CmdSpy-Investigator",
            Priority = ThreadPriority.BelowNormal
        };
        _worker.Start();
    }

    /// <summary>Queues an event for (re-)analysis, promoting any waiting automatic backlog pass.</summary>
    public void Enqueue(CmdEvent ev)
    {
        if (!_options.InvestigateEvents) return;
        var queue = _queue;
        if (queue is null || queue.IsAddingCompleted) return;
        var item = new WorkItem(ev, isBacklog: false);
        while (!_queued.TryAdd(ev.Id, item))
        {
            if (!_queued.TryGetValue(ev.Id, out var waiting)) continue;
            if (!waiting.IsBacklog) return;
            if (_queued.TryUpdate(ev.Id, item, waiting)) break;
        }
        try
        {
            queue.Add(item);
        }
        catch (InvalidOperationException)
        {
            _queued.TryRemove(new KeyValuePair<Guid, WorkItem>(ev.Id, item));
        }
    }

    /// <summary>
    /// Queues an older capture (e.g. loaded from today's log without a finished
    /// analysis) to be analysed when no live capture is waiting. A verdict that
    /// arrives before the work starts makes this automatic pass unnecessary.
    /// </summary>
    /// <param name="completed">An optional completion handler for this backlog pass only,
    /// used instead of <see cref="Completed"/>. A foreground request replaces both the
    /// waiting backlog pass and this handler.</param>
    public void EnqueueBacklog(CmdEvent ev, Action<CmdEvent, Investigation>? completed = null)
    {
        var queue = _queue;
        if (!_options.InvestigateEvents || queue is null || queue.IsAddingCompleted) return;
        lock (ev)
        {
            if (ev.Investigation is not null) return;
        }
        var item = new WorkItem(ev, isBacklog: true, completed);
        if (!_queued.TryAdd(ev.Id, item)) return;
        _backlog.Enqueue(item);
    }

    /// <summary>
    /// Applies an automatic GUI backfill only while no verdict has arrived from
    /// the service or another analysis. The check and assignment share the same
    /// event lock as LogFollower; this does not write the service's log files.
    /// Explicit reanalysis deliberately uses its ordinary completion handler.
    /// </summary>
    public static bool TryApplyBacklogResult(CmdEvent ev, Investigation investigation)
    {
        lock (ev)
        {
            if (ev.Investigation is not null) return false;
            ev.Investigation = investigation;
            return true;
        }
    }

    /// <summary>Stops accepting work and lets queued analyses finish for up to <paramref name="drainTimeout"/>.</summary>
    public void Stop(TimeSpan? drainTimeout = null)
    {
        var queue = _queue;
        var worker = _worker;
        if (queue is null) return;
        try { queue.CompleteAdding(); } catch (ObjectDisposedException) { }
        if (worker is not null && !worker.Join(drainTimeout ?? TimeSpan.FromSeconds(5)))
            _cancel?.Cancel();   // out of time: abandon what's left after the current analysis
        _worker = null;
        _queue = null;
        _cancel = null;
        _queued.Clear();
        _backlog.Clear();
    }

    public void Dispose() => Stop(TimeSpan.FromSeconds(1));

    private void Run(BlockingCollection<WorkItem> queue, CancellationToken token)
    {
        foreach (var item in Next(queue, token))
        {
            if (token.IsCancellationRequested) break;
            var ev = item.Event;
            // Removed before analysing, so a change during analysis queues a fresh pass.
            // An obsolete backlog token must not consume its promoted foreground pass.
            if (!_queued.TryRemove(new KeyValuePair<Guid, WorkItem>(ev.Id, item))) continue;
            if (item.IsBacklog)
            {
                lock (ev)
                {
                    if (ev.Investigation is not null) continue;
                }
            }
            Investigation investigation;
            try
            {
                investigation = Investigate(ev);
            }
            catch (Exception ex)
            {
                investigation = new Investigation { AnalyzedAtUtc = DateTimeOffset.UtcNow };
                investigation.Errors.Add($"Analysis failed: {ex.Message}");
            }
            try
            {
                (item.Completed ?? Completed)?.Invoke(ev, investigation);
            }
            catch
            {
                // A faulty subscriber must not stop the investigator.
            }
        }
    }

    /// <summary>Live captures first; the backlog only while nothing live is waiting (and not once stopping).</summary>
    private IEnumerable<WorkItem> Next(BlockingCollection<WorkItem> queue, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            WorkItem? item;
            try
            {
                bool idleWait = _backlog.IsEmpty || queue.IsAddingCompleted;
                if (!queue.TryTake(out item, idleWait ? 250 : 0))
                {
                    if (queue.IsAddingCompleted)
                    {
                        if (queue.IsCompleted) yield break;
                        continue;
                    }
                    if (!_backlog.TryDequeue(out item)) continue;
                }
            }
            catch (ObjectDisposedException)
            {
                yield break;
            }
            yield return item;
        }
    }

    // ------------------------------------------------------------ analysis --

    private sealed class Subject
    {
        public int ProcessId;
        public string Name = "";
        public string? ImagePath;
        public string? CommandLine;
        public int ParentProcessId;
        public string? ParentName;
        public string? ParentImage;
        public string? ParentCommandLine;
        public DateTimeOffset StartUtc;
        public DateTimeOffset? ExitUtc;
        public string CaptureSource = "";
        public int PreviousRevision;
        public List<ProcessInfo> Children = new();
    }

    /// <summary>Runs the full analysis synchronously (also used for "Re-analyse" and imports).</summary>
    public Investigation Investigate(CmdEvent ev)
    {
        Subject s;
        lock (ev) s = Snapshot(ev);

        var inv = new Investigation
        {
            AnalyzedAtUtc = DateTimeOffset.UtcNow,
            Revision = s.PreviousRevision + 1
        };

        Step(inv, "resolving the program path", () =>
            inv.ResolvedImagePath = ProcessImageResolver.Resolve(s.ProcessId, s.ImagePath, s.Name, s.CommandLine, s.StartUtc));

        Step(inv, "building the launch chain", () => inv.Ancestry = BuildAncestry(s, inv));

        ProcessInfo? launcher = null;
        Step(inv, "identifying the launcher", () => launcher = DetermineLauncher(inv.Ancestry, inv));

        var parsed = CommandParser.Parse(s.CommandLine, s.Name);

        Step(inv, "resolving referenced processes", () => inv.ReferencedProcesses = ResolveReferenced(parsed, s));

        Step(inv, "resolving action paths", () =>
        {
            foreach (var child in s.Children.Take(25))
                child.ImagePath = ProcessImageResolver.Resolve(child.ProcessId, child.ImagePath, child.ProcessName,
                    child.CommandLine, child.StartTimeUtc) ?? child.ImagePath;
        });

        if (_options.VerifySignatures)
            Step(inv, "verifying signatures", () => inv.Signatures = VerifySignatures(inv, s, launcher));
        Step(inv, "reading vendor information", () => FillVendorInfo(inv));

        Step(inv, "explaining the command", () => inv.Explanation = CommandExplainer.Explain(parsed, inv.ReferencedProcesses));

        Step(inv, "checking for suspicious indicators", () =>
        {
            var findings = SuspiciousCommandDetector.Analyze(new DetectionContext
            {
                CommandLine = s.CommandLine,
                Parsed = parsed,
                ProcessName = s.Name,
                ImagePath = inv.ResolvedImagePath ?? s.ImagePath,
                Ancestry = inv.Ancestry,
                Children = s.Children,
                IsSelfTest = CaptureSelfTest.IsGenuine(s.CommandLine, inv.Ancestry)
            });
            foreach (var f in SuspiciousCommandDetector.AnalyzeSignatures(inv.Signatures))
                if (!findings.Any(x => x.RuleId == f.RuleId)) findings.Add(f);
            inv.Findings = findings.OrderByDescending(f => Severity.Rank(f.Severity)).ToList();
        });

        if (_options.CorrelateScheduledTasks)
            Step(inv, "correlating scheduled tasks", () =>
                inv.ScheduledTask = _tasks.Correlate(SelfInfo(s, inv), inv.Ancestry, s.StartUtc, inv.Notes));

        if (_options.CorrelateEventLogs)
            Step(inv, "reading Windows event history", () => inv.History = CollectHistory(s, parsed, inv));

        Step(inv, "assessing risk", () => inv.Risk = RiskAssessor.Assess(new RiskInput
        {
            Findings = inv.Findings,
            Signatures = inv.Signatures,
            Ancestry = inv.Ancestry,
            AncestryComplete = inv.AncestryComplete,
            AncestryNote = inv.AncestryNote,
            Launcher = launcher,
            LaunchContext = inv.LaunchContext,
            Task = inv.ScheduledTask,
            Explanation = inv.Explanation,
            ProcessName = s.Name,
            CaptureSource = s.CaptureSource
        }));

        return inv;
    }

    private static Subject Snapshot(CmdEvent ev) => new()
    {
        ProcessId = ev.ProcessId,
        Name = ev.ProcessName,
        ImagePath = ev.ImagePath,
        CommandLine = ev.CommandLine,
        ParentProcessId = ev.ParentProcessId,
        ParentName = ev.ParentProcessName,
        ParentImage = ev.ParentImagePath,
        ParentCommandLine = ev.ParentCommandLine,
        StartUtc = ev.TimestampUtc,
        ExitUtc = ev.ExitedAtUtc,
        CaptureSource = ev.CaptureSource,
        PreviousRevision = ev.Investigation?.Revision ?? 0,
        Children = ev.ChildProcesses.Select(c => new ProcessInfo
        {
            ProcessId = c.ProcessId,
            ProcessName = c.ProcessName,
            ImagePath = c.ImagePath,
            CommandLine = c.CommandLine,
            ObservedAtUtc = c.ObservedAtUtc,
            ParentProcessId = c.ParentProcessId,
            Depth = c.Depth,
            StartTimeUtc = c.StartTimeUtc ?? c.ObservedAtUtc,
            ExitedAtUtc = c.ExitedAtUtc,
            ExitCode = c.ExitCode,
            Source = c.Source
        }).ToList()
    };

    private static void Step(Investigation inv, string what, Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            inv.Errors.Add($"Failed while {what}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static ProcessInfo SelfInfo(Subject s, Investigation inv) => new()
    {
        ProcessId = s.ProcessId,
        ProcessName = s.Name,
        ImagePath = inv.ResolvedImagePath ?? s.ImagePath,
        CommandLine = s.CommandLine,
        StartTimeUtc = s.StartUtc,
        ObservedAtUtc = s.StartUtc
    };

    // ---------------------------------------------------------- ancestry --

    private List<ProcessInfo> BuildAncestry(Subject s, Investigation inv)
    {
        var chain = new List<ProcessInfo>();
        int depth = 0;

        var walk = _processes.GetAncestry(s.ParentProcessId, s.StartUtc);
        foreach (var r in walk.Chain) chain.Add(r.ToProcessInfo(++depth));

        // Parent unknown to the process history (e.g. WMI fallback without a
        // snapshot): use the details captured at the time, then ask WMI.
        if (chain.Count == 0 && s.ParentProcessId > 0 && !string.IsNullOrEmpty(s.ParentName))
        {
            var parent = new ProcessInfo
            {
                ProcessId = s.ParentProcessId,
                ProcessName = s.ParentName!,
                ImagePath = s.ParentImage,
                CommandLine = s.ParentCommandLine,
                Depth = ++depth,
                Source = "captured with the event",
                Description = ProcessRoles.Describe(s.ParentName, s.ParentCommandLine, s.ParentProcessId)
            };
            chain.Add(parent);

            var live = ProcessSnapshot.TryGetRecord(s.ParentProcessId);
            if (live is not null && (live.StartTimeUtc == DateTimeOffset.MinValue || live.StartTimeUtc <= s.StartUtc + ProcessCache.Skew))
            {
                parent.ParentProcessId = live.ParentProcessId;
                parent.StartTimeUtc = live.StartTimeUtc == DateTimeOffset.MinValue ? null : live.StartTimeUtc;
                if (ProcessRoles.IsRoot(parent.ProcessName, parent.ProcessId))
                {
                    walk = new AncestryResult { Complete = true, Note = ProcessRoles.RootNote(parent.ProcessName, parent.ProcessId) };
                }
                else
                {
                    walk = _processes.GetAncestry(live.ParentProcessId, parent.StartTimeUtc ?? s.StartUtc);
                    foreach (var r in walk.Chain) chain.Add(r.ToProcessInfo(++depth));
                }
            }
        }

        // The chain stops at a process that exited before monitoring began:
        // Sysmon / Security 4688 may still know who it was.
        var missing = walk.MissingProcessId;
        var childStart = chain.Count > 0 ? chain[^1].StartTimeUtc ?? s.StartUtc : s.StartUtc;
        int hops = 0;
        while (missing is int pid && _options.CorrelateEventLogs && hops++ < 6)
        {
            var created = _history.FindProcessCreation(pid, childStart, TimeSpan.FromDays(2));
            if (created is null) break;

            var name = CommandLineTokenizer.FileNameOf(created.Image ?? $"PID {pid}");
            chain.Add(new ProcessInfo
            {
                ProcessId = pid,
                ProcessName = name,
                ImagePath = created.Image,
                CommandLine = created.CommandLine,
                StartTimeUtc = created.TimeUtc,
                ObservedAtUtc = created.TimeUtc,
                ParentProcessId = created.ParentProcessId ?? 0,
                Depth = ++depth,
                Source = created.Source,
                Description = ProcessRoles.Describe(name, created.CommandLine, pid)
            });

            if (ProcessRoles.IsRoot(name, pid) || created.ParentProcessId is null or <= 0)
            {
                walk = new AncestryResult { Complete = ProcessRoles.IsRoot(name, pid), Note = ProcessRoles.RootNote(name, pid) };
                missing = null;
                break;
            }

            walk = _processes.GetAncestry(created.ParentProcessId.Value, created.TimeUtc);
            foreach (var r in walk.Chain) chain.Add(r.ToProcessInfo(++depth));
            missing = walk.MissingProcessId;
            childStart = chain[^1].StartTimeUtc ?? created.TimeUtc;
        }

        inv.AncestryComplete = walk.Complete;
        inv.AncestryNote = walk.Note.Length > 0 ? walk.Note : (chain.Count == 0 ? "No parent-process evidence was available." : null);

        foreach (var a in chain.Take(12))
            a.ImagePath = ProcessImageResolver.Resolve(a.ProcessId, a.ImagePath, a.ProcessName, a.CommandLine, a.StartTimeUtc) ?? a.ImagePath;

        return chain;
    }

    /// <summary>
    /// The original launcher is the outermost process in the chain that isn't
    /// Windows plumbing (service hosts, the service manager, the desktop...).
    /// How it launched is judged from the closest plumbing above the popup.
    /// </summary>
    private static ProcessInfo? DetermineLauncher(IReadOnlyList<ProcessInfo> ancestry, Investigation inv)
    {
        ProcessInfo? launcher = null;
        foreach (var a in ancestry)
            if (!ProcessRoles.IsPlumbing(a.ProcessName, a.ProcessId)) launcher = a;

        string? context = null;
        foreach (var a in ancestry)
        {
            context = ProcessRoles.LaunchContextFor(a.ProcessName, a.CommandLine, a.ProcessId);
            if (context is not null) break;
        }

        if (launcher is not null)
        {
            inv.Launcher = launcher.ProcessName;
            inv.LaunchContext = context ?? (inv.AncestryComplete ? null : "Unknown — the launch chain is incomplete above this program");
            return launcher;
        }

        if (ancestry.Count > 0)
        {
            var closest = ancestry[0];
            inv.LaunchContext = context;
            inv.Launcher = context switch
            {
                not null when context.StartsWith("User desktop", StringComparison.Ordinal) => "explorer.exe (the signed-in user)",
                not null when context.StartsWith("Scheduled task", StringComparison.Ordinal) => "Task Scheduler",
                not null when context.StartsWith("WMI", StringComparison.Ordinal) => "WMI provider host (the real requester is hidden behind WMI)",
                _ => closest.ProcessName
            };
            return closest;
        }

        inv.Launcher = null;
        inv.LaunchContext = "Unknown — no parent-process evidence";
        return null;
    }

    // ------------------------------------------------- referenced processes --

    private List<ReferencedProcess> ResolveReferenced(ParsedCommand parsed, Subject s)
    {
        var texts = parsed.AllTexts().Select(t => t.Text).ToList();
        var results = new List<ReferencedProcess>();

        foreach (var reference in ReferencedPidExtractor.ExtractPids(texts))
        {
            var rp = new ReferencedProcess { ProcessId = reference.ProcessId, Context = reference.Context };
            if (reference.ProcessId is 0 or 4)
            {
                rp.ProcessName = reference.ProcessId == 0 ? "System Idle Process" : "System";
                rp.Status = "running";
                rp.Source = "well-known PID";
                results.Add(rp);
                continue;
            }

            var record = _processes.TryGet(reference.ProcessId, s.StartUtc, requireAlive: true)
                         ?? _processes.TryGet(reference.ProcessId, s.StartUtc);
            if (record is null)
            {
                var live = ProcessSnapshot.TryGetRecord(reference.ProcessId);
                if (live is not null && (live.StartTimeUtc == DateTimeOffset.MinValue || live.StartTimeUtc <= s.StartUtc + ProcessCache.Skew))
                    record = live;
            }

            if (record is not null)
            {
                rp.ProcessName = record.Name;
                rp.ImagePath = ProcessImageResolver.Resolve(record.ProcessId, record.ImagePath, record.Name, record.CommandLine, record.StartTimeUtc) ?? record.ImagePath;
                rp.CommandLine = record.CommandLine;
                rp.StartTimeUtc = record.StartTimeUtc == DateTimeOffset.MinValue ? null : record.StartTimeUtc;
                rp.ExitedAtUtc = record.ExitTimeUtc;
                rp.Status = record.ExitTimeUtc is null ? "running"
                    : record.ExitTimeUtc < s.StartUtc - ProcessCache.Skew ? "had already exited" : "exited";
                rp.Source = record.Source == "live" ? "live process" : "process history";
            }
            else if (_options.CorrelateEventLogs && _history.FindProcessCreation(reference.ProcessId, s.StartUtc, TimeSpan.FromDays(1)) is { } created)
            {
                rp.ProcessName = CommandLineTokenizer.FileNameOf(created.Image ?? "");
                rp.ImagePath = created.Image;
                rp.CommandLine = created.CommandLine;
                rp.StartTimeUtc = created.TimeUtc;
                rp.Status = "exited (found in the event log)";
                rp.Source = created.Source;
            }
            else
            {
                rp.Status = "not found";
            }
            results.Add(rp);
        }

        foreach (var reference in ReferencedPidExtractor.ExtractNames(texts))
        {
            var running = _processes.FindRunningByName(reference.Name);
            if (running.Count == 0)
            {
                results.Add(new ReferencedProcess { ProcessName = reference.Name, Status = "not running", Context = reference.Context, Source = "process history" });
                continue;
            }
            foreach (var record in running.Take(8))
            {
                if (results.Any(r => r.ProcessId == record.ProcessId)) continue;
                results.Add(new ReferencedProcess
                {
                    ProcessId = record.ProcessId,
                    ProcessName = record.Name,
                    ImagePath = ProcessImageResolver.Resolve(record.ProcessId, record.ImagePath, record.Name, record.CommandLine, record.StartTimeUtc) ?? record.ImagePath,
                    CommandLine = record.CommandLine,
                    StartTimeUtc = record.StartTimeUtc == DateTimeOffset.MinValue ? null : record.StartTimeUtc,
                    Status = "running",
                    Context = reference.Context,
                    Source = "process history"
                });
            }
        }
        return results;
    }

    // ---------------------------------------------------------- signatures --

    private List<SignatureInfo> VerifySignatures(Investigation inv, Subject s, ProcessInfo? launcher)
    {
        var targets = new List<(string Path, string Role, int? Pid)>();
        void Add(string? path, string role, int? pid)
        {
            if (ProcessImageResolver.IsRooted(path)) targets.Add((path!, role, pid));
        }

        Add(inv.ResolvedImagePath, "this process", s.ProcessId);
        for (int i = 0; i < inv.Ancestry.Count && i < 8; i++)
        {
            var a = inv.Ancestry[i];
            var role = i == 0 ? "parent" : $"ancestor (level {i + 1})";
            if (ReferenceEquals(a, launcher)) role += ", launcher";
            Add(a.ImagePath, role, a.ProcessId);
        }
        foreach (var child in s.Children.Take(10)) Add(child.ImagePath, $"action [{child.ProcessId}]", child.ProcessId);
        foreach (var r in inv.ReferencedProcesses.Where(r => r.ImagePath is not null).Take(10))
            Add(r.ImagePath, $"referenced [{r.ProcessId}]", r.ProcessId);

        var results = new List<SignatureInfo>();
        foreach (var group in targets.GroupBy(t => t.Path, StringComparer.OrdinalIgnoreCase))
        {
            var first = group.First();
            var roles = string.Join(", ", group.Select(g => g.Role).Distinct());
            results.Add(_signatures.Verify(first.Path, roles, first.Pid));
        }
        return results;
    }

    private static void FillVendorInfo(Investigation inv)
    {
        foreach (var rp in inv.ReferencedProcesses)
        {
            if (rp.ImagePath is null) continue;
            var sig = inv.Signatures.FirstOrDefault(x => x.Path.Equals(rp.ImagePath, StringComparison.OrdinalIgnoreCase));
            if (sig is not null)
            {
                rp.Company = sig.CompanyName ?? sig.Publisher;
                rp.Product = sig.ProductName ?? sig.FileDescription;
            }
            else
            {
                var (company, product, description) = SignatureVerifier.ReadVersionInfo(rp.ImagePath);
                rp.Company = company;
                rp.Product = product ?? description;
            }
        }
    }

    // ------------------------------------------------------------ history --

    private List<HistoricalEvent> CollectHistory(Subject s, ParsedCommand parsed, Investigation inv)
    {
        var list = new List<HistoricalEvent>();

        foreach (var a in inv.Ancestry.Where(a => a.Source is "Security 4688" or "Sysmon 1"))
        {
            list.Add(new HistoricalEvent
            {
                TimeUtc = a.StartTimeUtc ?? s.StartUtc,
                Source = a.Source!,
                ProcessId = a.ProcessId,
                ParentProcessId = a.ParentProcessId,
                Image = a.ImagePath,
                CommandLine = a.CommandLine,
                RelatedTo = $"launch chain (level {a.Depth}) — recovered from the event log"
            });
        }

        if (_history.FindProcessCreation(s.ProcessId, s.StartUtc, TimeSpan.FromMinutes(1)) is { } self)
        {
            self.RelatedTo = "this process";
            list.Add(self);
        }

        if (parsed.IsPowerShell)
            list.AddRange(_history.FindPowerShellActivity(s.ProcessId, s.StartUtc, s.ExitUtc, s.CommandLine));

        foreach (var child in s.Children.Where(c => CommandParser.KindOf(c.ProcessName) is InterpreterKind.PowerShell or InterpreterKind.Pwsh).Take(3))
        {
            foreach (var e in _history.FindPowerShellActivity(child.ProcessId, child.StartTimeUtc ?? s.StartUtc, child.ExitedAtUtc, child.CommandLine))
            {
                e.RelatedTo = $"action [{child.ProcessId}]: {e.RelatedTo}";
                list.Add(e);
            }
        }

        if (inv.ScheduledTask is { Confidence: TaskConfidence.Confirmed } task)
        {
            list.Add(new HistoricalEvent
            {
                TimeUtc = task.LaunchedAtUtc ?? s.StartUtc,
                Source = "Task Scheduler 129",
                EventId = 129,
                ProcessId = task.MatchedProcessId,
                Detail = $"The task {task.TaskPath} created this process.",
                RelatedTo = "scheduled task"
            });
        }

        if (!inv.AncestryComplete && OperatingSystem.IsWindows())
        {
            var security = _history.GetSourceStatus().FirstOrDefault(x => x.LogName == WindowsEventHistory.SecurityLog);
            var sysmon = _history.GetSourceStatus().FirstOrDefault(x => x.LogName == WindowsEventHistory.SysmonLog);
            if (security is { Active: false } && sysmon is not { Active: true })
                inv.Notes.Add("Process-creation auditing (Security 4688) is off and Sysmon isn't installed, so programs that exited before CMD-spy started can't be traced. Turn auditing on via Investigate ▾ → Windows logging.");
        }

        return list.OrderBy(e => e.TimeUtc).Take(25).ToList();
    }
}
