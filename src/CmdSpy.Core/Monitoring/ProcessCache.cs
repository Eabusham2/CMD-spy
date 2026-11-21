using System;
using System.Collections.Generic;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Monitoring;

/// <summary>One incarnation of a process ID: who started it, what it ran, when it lived.</summary>
public sealed class ProcessRecord
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string Name { get; init; } = "";
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }

    /// <summary>When it started (DateTimeOffset.MinValue when unknown).</summary>
    public DateTimeOffset StartTimeUtc { get; init; }

    public DateTimeOffset? ExitTimeUtc { get; set; }
    public int? ExitCode { get; set; }
    public int SessionId { get; init; } = -1;

    /// <summary>"ETW"/"WMI" (seen starting live), "snapshot" (already running at start-up) or "live".</summary>
    public string Source { get; init; } = "";

    public ProcessRecord Clone() => (ProcessRecord)MemberwiseClone();

    public ProcessInfo ToProcessInfo(int depth = 0) => new()
    {
        ProcessId = ProcessId,
        ParentProcessId = ParentProcessId,
        ProcessName = Name,
        ImagePath = ImagePath,
        CommandLine = CommandLine,
        ObservedAtUtc = StartTimeUtc == DateTimeOffset.MinValue ? default : StartTimeUtc,
        StartTimeUtc = StartTimeUtc == DateTimeOffset.MinValue ? null : StartTimeUtc,
        ExitedAtUtc = ExitTimeUtc,
        ExitCode = ExitCode,
        Depth = depth,
        Source = Source,
        Description = ProcessRoles.Describe(Name, CommandLine, ProcessId)
    };
}

/// <summary>Result of walking a launch chain upwards.</summary>
public sealed class AncestryResult
{
    /// <summary>Parent first, then grandparent, ...</summary>
    public List<ProcessRecord> Chain { get; } = new();

    /// <summary>True when the walk reached a recognised root.</summary>
    public bool Complete { get; set; }

    public string Note { get; set; } = "";

    /// <summary>The first PID that could not be identified, if the walk stopped early.</summary>
    public int? MissingProcessId { get; set; }
}

/// <summary>
/// Remembers every process CMD-spy has seen start — plus everything that was
/// already running when monitoring began — including ones that have since
/// exited. This is what lets CMD-spy name a popup's parent and walk the whole
/// launch chain even when the parent closed before anyone could look at it, and
/// resolve PIDs mentioned in a command to the executables they belonged to.
///
/// PID reuse is handled by keeping every incarnation of a PID with its start
/// time and picking the one that was alive at the moment in question.
/// </summary>
public sealed class ProcessCache
{
    /// <summary>Tolerance for timestamps that come from different sources.</summary>
    public static readonly TimeSpan Skew = TimeSpan.FromSeconds(2);

    private readonly object _gate = new();
    private readonly Dictionary<int, List<ProcessRecord>> _byPid = new();
    private int _count;
    private int _writesSincePrune;

    public ProcessCache(TimeSpan? retainExited = null, int maxRecords = 50_000)
    {
        RetainExited = retainExited ?? TimeSpan.FromHours(6);
        MaxRecords = Math.Max(1_000, maxRecords);
    }

    /// <summary>How long an exited process is remembered.</summary>
    public TimeSpan RetainExited { get; }

    /// <summary>Hard cap on remembered incarnations.</summary>
    public int MaxRecords { get; }

    public int Count
    {
        get { lock (_gate) return _count; }
    }

    /// <summary>Adds processes that were already running when monitoring began.</summary>
    public void Seed(IEnumerable<ProcessRecord> running)
    {
        lock (_gate)
        {
            foreach (var record in running)
            {
                var list = ListFor(record.ProcessId);
                // Skip an incarnation we already know (same PID and start time).
                bool known = false;
                foreach (var existing in list)
                {
                    if (Math.Abs((existing.StartTimeUtc - record.StartTimeUtc).TotalSeconds) < 1)
                    {
                        known = true;
                        break;
                    }
                }
                if (known) continue;
                InsertSorted(list, record);
                _count++;
            }
        }
    }

    /// <summary>Records a process start seen live by the watcher.</summary>
    public ProcessRecord RecordStart(ProcessStartedEventArgs e)
    {
        var record = new ProcessRecord
        {
            ProcessId = e.ProcessId,
            ParentProcessId = e.ParentProcessId,
            Name = NameFor(e.ImagePath, e.ProcessName),
            ImagePath = e.ImagePath,
            CommandLine = e.CommandLine,
            StartTimeUtc = e.TimestampUtc,
            SessionId = e.SessionId,
            Source = e.Source
        };

        lock (_gate)
        {
            InsertSorted(ListFor(e.ProcessId), record);
            _count++;
            if (++_writesSincePrune >= 512)
            {
                _writesSincePrune = 0;
                PruneLocked(e.TimestampUtc);
            }
        }
        return record;
    }

    /// <summary>Records a process exit, against the incarnation that was running.</summary>
    public void RecordStop(ProcessStoppedEventArgs e)
    {
        lock (_gate)
        {
            if (!_byPid.TryGetValue(e.ProcessId, out var list)) return;
            for (int i = list.Count - 1; i >= 0; i--)
            {
                var r = list[i];
                if (r.ExitTimeUtc is null && r.StartTimeUtc <= e.TimestampUtc + Skew)
                {
                    r.ExitTimeUtc = e.TimestampUtc;
                    r.ExitCode = e.ExitCode;
                    return;
                }
            }
        }
    }

    /// <summary>
    /// The incarnation of <paramref name="processId"/> that existed at
    /// <paramref name="asOfUtc"/> (the most recent one if no time is given).
    /// With <paramref name="requireAlive"/>, returns null if that incarnation had
    /// already exited by then. Returns a copy, safe to read without locking.
    /// </summary>
    public ProcessRecord? TryGet(int processId, DateTimeOffset? asOfUtc = null, bool requireAlive = false)
    {
        lock (_gate)
        {
            if (!_byPid.TryGetValue(processId, out var list) || list.Count == 0) return null;
            if (asOfUtc is null) return list[^1].Clone();

            var t = asOfUtc.Value;
            for (int i = list.Count - 1; i >= 0; i--)
            {
                var r = list[i];
                if (r.StartTimeUtc > t + Skew) continue;          // started after the moment in question
                if (requireAlive && r.ExitTimeUtc is { } exit && exit < t - Skew)
                    return null;                                   // that PID was already gone
                return r.Clone();
            }
            return null;
        }
    }

    /// <summary>All incarnations currently running whose image name matches (e.g. "asus_framework").</summary>
    public List<ProcessRecord> FindRunningByName(string nameOrPath)
    {
        var stem = ProcessRoles.Stem(nameOrPath);
        var result = new List<ProcessRecord>();
        if (stem.Length == 0) return result;
        lock (_gate)
        {
            foreach (var list in _byPid.Values)
            {
                var latest = list[^1];
                if (latest.ExitTimeUtc is null &&
                    ProcessRoles.Stem(latest.Name).Equals(stem, StringComparison.OrdinalIgnoreCase))
                    result.Add(latest.Clone());
            }
        }
        result.Sort((a, b) => a.ProcessId.CompareTo(b.ProcessId));
        return result;
    }

    /// <summary>
    /// Walks upwards from <paramref name="parentProcessId"/> (the parent of a
    /// process that started at <paramref name="childStartUtc"/>): parent,
    /// grandparent, ... until a recognised root, a gap, or <paramref name="maxDepth"/>.
    /// Each step must have been alive when its child started, which rejects
    /// recycled PIDs.
    /// </summary>
    public AncestryResult GetAncestry(int parentProcessId, DateTimeOffset childStartUtc, int maxDepth = 24)
    {
        var result = new AncestryResult();
        var visited = new HashSet<int>();
        var pid = parentProcessId;
        var childStart = childStartUtc;

        for (int depth = 1; depth <= maxDepth; depth++)
        {
            if (pid <= 0)
            {
                result.Complete = true;
                result.Note = "Reached the top of the process tree.";
                return result;
            }
            if (!visited.Add(pid))
            {
                result.Note = $"Stopped: PID {pid} appeared twice (recycled process IDs).";
                return result;
            }

            var parent = TryGet(pid, childStart, requireAlive: true);
            if (parent is null)
            {
                result.MissingProcessId = pid;
                result.Note = $"PID {pid} is not running any more and was not recorded — it exited before CMD-spy started monitoring.";
                return result;
            }

            result.Chain.Add(parent);
            if (ProcessRoles.IsRoot(parent.Name, parent.ProcessId))
            {
                result.Complete = true;
                result.Note = ProcessRoles.RootNote(parent.Name, parent.ProcessId);
                return result;
            }

            if (parent.StartTimeUtc != DateTimeOffset.MinValue)
                childStart = parent.StartTimeUtc;
            pid = parent.ParentProcessId;
        }

        result.Note = $"Stopped after {maxDepth} levels.";
        return result;
    }

    /// <summary>Drops exited processes older than the retention window.</summary>
    public void Prune(DateTimeOffset nowUtc)
    {
        lock (_gate) PruneLocked(nowUtc);
    }

    private void PruneLocked(DateTimeOffset nowUtc)
    {
        // Running processes are always kept. Exited ones are kept for the
        // retention window so recent launch chains can still be explained.
        var cutoff = nowUtc - RetainExited;
        var emptied = new List<int>();
        foreach (var (pid, list) in _byPid)
        {
            for (int i = list.Count - 1; i >= 0; i--)
            {
                if (list[i].ExitTimeUtc is { } exit && exit < cutoff)
                {
                    list.RemoveAt(i);
                    _count--;
                }
            }
            if (list.Count == 0) emptied.Add(pid);
        }
        foreach (var pid in emptied) _byPid.Remove(pid);

        if (_count <= MaxRecords) return;

        // Still over the cap (very busy machine): drop the oldest exited ones.
        var exited = new List<(int pid, ProcessRecord r)>();
        foreach (var (pid, list) in _byPid)
            foreach (var r in list)
                if (r.ExitTimeUtc is not null) exited.Add((pid, r));
        exited.Sort((a, b) => Nullable.Compare(a.r.ExitTimeUtc, b.r.ExitTimeUtc));
        foreach (var (pid, r) in exited)
        {
            if (_count <= MaxRecords) break;
            var list = _byPid[pid];
            if (list.Remove(r)) _count--;
            if (list.Count == 0) _byPid.Remove(pid);
        }
    }

    private List<ProcessRecord> ListFor(int processId)
    {
        if (!_byPid.TryGetValue(processId, out var list))
        {
            list = new List<ProcessRecord>(1);
            _byPid[processId] = list;
        }
        return list;
    }

    private static void InsertSorted(List<ProcessRecord> list, ProcessRecord record)
    {
        int i = list.Count;
        while (i > 0 && list[i - 1].StartTimeUtc > record.StartTimeUtc) i--;
        list.Insert(i, record);
    }

    private static string NameFor(string? imagePath, string processName)
    {
        if (!string.IsNullOrWhiteSpace(imagePath))
        {
            var slash = imagePath.LastIndexOfAny(new[] { '\\', '/' });
            return slash >= 0 ? imagePath[(slash + 1)..] : imagePath;
        }
        return processName;
    }
}
