using System;
using System.Collections.Generic;
using System.Linq;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Works out whether a scheduled task caused a launch, and which one:
/// <list type="bullet">
/// <item><b>Confirmed</b> — Task Scheduler's own log (event 129) recorded launching that exact PID.</item>
/// <item><b>Likely</b> — the Task Scheduler service is in the launch chain and a registered task's action matches the process it started.</item>
/// <item><b>Possible</b> — a registered task's action matches exactly, but the chain doesn't show the scheduler.</item>
/// </list>
/// </summary>
public sealed class ScheduledTaskCorrelator
{
    private readonly ScheduledTaskCatalog _catalog;
    private readonly WindowsEventHistory? _history;

    public ScheduledTaskCorrelator(ScheduledTaskCatalog catalog, WindowsEventHistory? history)
    {
        _catalog = catalog;
        _history = history;
    }

    /// <param name="self">The captured process.</param>
    /// <param name="ancestry">Its launch chain, parent first.</param>
    /// <param name="notes">Receives explanations (e.g. "Task Scheduler history is off").</param>
    public ScheduledTaskMatch? Correlate(ProcessInfo self, IReadOnlyList<ProcessInfo> ancestry, DateTimeOffset whenUtc, List<string> notes)
    {
        var chain = new List<ProcessInfo> { self };
        chain.AddRange(ancestry);

        // 1) Exact attribution from Task Scheduler history.
        if (_history is not null)
        {
            var earliest = chain.Where(p => p.StartTimeUtc is not null).Select(p => p.StartTimeUtc!.Value).DefaultIfEmpty(whenUtc).Min();
            var launches = _history.FindTaskLaunches(earliest - TimeSpan.FromMinutes(2), whenUtc + TimeSpan.FromMinutes(1));
            foreach (var member in chain)
            {
                var launch = launches.FirstOrDefault(l => l.ProcessId == member.ProcessId &&
                    (member.StartTimeUtc is null || (l.TimeUtc - member.StartTimeUtc.Value).Duration() <= TimeSpan.FromSeconds(30)));
                if (launch is null) continue;

                var task = _catalog.FindByPath(launch.TaskName);
                var action = task?.Actions.FirstOrDefault(a => a.Kind == "Exec");
                return new ScheduledTaskMatch
                {
                    TaskPath = launch.TaskName,
                    Confidence = TaskConfidence.Confirmed,
                    Evidence = $"Task Scheduler's log (event 129) recorded this task starting {member.ProcessName} (PID {member.ProcessId}).",
                    MatchedProcessId = member.ProcessId,
                    Command = action?.Command ?? launch.ImagePath,
                    Arguments = action?.Arguments,
                    Author = task?.Author,
                    RunAs = task?.UserId,
                    Enabled = task?.Enabled,
                    Triggers = task?.TriggerSummary,
                    LaunchedAtUtc = launch.TimeUtc
                };
            }
        }

        // 2) The Task Scheduler service is in the launch chain.
        int hostIndex = -1;
        bool sharedHost = false;
        for (int i = 0; i < ancestry.Count; i++)
        {
            if (ProcessRoles.IsSchedulerHost(ancestry[i].ProcessName, ancestry[i].CommandLine)) { hostIndex = i; break; }
            if (ProcessRoles.IsSharedNetsvcsHost(ancestry[i].ProcessName, ancestry[i].CommandLine)) { hostIndex = i; sharedHost = true; break; }
        }

        if (hostIndex >= 0)
        {
            var taskProcess = hostIndex == 0 ? self : ancestry[hostIndex - 1];
            var host = ancestry[hostIndex];
            var candidates = _catalog.Match(taskProcess.ImagePath, taskProcess.CommandLine);
            var best = UniqueBestMatch(candidates, 50);
            HistoryNote(notes);

            if (best is { } match)
            {
                return new ScheduledTaskMatch
                {
                    TaskPath = match.Task.Path,
                    Confidence = sharedHost ? TaskConfidence.Possible : TaskConfidence.Likely,
                    Evidence = $"{host.ProcessName} (PID {host.ProcessId}, the Task Scheduler{(sharedHost ? " — shared service host" : "")}) started " +
                               $"{taskProcess.ProcessName} (PID {taskProcess.ProcessId}), and this task's action runs that exact {(match.Score >= 70 ? "command" : "program")}.",
                    MatchedProcessId = taskProcess.ProcessId,
                    Command = match.Action.Command,
                    Arguments = match.Action.Arguments,
                    Author = match.Task.Author,
                    RunAs = match.Task.UserId,
                    Enabled = match.Task.Enabled,
                    Triggers = match.Task.TriggerSummary
                };
            }

            bool ambiguous = candidates.Any(candidate => candidate.Score >= 50);
            return new ScheduledTaskMatch
            {
                TaskPath = "",
                Confidence = sharedHost ? TaskConfidence.Possible : TaskConfidence.Likely,
                Evidence = $"{host.ProcessName} (PID {host.ProcessId}) {(sharedHost ? "may be" : "is")} the Task Scheduler and started " +
                           $"{taskProcess.ProcessName} (PID {taskProcess.ProcessId}), but " +
                           (ambiguous
                               ? "multiple registered tasks have plausible matching actions, so none can be uniquely attributed"
                               : "no registered task's action matches it exactly") +
                           (_catalog.LastError is { } err ? $" ({err})" : "") + ".",
                MatchedProcessId = taskProcess.ProcessId
            };
        }

        // 3) No scheduler in the chain: only an exact action match is worth mentioning.
        foreach (var member in chain.Take(2))
        {
            var candidates = _catalog.Match(member.ImagePath, member.CommandLine);
            var best = UniqueBestMatch(candidates, 90);
            if (best is { } match)
            {
                return new ScheduledTaskMatch
                {
                    TaskPath = match.Task.Path,
                    Confidence = TaskConfidence.Possible,
                    Evidence = $"This task runs exactly {member.ProcessName} with these arguments, but the launch chain doesn't show the Task Scheduler — it may have been started another way.",
                    MatchedProcessId = member.ProcessId,
                    Command = match.Action.Command,
                    Arguments = match.Action.Arguments,
                    Author = match.Task.Author,
                    RunAs = match.Task.UserId,
                    Enabled = match.Task.Enabled,
                    Triggers = match.Task.TriggerSummary
                };
            }

            if (candidates.Any(candidate => candidate.Score >= 90))
            {
                return new ScheduledTaskMatch
                {
                    TaskPath = "",
                    Confidence = TaskConfidence.Possible,
                    Evidence = $"Multiple registered tasks run exactly {member.ProcessName} with these arguments, so none can be uniquely attributed.",
                    MatchedProcessId = member.ProcessId
                };
            }
        }
        return null;
    }

    internal static (ScheduledTaskInfo Task, TaskAction Action, int Score)? UniqueBestMatch(
        IReadOnlyList<(ScheduledTaskInfo Task, TaskAction Action, int Score)> candidates, int minimumScore)
    {
        var eligible = candidates.Where(candidate => candidate.Score >= minimumScore).ToList();
        if (eligible.Count == 0) return null;

        // Similarity cannot authenticate one candidate while another task also clears the threshold.
        bool oneTask = eligible.Select(candidate => candidate.Task.Path)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .Count() == 1;
        return oneTask ? eligible.OrderByDescending(candidate => candidate.Score).First() : null;
    }

    private void HistoryNote(List<string> notes)
    {
        if (_history is null) return;
        var status = _history.GetSourceStatus().FirstOrDefault(s => s.LogName == WindowsEventHistory.TaskSchedulerLog);
        if (status is not null && !status.Active)
            notes.Add("Task Scheduler history is off, so the exact task can't be confirmed from its log. Turn it on via Investigate ▾ → Windows logging.");
    }
}
