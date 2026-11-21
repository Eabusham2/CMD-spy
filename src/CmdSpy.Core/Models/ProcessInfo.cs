using System;

namespace CmdSpy.Core.Models;

/// <summary>
/// Lightweight description of a process. Used for the "cause" (parent) of a
/// cmd popup, every step of its launch chain, and the processes it launches
/// ("actions", including grandchildren).
/// </summary>
public sealed class ProcessInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public DateTimeOffset ObservedAtUtc { get; set; }

    /// <summary>PID of the process that started this one (0 if unknown).</summary>
    public int ParentProcessId { get; set; }

    /// <summary>
    /// Generation relative to the captured popup. For actions: 1 = direct child,
    /// 2 = grandchild... For the launch chain: 1 = parent, 2 = grandparent...
    /// </summary>
    public int Depth { get; set; }

    public DateTimeOffset? StartTimeUtc { get; set; }
    public DateTimeOffset? ExitedAtUtc { get; set; }
    public int? ExitCode { get; set; }

    /// <summary>Where these details came from (ETW, WMI, snapshot, live, event log...).</summary>
    public string? Source { get; set; }

    /// <summary>Plain-English role, e.g. "Task Scheduler service host".</summary>
    public string? Description { get; set; }

    public override string ToString()
    {
        var cmd = string.IsNullOrWhiteSpace(CommandLine) ? ImagePath : CommandLine;
        return $"[{ProcessId}] {ProcessName}{(string.IsNullOrWhiteSpace(cmd) ? "" : " :: " + cmd)}";
    }
}
