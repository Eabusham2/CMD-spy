using System;
using System.Text.Json.Serialization;

namespace CmdSpy.Core.Models;

/// <summary>How sure CMD-spy is that a scheduled task caused a launch.</summary>
public static class TaskConfidence
{
    /// <summary>Task Scheduler's own log recorded launching this exact process ID.</summary>
    public const string Confirmed = "Confirmed";
    /// <summary>The Task Scheduler is in the launch chain and a registered task's action matches.</summary>
    public const string Likely = "Likely";
    /// <summary>A registered task's action matches, but the launch chain doesn't show the scheduler.</summary>
    public const string Possible = "Possible";
}

/// <summary>The scheduled task believed to be responsible for a launch.</summary>
public sealed class ScheduledTaskMatch
{
    /// <summary>Full task path, e.g. "\ASUS\Framework Service Task". Empty when the scheduler is known but the task isn't.</summary>
    public string TaskPath { get; set; } = "";

    /// <summary>One of <see cref="TaskConfidence"/>.</summary>
    public string Confidence { get; set; } = "";

    /// <summary>Why CMD-spy believes this.</summary>
    public string Evidence { get; set; } = "";

    /// <summary>The process in the chain that the task started.</summary>
    public int? MatchedProcessId { get; set; }

    public string? Command { get; set; }
    public string? Arguments { get; set; }
    public string? Author { get; set; }
    public string? RunAs { get; set; }
    public bool? Enabled { get; set; }
    public string? Triggers { get; set; }
    public DateTimeOffset? LaunchedAtUtc { get; set; }

    [JsonIgnore]
    public string TaskName
    {
        get
        {
            if (string.IsNullOrEmpty(TaskPath)) return "";
            var i = TaskPath.LastIndexOf('\\');
            return i >= 0 ? TaskPath[(i + 1)..] : TaskPath;
        }
    }
}
