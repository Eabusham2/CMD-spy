using System;

namespace CmdSpy.Core.Models;

/// <summary>
/// A record from the Windows event logs (Security 4688, Sysmon 1, PowerShell
/// 400/4104, Task Scheduler 129...) that relates to a captured popup or to a
/// launch that happened before CMD-spy was running.
/// </summary>
public sealed class HistoricalEvent
{
    public DateTimeOffset TimeUtc { get; set; }

    /// <summary>"Security 4688", "Sysmon 1", "PowerShell 400", "PowerShell 4104", "Task Scheduler 129".</summary>
    public string Source { get; set; } = "";

    /// <summary>The source log's monotonically assigned record ID, when available.</summary>
    public long? SourceRecordId { get; set; }

    public int EventId { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessGuid { get; set; }
    public int? ParentProcessId { get; set; }
    public string? Image { get; set; }
    public string? ParentImage { get; set; }
    public string? CommandLine { get; set; }
    public string? User { get; set; }
    public string? UserSid { get; set; }
    public string? LogonId { get; set; }
    public int? SessionId { get; set; }

    /// <summary>Extra content: script block text, task name, hashes...</summary>
    public string? Detail { get; set; }

    /// <summary>How it relates to the capture: "this process", "parent", "launch chain"...</summary>
    public string? RelatedTo { get; set; }
}
