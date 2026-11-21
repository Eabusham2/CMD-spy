using System;

namespace CmdSpy.Core.Models;

/// <summary>
/// A process that a captured command points at — e.g. the PIDs inside
/// <c>gwmi win32_process -Filter 'ProcessId=37868 or ...'</c> — resolved to the
/// executable it actually was at the time.
/// </summary>
public sealed class ReferencedProcess
{
    public int ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }

    /// <summary>Vendor from the file's version info (e.g. "ASUSTeK COMPUTER INC.").</summary>
    public string? Company { get; set; }

    /// <summary>Product/description from the file's version info.</summary>
    public string? Product { get; set; }

    /// <summary>"running", "exited" or "not found".</summary>
    public string Status { get; set; } = "";

    /// <summary>Where the identity came from (process history, live process, event log...).</summary>
    public string? Source { get; set; }

    /// <summary>The text in the command that referenced it, e.g. "ProcessId=37868".</summary>
    public string Context { get; set; } = "";

    public DateTimeOffset? StartTimeUtc { get; set; }
    public DateTimeOffset? ExitedAtUtc { get; set; }
}
