using System;
using System.Collections.Generic;

namespace CmdSpy.Core.Models;

/// <summary>
/// The deep analysis CMD-spy attaches to a captured popup shortly after it is
/// seen. It answers the two questions a person actually has when a window
/// flashes: "what opened this?" (launch chain, scheduled task, signatures) and
/// "should I be worried?" (command explanation, suspicious indicators, risk).
/// </summary>
public sealed class Investigation
{
    public DateTimeOffset AnalyzedAtUtc { get; set; }

    /// <summary>Increments each time the event is re-analysed (e.g. a new child appeared).</summary>
    public int Revision { get; set; }

    /// <summary>Full path of the popup's executable, resolved even if it already exited.</summary>
    public string? ResolvedImagePath { get; set; }

    // ---- Launch chain -----------------------------------------------------
    /// <summary>Parent first, then grandparent, ... up to the original launcher.</summary>
    public List<ProcessInfo> Ancestry { get; set; } = new();

    /// <summary>True when the chain reached a recognised root (System, wininit, the user shell...).</summary>
    public bool AncestryComplete { get; set; }

    /// <summary>Why the chain stops where it does.</summary>
    public string? AncestryNote { get; set; }

    /// <summary>The program that ultimately caused the launch, in plain words.</summary>
    public string? Launcher { get; set; }

    /// <summary>How it was launched: Windows service, scheduled task, user desktop, WMI...</summary>
    public string? LaunchContext { get; set; }

    // ---- What the command touches ---------------------------------------
    public List<ReferencedProcess> ReferencedProcesses { get; set; } = new();

    public ScheduledTaskMatch? ScheduledTask { get; set; }

    public List<SignatureInfo> Signatures { get; set; } = new();

    public CommandExplanation? Explanation { get; set; }

    public List<Finding> Findings { get; set; } = new();

    public List<HistoricalEvent> History { get; set; } = new();

    public RiskAssessment? Risk { get; set; }

    /// <summary>Context worth knowing (e.g. "Security 4688 auditing is disabled").</summary>
    public List<string> Notes { get; set; } = new();

    /// <summary>Steps that failed; the rest of the investigation is still valid.</summary>
    public List<string> Errors { get; set; } = new();
}
