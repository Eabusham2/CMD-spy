namespace CmdSpy.Core.Models;

/// <summary>Severity levels for suspicious-command findings.</summary>
public static class Severity
{
    public const string Info = "Info";
    public const string Low = "Low";
    public const string Medium = "Medium";
    public const string High = "High";

    public static int Rank(string? severity) => severity switch
    {
        High => 3,
        Medium => 2,
        Low => 1,
        _ => 0
    };
}

/// <summary>One suspicious (or noteworthy) indicator found in a command or its context.</summary>
public sealed class Finding
{
    public string RuleId { get; set; } = "";

    /// <summary>One of <see cref="Severity"/>.</summary>
    public string Severity { get; set; } = "";

    public string Title { get; set; } = "";

    /// <summary>Why this matters, in plain words.</summary>
    public string Detail { get; set; } = "";

    /// <summary>MITRE ATT&amp;CK technique, e.g. "T1059.001".</summary>
    public string? Technique { get; set; }

    /// <summary>The text that triggered the finding.</summary>
    public string? Evidence { get; set; }

    /// <summary>What it was found in: "command", "decoded command", "action [123] x.exe", "launch chain"...</summary>
    public string? Subject { get; set; }
}
