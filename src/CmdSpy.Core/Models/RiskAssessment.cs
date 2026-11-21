using System.Collections.Generic;

namespace CmdSpy.Core.Models;

/// <summary>Verdict labels. There is deliberately no "clean" / "safe" level.</summary>
public static class RiskLevel
{
    public const string High = "High risk";
    public const string Suspicious = "Suspicious";
    public const string Low = "Low risk";
    public const string Unknown = "Unknown";
    public const string SelfTest = "Self-test";
}

/// <summary>
/// Evidence-based risk estimate with its uncertainty spelled out. CMD-spy never
/// declares a computer clean: a harmless-looking command can still have been
/// launched by something that needs verifying.
/// </summary>
public sealed class RiskAssessment
{
    /// <summary>One of <see cref="RiskLevel"/>.</summary>
    public string Level { get; set; } = "";

    /// <summary>0 (no indicators) to 100 (many strong indicators).</summary>
    public int Score { get; set; }

    /// <summary>"Low", "Medium" or "High" — how much evidence the verdict rests on.</summary>
    public string Confidence { get; set; } = "";

    public string Summary { get; set; } = "";

    /// <summary>Evidence that raises the risk.</summary>
    public List<string> RaisingFactors { get; set; } = new();

    /// <summary>Evidence that lowers the risk.</summary>
    public List<string> LoweringFactors { get; set; } = new();

    /// <summary>What could not be verified.</summary>
    public List<string> Unknowns { get; set; } = new();

    public string Disclaimer { get; set; } = "";
}
