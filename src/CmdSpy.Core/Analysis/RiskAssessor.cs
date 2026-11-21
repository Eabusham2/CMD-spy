using System;
using System.Collections.Generic;
using System.Linq;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Analysis;

/// <summary>Everything the risk assessment weighs.</summary>
public sealed class RiskInput
{
    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();
    public IReadOnlyList<SignatureInfo> Signatures { get; init; } = Array.Empty<SignatureInfo>();
    public IReadOnlyList<ProcessInfo> Ancestry { get; init; } = Array.Empty<ProcessInfo>();
    public bool AncestryComplete { get; init; }
    public string? AncestryNote { get; init; }

    /// <summary>The process judged to be the original launcher (null if unknown).</summary>
    public ProcessInfo? Launcher { get; init; }
    public string? LaunchContext { get; init; }
    public ScheduledTaskMatch? Task { get; init; }
    public CommandExplanation? Explanation { get; init; }
    public string ProcessName { get; init; } = "";
    public string CaptureSource { get; init; } = "";
}

/// <summary>
/// Combines the evidence into a verdict with its uncertainty spelled out.
/// There is deliberately no "clean" verdict: when the command shows nothing
/// suspicious but the launcher can't be verified, the answer is "Unknown",
/// because a harmless-looking command can still come from a harmful program.
/// </summary>
public static class RiskAssessor
{
    public const string Disclaimer =
        "Automated, evidence-based estimate — not a guarantee. A harmless-looking command does not mean the computer is clean: " +
        "the program that launched it must still be verified, and malware can hide in ways a single command line can't show.";

    public static int Weight(string severity) => severity switch
    {
        Severity.High => 35,
        Severity.Medium => 15,
        Severity.Low => 5,
        _ => 0
    };

    public static RiskAssessment Assess(RiskInput input)
    {
        var result = new RiskAssessment { Disclaimer = Disclaimer };

        if (input.Findings.Any(f => f.RuleId == "INFO.SelfTest"))
        {
            result.Level = RiskLevel.SelfTest;
            result.Score = 0;
            result.Confidence = "High";
            result.Summary = "CMD-spy self-test process — started by CMD-spy itself to verify that short-lived windows are captured.";
            return result;
        }

        // ---- Score ----------------------------------------------------------
        var counted = input.Findings
            .GroupBy(f => f.RuleId)
            .Select(g => g.OrderByDescending(f => Severity.Rank(f.Severity)).First())
            .ToList();
        result.Score = Math.Min(100, counted.Sum(f => Weight(f.Severity)));

        foreach (var f in counted.Where(f => Severity.Rank(f.Severity) >= Severity.Rank(Severity.Medium))
                                 .OrderByDescending(f => Severity.Rank(f.Severity)).Take(8))
            result.RaisingFactors.Add($"[{f.Severity}] {f.Title}{(f.Subject is null or "command" ? "" : $" ({f.Subject})")}");
        foreach (var f in counted.Where(f => f.Severity == Severity.Low).Take(4))
            result.RaisingFactors.Add($"[Low] {f.Title}");

        // ---- What we could verify ------------------------------------------
        var processSig = input.Signatures.FirstOrDefault(s => s.Role.Contains("this process", StringComparison.OrdinalIgnoreCase));
        var launcherSig = input.Launcher is null
            ? null
            : input.Signatures.FirstOrDefault(s => s.Role.Contains("launcher", StringComparison.OrdinalIgnoreCase));

        bool processVerified = processSig?.IsValid == true;
        bool launcherKnown = input.Launcher is not null || IsIdentifiedTask(input.Task);
        bool launcherVerified =
            (launcherSig?.IsValid == true) ||
            (input.Launcher is null && IsIdentifiedTask(input.Task) && input.Task!.TaskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase));

        if (processVerified)
            result.LoweringFactors.Add($"{FileName(processSig!.Path)} itself is genuine (validly signed by {processSig.Publisher}).");
        if (launcherSig?.IsValid == true)
            result.LoweringFactors.Add($"The launcher {input.Launcher!.ProcessName} is validly signed by {launcherSig.Publisher}.");
        if (IsIdentifiedTask(input.Task))
            result.LoweringFactors.Add($"Started by the scheduled task {input.Task!.TaskPath} ({input.Task.Confidence.ToLowerInvariant()}{(input.Task.Author is null ? "" : ", author " + input.Task.Author)}).");
        if (input.Explanation?.IsReadOnly == true)
            result.LoweringFactors.Add("The command only reads information — no modification is evident.");

        // ---- What we could not verify ---------------------------------------
        if (!launcherKnown)
        {
            result.Unknowns.Add(input.Ancestry.Count == 0
                ? "The program that launched it could not be identified (no parent-process evidence)."
                : $"The original launcher could not be identified — {input.AncestryNote ?? "the launch chain is incomplete"}");
        }
        else if (!launcherVerified)
        {
            if (launcherSig is null || launcherSig.Status is SignatureStatus.Error or SignatureStatus.Unavailable or SignatureStatus.NotFound)
                result.Unknowns.Add($"The launcher {input.Launcher?.ProcessName ?? input.Task?.TaskPath}'s signature could not be checked{(launcherSig?.Detail is { } d ? $" ({d})" : "")}.");
            else if (launcherSig.Status == SignatureStatus.Unsigned)
                result.Unknowns.Add($"The launcher {input.Launcher?.ProcessName} is unsigned, so its publisher can't be verified.");
        }
        if (processSig is null || processSig.Status is SignatureStatus.Error or SignatureStatus.Unavailable or SignatureStatus.NotFound)
            result.Unknowns.Add($"The signature of {input.ProcessName} itself could not be checked.");
        if (input.Explanation is null || input.Explanation.IsReadOnly is null)
            result.Unknowns.Add("Part of the command could not be interpreted, so its full effect is unknown.");
        if (input.Explanation?.ScriptPath is not null)
            result.Unknowns.Add($"The script {input.Explanation.ScriptPath} was run, but its contents are not part of the command line.");
        if (input.CaptureSource.Equals("WMI", StringComparison.OrdinalIgnoreCase))
            result.Unknowns.Add("Captured in reduced-fidelity mode (WMI): details of very short-lived processes may be missing.");

        // ---- Level ------------------------------------------------------------
        bool hasMediumOrWorse = counted.Any(f => Severity.Rank(f.Severity) >= Severity.Rank(Severity.Medium));
        // One strong indicator (ransomware-style backup deletion, a download
        // cradle, credential dumping...) is enough on its own.
        if (result.Score >= 60 || counted.Any(f => f.Severity == Severity.High))
            result.Level = RiskLevel.High;
        else if (result.Score >= 25)
            result.Level = RiskLevel.Suspicious;
        else if (!hasMediumOrWorse && launcherVerified && processVerified)
            result.Level = RiskLevel.Low;
        else
            result.Level = RiskLevel.Unknown;

        // ---- Confidence ---------------------------------------------------------
        bool strongIndicators = counted.Any(f => f.Severity == Severity.High);
        result.Confidence = strongIndicators
            ? "High"
            : !launcherKnown ? "Low"
            : result.Unknowns.Count == 0 ? "High"
            : result.Unknowns.Count <= 2 ? "Medium" : "Low";

        // ---- Summary ------------------------------------------------------------
        var topReasons = counted.Where(f => Severity.Rank(f.Severity) >= Severity.Rank(Severity.Medium))
            .OrderByDescending(f => Severity.Rank(f.Severity))
            .Take(3)
            .Select(f => f.Title.ToLowerInvariant())
            .ToList();
        var launcherName = input.Launcher?.ProcessName ?? (IsIdentifiedTask(input.Task) ? $"the task {input.Task!.TaskPath}" : "the launching program");

        result.Summary = result.Level switch
        {
            RiskLevel.High =>
                $"High risk: {Join(topReasons)}. Treat this as a likely sign of malicious activity — find out what {launcherName} is, disconnect from the network if unsure, and run a full antivirus scan.",
            RiskLevel.Suspicious =>
                $"Suspicious: {Join(topReasons)}. Review the launch chain and the command before trusting it.",
            RiskLevel.Low =>
                $"Low risk based on the evidence collected: {(input.Explanation?.IsReadOnly == true ? "the command only reads information, " : "")}it was launched by {launcherName} (signature verified) and the program itself is genuine. This is not proof that the computer is clean.",
            _ => (hasMediumOrWorse ? $"Some indicators ({Join(topReasons)}) but not enough evidence to judge. " : "No suspicious indicators were found in the command itself, but there isn't enough evidence to judge it. ") +
                 (result.Unknowns.FirstOrDefault() ?? "") +
                 " The program that launched it still needs verification."
        };

        return result;
    }

    private static bool IsIdentifiedTask(ScheduledTaskMatch? task) =>
        task is not null && !string.IsNullOrEmpty(task.TaskPath) &&
        task.Confidence is TaskConfidence.Confirmed or TaskConfidence.Likely;

    private static string Join(List<string> items) => items.Count switch
    {
        0 => "indicators were found",
        1 => items[0],
        _ => string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1]
    };

    private static string FileName(string path)
    {
        var i = path.LastIndexOfAny(new[] { '\\', '/' });
        return i >= 0 ? path[(i + 1)..] : path;
    }
}
