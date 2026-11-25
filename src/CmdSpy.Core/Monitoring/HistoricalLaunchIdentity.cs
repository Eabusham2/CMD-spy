using System;
using CmdSpy.Core.Models;

namespace CmdSpy.Core.Monitoring;

/// <summary>
/// Identifies duplicate representations of one process launch without treating
/// command text as record identity. Missing or conflicting identity evidence is
/// deliberately retained as a separate historical record.
/// </summary>
internal static class HistoricalLaunchIdentity
{
    internal static readonly TimeSpan MaximumTimeSkew = TimeSpan.FromMilliseconds(500);

    public static bool IsSame(HistoricalEvent first, HistoricalEvent second) =>
        IsSame(From(first), From(second));

    public static bool IsSame(CmdEvent known, HistoricalEvent candidate) =>
        IsSame(From(known), From(candidate));

    private static bool IsSame(LaunchIdentity first, LaunchIdentity second)
    {
        if ((first.TimeUtc - second.TimeUtc).Duration() > MaximumTimeSkew) return false;

        bool sameSource = HasValue(first.Source) && HasValue(second.Source) &&
                          string.Equals(first.Source, second.Source, StringComparison.OrdinalIgnoreCase);
        if (sameSource)
        {
            // Record IDs are unique only within their source log. Distinct or
            // unavailable IDs are ambiguous and must remain separate.
            return first.RecordId is { } firstId && second.RecordId is { } secondId && firstId == secondId;
        }

        if (first.ProcessId is not { } firstPid || second.ProcessId is not { } secondPid ||
            firstPid <= 0 || secondPid <= 0 || firstPid != secondPid)
            return false;

        if (!SameFullImage(first.Image, second.Image)) return false;
        if (Conflicts(first.ProcessGuid, second.ProcessGuid) ||
            Conflicts(first.UserSid, second.UserSid) ||
            Conflicts(first.LogonId, second.LogonId) ||
            Conflicts(first.SessionId, second.SessionId))
            return false;

        if (HasValue(first.CommandLine) && HasValue(second.CommandLine) &&
            !WindowsEventHistory.SameCommand(first.CommandLine, second.CommandLine))
            return false;

        // At least one principal attribute must independently agree. A PID,
        // image and nearby timestamp alone cannot establish attribution.
        return Matches(first.UserSid, second.UserSid) ||
               Matches(first.LogonId, second.LogonId) ||
               Matches(first.User, second.User);
    }

    private static bool SameFullImage(string? first, string? second)
    {
        var firstPath = NormalizeFullImage(first);
        var secondPath = NormalizeFullImage(second);
        return firstPath is not null && secondPath is not null &&
               string.Equals(firstPath, secondPath, StringComparison.OrdinalIgnoreCase);
    }

    private static string? NormalizeFullImage(string? image)
    {
        var path = ProcessImageResolver.NormalizeKernelPath(image)?.Trim().Trim('"').Replace('/', '\\');
        return ProcessImageResolver.IsRooted(path) ? path : null;
    }

    private static bool Conflicts(string? first, string? second) =>
        HasValue(first) && HasValue(second) && !string.Equals(first, second, StringComparison.OrdinalIgnoreCase);

    private static bool Conflicts(int? first, int? second) =>
        first is { } firstValue && second is { } secondValue && firstValue != secondValue;

    private static bool Matches(string? first, string? second) =>
        HasValue(first) && HasValue(second) && string.Equals(first, second, StringComparison.OrdinalIgnoreCase);

    private static bool HasValue(string? value) => !string.IsNullOrWhiteSpace(value);

    private static LaunchIdentity From(HistoricalEvent historical) => new(
        historical.TimeUtc,
        historical.Source,
        historical.SourceRecordId,
        historical.ProcessId,
        historical.ProcessGuid,
        historical.Image,
        historical.CommandLine,
        historical.User,
        historical.UserSid,
        historical.LogonId,
        historical.SessionId);

    private static LaunchIdentity From(CmdEvent known) => new(
        known.TimestampUtc,
        HistoricalSourceOf(known),
        known.HistoricalRecordId,
        known.ProcessId > 0 ? known.ProcessId : null,
        known.HistoricalProcessGuid,
        known.ImagePath,
        known.CommandLine,
        known.UserName,
        known.HistoricalUserSid,
        known.HistoricalLogonId,
        known.SessionId >= 0 ? known.SessionId : null);

    private static string? HistoricalSourceOf(CmdEvent known)
    {
        if (HasValue(known.HistoricalSource)) return known.HistoricalSource;

        const string importedSuffix = " (imported)";
        return known.CaptureSource.EndsWith(importedSuffix, StringComparison.OrdinalIgnoreCase)
            ? known.CaptureSource[..^importedSuffix.Length]
            : null;
    }

    private readonly record struct LaunchIdentity(
        DateTimeOffset TimeUtc,
        string? Source,
        long? RecordId,
        int? ProcessId,
        string? ProcessGuid,
        string? Image,
        string? CommandLine,
        string? User,
        string? UserSid,
        string? LogonId,
        int? SessionId);
}
