using System;
using System.Collections.Generic;
using System.Linq;
using CmdSpy.Core.Analysis;
using CmdSpy.Core.Models;
using CmdSpy.Core.Monitoring;

namespace CmdSpy.Core;

/// <summary>
/// Turns launches of console/script hosts recorded in the Windows event logs
/// (Sysmon 1, Security 4688, PowerShell 400) into captures, so popups that
/// happened before CMD-spy was running — the ones that made you suspicious in
/// the first place — can be investigated the same way as live ones.
/// </summary>
public static class HistoryImporter
{
    public static List<CmdEvent> Read(WindowsEventHistory history, CmdSpyOptions options, DateTimeOffset sinceUtc,
        IEnumerable<CmdEvent> alreadyKnown, int max = 500)
    {
        var stems = options.TargetStems();
        var launches = history.ReadProcessHistory(sinceUtc,
            image => !string.IsNullOrWhiteSpace(image) && stems.Contains(CmdSpyOptions.Stem(CommandLineTokenizer.FileNameOf(image))),
            max);

        var known = alreadyKnown.ToList();
        var currentBootUtc = SystemTimings.BootTimeLocal.ToUniversalTime();
        var result = new List<CmdEvent>();
        foreach (var h in launches)
        {
            bool duplicate = known.Any(k => HistoricalLaunchIdentity.IsSame(k, h));
            if (duplicate) continue;

            var ev = ToEvent(h, currentBootUtc, history);
            known.Add(ev);
            result.Add(ev);
        }
        return result;
    }

    public static CmdEvent ToEvent(HistoricalEvent h, DateTimeOffset currentBootUtc, WindowsEventHistory? history = null)
    {
        DateTimeOffset? bootUtc = h.TimeUtc >= currentBootUtc ? currentBootUtc : history?.FindBootBefore(h.TimeUtc);
        var image = h.Image;
        var name = string.IsNullOrWhiteSpace(image) ? "?" : CommandLineTokenizer.FileNameOf(image!);

        var ev = new CmdEvent
        {
            TimestampUtc = h.TimeUtc,
            TimestampLocal = h.TimeUtc.ToLocalTime(),
            SystemBootTimeLocal = (bootUtc ?? h.TimeUtc).ToLocalTime(),
            TimeSinceBoot = bootUtc is null ? TimeSpan.Zero : h.TimeUtc - bootUtc.Value,
            SystemUptimeSeconds = bootUtc is null ? 0 : (h.TimeUtc - bootUtc.Value).TotalSeconds,
            ProcessId = h.ProcessId ?? 0,
            ProcessName = name,
            ImagePath = ProcessImageResolver.IsRooted(image) ? image : null,
            CommandLine = h.CommandLine,
            UserName = h.User,
            SessionId = h.SessionId ?? -1,
            ParentProcessId = h.ParentProcessId ?? 0,
            ParentProcessName = string.IsNullOrWhiteSpace(h.ParentImage) ? null : CommandLineTokenizer.FileNameOf(h.ParentImage!),
            ParentImagePath = ProcessImageResolver.IsRooted(h.ParentImage) ? h.ParentImage : null,
            CaptureSource = $"{h.Source} (imported)",
            HistoricalSource = h.Source,
            HistoricalRecordId = h.SourceRecordId,
            HistoricalProcessGuid = h.ProcessGuid,
            HistoricalUserSid = h.UserSid,
            HistoricalLogonId = h.LogonId,
            Notes = "Imported from the Windows event log — this launch happened before CMD-spy was capturing, " +
                    "so its exit, actions and connections were not observed." +
                    (bootUtc is null ? " The boot it belongs to could not be determined, so 'since boot' is not available." : "")
        };
        return ev;
    }
}
